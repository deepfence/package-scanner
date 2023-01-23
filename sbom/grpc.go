package sbom

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"

	"github.com/Jeffail/tunny"
	"github.com/deepfence/package-scanner/output"
	pb "github.com/deepfence/package-scanner/proto"
	"github.com/deepfence/package-scanner/utils"
	log "github.com/sirupsen/logrus"
	"google.golang.org/grpc"
	"google.golang.org/grpc/reflection"
)

type gRPCServer struct {
	socketPath string
	pluginName string
	config     utils.Config
	pb.UnimplementedPackageScannerServer
	pb.UnimplementedAgentPluginServer
}

var (
	scanConcurrencyGrpc int
	grpcScanWorkerPool  *tunny.Pool
)

func init() {
	var err error
	scanConcurrencyGrpc, err = strconv.Atoi(os.Getenv("PACKAGE_SCAN_CONCURRENCY"))
	if err != nil {
		scanConcurrencyGrpc = DefaultPackageScanConcurrency
	}
	grpcScanWorkerPool = tunny.NewFunc(scanConcurrencyGrpc, processSbomGeneration)
}

func RunGrpcServer(pluginName string, config utils.Config) error {

	sigs := make(chan os.Signal, 1)
	done := make(chan bool, 1)

	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)

	var lis net.Listener
	var err error
	if config.SocketPath != "" {
		lis, err = net.Listen("unix", config.SocketPath)
	} else if config.Port != "" {
		lis, err = net.Listen("tcp", fmt.Sprintf("0.0.0.0:%s", config.Port))
	} else {
		return fmt.Errorf("grpc mode requires either socket-path or port to be set")
	}
	if err != nil {
		return err
	}
	fmt.Println(lis.Addr().String())
	s := grpc.NewServer()

	go func() {
		<-sigs
		s.GracefulStop()
		done <- true
	}()

	config.ConsoleURL = os.Getenv("MGMT_CONSOLE_URL")
	config.ConsolePort = os.Getenv("MGMT_CONSOLE_PORT")
	if config.ConsolePort == "" {
		config.ConsolePort = "443"
	}
	config.DeepfenceKey = os.Getenv("DEEPFENCE_KEY")

	impl := &gRPCServer{socketPath: config.SocketPath, pluginName: pluginName, config: config}
	pb.RegisterAgentPluginServer(s, impl)
	pb.RegisterPackageScannerServer(s, impl)
	// Register reflection service on gRPC server.
	reflection.Register(s)
	log.Infof("main: server listening at %v", lis.Addr())
	if err := s.Serve(lis); err != nil {
		return err
	}

	<-done
	log.Info("main: exiting gracefully")
	return nil
}

func (s *gRPCServer) GenerateSBOM(_ context.Context, r *pb.SBOMRequest) (*pb.SBOMResult, error) {
	log.Infof("SBOMRequest: %v", r)
	var nodeId string
	var nodeType string
	if strings.HasPrefix(r.Source, "dir:") || r.Source == "." {
		nodeId = r.HostName
		nodeType = utils.NodeTypeHost
	} else if r.NodeType == utils.NodeTypeContainer {
		nodeId = r.Source
		nodeType = utils.NodeTypeContainer
	} else {
		nodeId = r.Source
		nodeType = utils.NodeTypeImage
	}
	config := utils.Config{
		Mode:                  s.config.Mode,
		SocketPath:            s.config.SocketPath,
		Output:                "",
		Quiet:                 true,
		ConsoleURL:            s.config.ConsoleURL,
		ConsolePort:           s.config.ConsolePort,
		DeepfenceKey:          s.config.DeepfenceKey,
		Source:                r.Source,
		ScanType:              r.ScanType,
		VulnerabilityScan:     true,
		ScanId:                r.ScanId,
		NodeType:              nodeType,
		NodeId:                nodeId,
		HostName:              r.HostName,
		ImageId:               r.ImageId,
		ContainerName:         r.ContainerName,
		KubernetesClusterName: r.KubernetesClusterName,
		RegistryId:            r.RegistryId,
		ContainerID:           r.ContainerId,
		SyftBinPath:           s.config.SyftBinPath,
		GrypeBinPath:          s.config.GrypeBinPath,
		GrypeConfigPath:       s.config.GrypeConfigPath,
	}

	go grpcScanWorkerPool.Process(config)

	return &pb.SBOMResult{SbomPath: ""}, nil
}

func processSbomGeneration(configInterface interface{}) interface{} {
	config, ok := configInterface.(utils.Config)
	if !ok {
		log.Error("Error processing grpc input for generating SBOM")
		return nil
	}

	var (
		publisher *output.Publisher
		err       error
		sbom      []byte
	)

	publisher, err = output.NewPublisher(config)
	if err != nil {
		log.Error("error in creating publisher")
		return err
	}
	publisher.PublishScanStatus("IN_PROGRESS")

	publisher.StopPublishScanStatus()
	publisher.PublishScanStatus("GENERATING_SBOM")

	sbom, err = GenerateSBOM(config)
	if err != nil {
		log.Error("error in generating sbom: " + err.Error())
		publisher.PublishScanError(string(sbom) + " " + err.Error())
		return err
	}

	// Send sbom to Deepfence Management Console for Vulnerability Scan
	publisher.RunVulnerabilityScan(sbom)

	publisher.StopPublishScanStatus()

	return nil
}
