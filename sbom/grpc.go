package sbom

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"

	pb "github.com/deepfence/package-scanner/proto"
	"github.com/deepfence/package-scanner/utils"
	log "github.com/sirupsen/logrus"
	"google.golang.org/grpc"
	"google.golang.org/grpc/reflection"
)

var (
	scanIdReplacer = strings.NewReplacer("/", "_", ":", "_", ".", "_")
)

type gRPCServer struct {
	socketPath string
	pluginName string
	config     utils.Config
	pb.UnimplementedPackageScannerServer
	pb.UnimplementedAgentPluginServer
}

func RunGrpcServer(pluginName string, config utils.Config) error {

	sigs := make(chan os.Signal, 1)
	done := make(chan bool, 1)

	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)

	var lis net.Listener
	var err error
	if config.Port != "" {
		lis, err = net.Listen("tcp", fmt.Sprintf("0.0.0.0:%s", config.Port))
	} else if config.SocketPath != "" {
		lis, err = net.Listen("unix", config.SocketPath)
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

	config.ManagementConsoleUrl = os.Getenv("MGMT_CONSOLE_URL")
	config.ManagementConsolePort = os.Getenv("MGMT_CONSOLE_PORT")
	if config.ManagementConsolePort == "" {
		config.ManagementConsolePort = "443"
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
	log.Infof("generate sbom parameters: %+v", r)
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
		ManagementConsoleUrl:  s.config.ManagementConsoleUrl,
		ManagementConsolePort: s.config.ManagementConsolePort,
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
	}

	sbom, err := GenerateSBOM(config)
	if err != nil {
		log.Error("error in generating sbom: " + err.Error())
		return nil, err
	}
	path := filepath.Join("/tmp", scanIdReplacer.Replace(config.ScanId)+".json")
	err = os.WriteFile(path, sbom, 0666)
	if err != nil {
		return nil, err
	}

	return &pb.SBOMResult{SbomPath: path}, nil
}
