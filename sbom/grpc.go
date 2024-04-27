package sbom

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/Jeffail/tunny"
	pb "github.com/deepfence/agent-plugins-grpc/srcgo"
	dschttp "github.com/deepfence/golang_deepfence_sdk/utils/http"
	"github.com/deepfence/golang_deepfence_sdk/utils/tasks"
	"github.com/deepfence/package-scanner/jobs"
	"github.com/deepfence/package-scanner/output"
	"github.com/deepfence/package-scanner/sbom/syft"
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
	pb.UnimplementedScannersServer
}

var (
	scanConcurrencyGrpc int
	grpcScanWorkerPool  *tunny.Pool
	scanMap             sync.Map
)

func init() {
	var err error
	scanConcurrencyGrpc, err = strconv.Atoi(os.Getenv("PACKAGE_SCAN_CONCURRENCY"))
	if err != nil {
		scanConcurrencyGrpc = DefaultPackageScanConcurrency
	}
	grpcScanWorkerPool = tunny.NewFunc(scanConcurrencyGrpc, processSbomGeneration)
	scanMap = sync.Map{}
}

func RunGrpcServer(pluginName string, config utils.Config) error {

	sigs := make(chan os.Signal, 1)
	done := make(chan bool, 1)

	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)

	var lis net.Listener
	var err error
	switch {
	case config.SocketPath != "":
		lis, err = net.Listen("unix", config.SocketPath)
	case config.Port != "":
		lis, err = net.Listen("tcp", fmt.Sprintf("0.0.0.0:%s", config.Port))
	default:
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

	if dschttp.IsConsoleAgent(config.ConsoleURL) && strings.Trim(config.DeepfenceKey, "\"") == "" {
		internalURL := os.Getenv("MGMT_CONSOLE_URL_INTERNAL")
		internalPort := os.Getenv("MGMT_CONSOLE_PORT_INTERNAL")
		log.Info("fetch token for console agent")
		for {
			var err error
			if config.DeepfenceKey, err = dschttp.GetConsoleApiToken(internalURL, internalPort); err != nil {
				log.Error(err)
				time.Sleep(5 * time.Second)
			} else {
				break
			}
		}
	}

	impl := &gRPCServer{socketPath: config.SocketPath, pluginName: pluginName, config: config}
	pb.RegisterAgentPluginServer(s, impl)
	pb.RegisterPackageScannerServer(s, impl)
	pb.RegisterScannersServer(s, impl)
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

func (s *gRPCServer) ReportJobsStatus(context.Context, *pb.Empty) (*pb.JobReports, error) {
	return &pb.JobReports{
		RunningJobs: jobs.GetRunningJobCount(),
	}, nil
}

func (s *gRPCServer) GenerateSBOM(_ context.Context, r *pb.SBOMRequest) (*pb.SBOMResult, error) {
	log.Infof("SBOMRequest: %v", r)
	var nodeID string
	var nodeType string
	switch {
	case strings.HasPrefix(r.Source, "dir:") || r.Source == ".":
		nodeID = r.HostName
		nodeType = utils.NodeTypeHost
	case r.NodeType == utils.NodeTypeContainer:
		nodeID = r.Source
		nodeType = utils.NodeTypeContainer
	default:
		nodeID = r.Source
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
		ScanID:                r.ScanId,
		NodeType:              nodeType,
		NodeID:                nodeID,
		HostName:              r.HostName,
		ImageID:               r.ImageId,
		ContainerName:         r.ContainerName,
		KubernetesClusterName: r.KubernetesClusterName,
		RegistryID:            r.RegistryId,
		ContainerID:           r.ContainerId,
		SyftBinPath:           s.config.SyftBinPath,
		GrypeBinPath:          s.config.GrypeBinPath,
		GrypeConfigPath:       s.config.GrypeConfigPath,
	}

	go grpcScanWorkerPool.Process(config)

	return &pb.SBOMResult{SbomPath: ""}, nil
}

func processSbomGeneration(configInterface interface{}) interface{} {
	var (
		publisher *output.Publisher
		err       error
		sbom      []byte
	)

	jobs.StartScanJob()
	defer jobs.StopScanJob()

	res, ctx := tasks.StartStatusReporter(
		"",
		func(ss tasks.ScanStatus) error {
			if publisher != nil {
				publisher.PublishScanStatusMessage(ss.ScanMessage, ss.ScanStatus)
			}
			return nil
		},
		tasks.StatusValues{
			IN_PROGRESS: "IN_PROGRESS",
			CANCELLED:   "CANCELLED",
			FAILED:      "ERROR",
			SUCCESS:     "COMPLETE",
		},
		5*time.Hour,
	)
	defer func() {
		res <- err
		close(res)
	}()

	config, ok := configInterface.(utils.Config)
	if !ok {
		log.Error("error processing grpc input for generating sbom")
		return fmt.Errorf("error processing grpc input for generating sbom")
	}

	log.Info("Adding to map:" + config.ScanID)

	publisher, err = output.NewPublisher(config)
	if err != nil {
		log.Errorf("error in creating publisher %s", err)
		return err
	}

	scanMap.Store(config.ScanID, ctx)
	defer func() {
		log.Info("Removing from map:" + config.ScanID)
		scanMap.Delete(config.ScanID)
	}()

	err = ctx.Checkpoint("Before generating SBOM")
	if err != nil {
		log.Errorf("error in checkpoint: %s", err)
		return err
	}

	// generate sbom
	sbom, err = syft.GenerateSBOM(ctx.Context, config)
	if err != nil {
		log.Errorf("error in GenerateSBOM: %s", err)
		return err
	}

	err = ctx.Checkpoint("After generating SBOM")
	if err != nil {
		log.Errorf("error in checkpoint: %s", err)
		return err
	}

	// Send sbom to Deepfence Management Console for Vulnerability Scan
	err = publisher.SendSbomToConsole(sbom, false)
	if err != nil {
		log.Errorf("error in SendSbomToConsole: %s", err)
		return err
	}

	return nil
}

func (s *gRPCServer) StopScan(_ context.Context, req *pb.StopScanRequest) (*pb.StopScanResult, error) {
	log.Infof("StopSBOM: %v", req)

	scanID := req.ScanId
	result := &pb.StopScanResult{
		Success:     true,
		Description: "",
	}

	obj, found := scanMap.Load(scanID)
	logMsg := ""
	successFlag := true
	if !found {
		logMsg = "Failed to Stop scan, may have already completed"
		successFlag = false
	} else {
		ctx := obj.(*tasks.ScanContext)
		ctx.StopTriggered.Store(true)
		ctx.Cancel()
		logMsg = "Stop GenerateSBOM request submitted"
	}

	log.Infof("%s, scan_id: %s", logMsg, scanID)
	result.Success = successFlag
	result.Description = logMsg
	return result, nil
}
