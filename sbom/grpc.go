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

	jobs.StartScanJob()
	defer jobs.StopScanJob()

	config, ok := configInterface.(utils.Config)
	if !ok {
		log.Error("error processing grpc input for generating sbom")
		return fmt.Errorf("error processing grpc input for generating sbom")
	}

	log.Info("Adding to map:" + config.ScanId)
	ctx, cancel := context.WithCancel(context.Background())
	scanMap.Store(config.ScanId, cancel)
	defer func() {
		log.Info("Removing from map:" + config.ScanId)
		scanMap.Delete(config.ScanId)
	}()
	var (
		publisher *output.Publisher
		err       error
		sbom      []byte
	)

	publisher, err = output.NewPublisher(config)
	if err != nil {
		log.Errorf("error in creating publisher %s", err)
		return err
	}

	statusChan := make(chan output.JobStatus)
	var wg sync.WaitGroup
	wg.Add(1)
	publisher.StartStatusReporter(statusChan, &wg)
	defer wg.Wait()

	statusChan <- output.JobStatus{Status: output.IN_PROGRESS, Msg: ""}

	// generate sbom
	sbom, err = syft.GenerateSBOM(ctx, config)
	if err != nil {
		if ctx.Err() == context.Canceled {
			log.Infof("Stopping GenerateSBOM as per user request, scanID:", config.ScanId)
			statusChan <- output.JobStatus{Status: output.ABORT, Msg: "CANCELLED"}
		} else {
			log.Error("error in generating sbom: " + err.Error())
			statusChan <- output.JobStatus{Status: output.ERROR, Msg: string(sbom) + " " + err.Error()}
		}
		return err
	}

	// Send sbom to Deepfence Management Console for Vulnerability Scan
	if err := publisher.SendSbomToConsole(sbom, false); err != nil {
		log.Error(config.ScanId, " ", err.Error())
		statusChan <- output.JobStatus{Status: output.ERROR, Msg: string(sbom) + " " + err.Error()}
		return err
	}

	//This is to signal completion to the StatusChecker
	statusChan <- output.JobStatus{Status: output.COMPLETE, Msg: ""}

	return nil
}

func (s *gRPCServer) StopScan(_ context.Context, req *pb.StopScanRequest) (*pb.StopScanResult, error) {
	log.Infof("StopSBOM: %v", req)

	scanID := req.ScanId
	result := &pb.StopScanResult{
		Success:     true,
		Description: "",
	}

	cancelFnObj, found := scanMap.Load(scanID)
	logMsg := ""
	successFlag := true
	if !found {
		logMsg = "Failed to Stop scan, may have already completed"
		successFlag = false
	} else {
		cancelFn := cancelFnObj.(context.CancelFunc)
		cancelFn()
		logMsg = "Stop GenerateSBOM request submitted"
	}

	log.Infof("%s, scan_id: %s", logMsg, scanID)
	result.Success = successFlag
	result.Description = logMsg
	return result, nil
}
