package package_sbom

import (
	"context"
	"encoding/json"
	"fmt"
	pb "github.com/deepfence/agent-plugins-grpc/proto"
	"github.com/deepfence/package-scanner/util"
	log "github.com/sirupsen/logrus"
	"google.golang.org/grpc"
	"google.golang.org/grpc/reflection"
	"net"
	"os"
	"os/signal"
	"strings"
	"syscall"
)

type gRPCServer struct {
	socketPath string
	pluginName string
	config     util.Config
	pb.UnimplementedPackageScannerServer
	pb.UnimplementedAgentPluginServer
}

func RunServer(pluginName string, config util.Config) error {

	sigs := make(chan os.Signal, 1)
	done := make(chan bool, 1)

	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)

	lis, err := net.Listen("unix", config.SocketPath)
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
	var nodeId string
	var nodeType string
	if strings.HasPrefix(r.Source, "dir:") {
		nodeId = r.HostName
		nodeType = util.NodeTypeHost
	} else {
		nodeId = r.Source
		nodeType = util.NodeTypeImage
	}
	config := util.Config{
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
	}

	sbom, err := GenerateSBOM(config)
	if err != nil {
		log.Error(err)
		return nil, err
	}
	sbomBytes, err := json.Marshal(&sbom)
	if err != nil {
		return nil, err
	}
	return &pb.SBOMResult{Sbom: string(sbomBytes)}, nil
}
