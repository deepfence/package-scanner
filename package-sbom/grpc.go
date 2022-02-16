package package_sbom

import (
	"context"
	"fmt"
	pb "github.com/deepfence/agent-plugins-grpc/proto"
	log "github.com/sirupsen/logrus"
	"google.golang.org/grpc"
	"google.golang.org/grpc/reflection"
	"net"
	"os"
	"os/signal"
	"syscall"
)

type gRPCServer struct {
	socketPath string
	pluginName string
	pb.UnimplementedPackageScannerServer
	pb.UnimplementedAgentPluginServer
}

func RunServer(socketPath string, pluginName string) error {

	sigs := make(chan os.Signal, 1)
	done := make(chan bool, 1)

	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)

	lis, err := net.Listen("unix", socketPath)
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

	impl := &gRPCServer{socketPath: socketPath, pluginName: pluginName}
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
	sbom, err := GenerateSBOM(r.Source, r.ScanType)
	if err != nil {
		log.Error(err)
		return nil, err
	}
	return sbom, nil
}
