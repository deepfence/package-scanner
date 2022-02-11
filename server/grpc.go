package server

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/signal"
	"syscall"

	pb "github.com/deepfence/agent-plugins-grpc/proto"
	"github.com/deepfence/vulnerability-sbom-plugin/internal/syft"

	log "github.com/sirupsen/logrus"
	"google.golang.org/grpc"
	"google.golang.org/grpc/reflection"
)

type gRPCServer struct {
	socket_path string
	plugin_name string
	pb.UnimplementedSyftPluginServer
	pb.UnimplementedAgentPluginServer
}

func RunServer(socket_path string, plugin_name string) error {

	sigs := make(chan os.Signal, 1)
	done := make(chan bool, 1)

	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)

	lis, err := net.Listen("unix", socket_path)
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

	impl := &gRPCServer{socket_path: socket_path, plugin_name: plugin_name}
	pb.RegisterAgentPluginServer(s, impl)
	pb.RegisterSyftPluginServer(s, impl)
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

func (s *gRPCServer) GetSBOMJSON(_ context.Context, r *pb.SBOMRequest) (*pb.SBOMResult, error) {
	jsonBOM, err := syft.GetJSONSBOM(r.UserInput)
	if err != nil {
		log.Error(err)
		return nil, err
	}
	req := pb.SBOMResult{}
	json.Unmarshal(jsonBOM, &req)
	if err != nil {
		log.Error(err)
		return nil, err
	}
	return &req, nil
}
