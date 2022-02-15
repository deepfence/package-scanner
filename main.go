package main

import (
	"flag"
	"fmt"
	"github.com/deepfence/vulnerability-sbom-plugin/vulnerability-sbom"
	log "github.com/sirupsen/logrus"
)

const (
	PluginName     = "SyftPlugin"
	modeLocal      = "local"
	modeGrpcServer = "grpc-server"
)

var (
	mode       = flag.String("mode", modeLocal, modeLocal+" | "+modeGrpcServer)
	socketPath = flag.String("socket-path", "", "Socket path for grpc server")
	source     = flag.String("source", "", "Image name (nginx:latest) or directory (dir:/)")
	scanType   = flag.String("scan-type", "all", "base,java,python,ruby,php,javascript,rust,golang")
)

func runOnce() {
	sbom, err := vulnerability_sbom.GetVulnerabilitySBOM(*source, *scanType)
	if err != nil {
		log.Errorf("Error: %v", err)
		return
	}
	fmt.Println(sbom.String())
}

func main() {
	flag.Parse()

	if *mode == modeLocal {
		runOnce()
	} else if *mode == modeGrpcServer {
		if *socketPath == "" {
			log.Errorf("socket-path is required")
			return
		}
		err := vulnerability_sbom.RunServer(*socketPath, PluginName)
		if err != nil {
			log.Errorf("error: %v", err)
			return
		}
	} else {
		log.Errorf("invalid mode")
		return
	}
}
