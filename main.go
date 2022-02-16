package main

import (
	"flag"
	"fmt"
	"github.com/deepfence/package-scanner/package-sbom"
	log "github.com/sirupsen/logrus"
)

const (
	PluginName     = "PackageScanner"
	modeLocal      = "local"
	modeGrpcServer = "grpc-server"
)

var (
	mode       = flag.String("mode", modeLocal, modeLocal+" | "+modeGrpcServer)
	socketPath = flag.String("socket-path", "", "Socket path for grpc server")
	source     = flag.String("source", "", "Image name (nginx:latest) or directory (dir:/)")
	scanType   = flag.String("scan-type", "base,java,python,ruby,php,javascript,rust,golang", "base,java,python,ruby,php,javascript,rust,golang")
)

func runOnce() {
	sbom, err := package_sbom.GenerateSBOM(*source, *scanType)
	if err != nil {
		log.Errorf("Error: %v", err)
		return
	}
	fmt.Println(sbom.String())
}

func main() {
	flag.Parse()
	customFormatter := new(log.TextFormatter)
	customFormatter.TimestampFormat = "2006-01-02 15:04:05"
	log.SetFormatter(customFormatter)
	customFormatter.FullTimestamp = true

	if *mode == modeLocal {
		runOnce()
	} else if *mode == modeGrpcServer {
		if *socketPath == "" {
			log.Errorf("socket-path is required")
			return
		}
		err := package_sbom.RunServer(*socketPath, PluginName)
		if err != nil {
			log.Errorf("error: %v", err)
			return
		}
	} else {
		log.Errorf("invalid mode")
		return
	}
}
