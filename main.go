package main

import (
	"flag"
	"fmt"

	"github.com/deepfence/vulnerability-sbom-plugin/internal/syft"
	"github.com/deepfence/vulnerability-sbom-plugin/server"
	log "github.com/sirupsen/logrus"
)

const (
	PLUGIN_NAME = "SyftPlugin"
)

var (
	socketPath = flag.String("socket-path", "", "The server port")
	userInput  = flag.String("user-input", "", "The user input")
)

func runOnce() {
	jsonBOM, err := syft.GetVulnerabilitySBOM(*userInput)
	if err != nil {
		log.Errorf("Error: %v", err)
		return
	}
	fmt.Println(string(jsonBOM))
}

func main() {
	flag.Parse()

	if *socketPath != "" {
		err := server.RunServer(*socketPath, PLUGIN_NAME)
		if err != nil {
			log.Panic(err)
		}
	} else {
		runOnce()
	}
}
