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
	socket_path = flag.String("socket-path", "", "The server port")
	user_input  = flag.String("user-input", "", "The user input")
)

func run_once() {
	jsonBOM, err := syft.GetJSONSBOM(*user_input)
	if err != nil {
		log.Errorf("Error: %v", err)
		return
	}
	fmt.Println(string(jsonBOM))
}

func main() {
	flag.Parse()

	if *socket_path != "" {
		err := server.RunServer(*socket_path, PLUGIN_NAME)
		if err != nil {
			log.Panic(err)
		}
	} else {
		run_once()
	}
}
