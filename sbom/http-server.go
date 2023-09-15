package sbom

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strconv"

	"github.com/Jeffail/tunny"
	"github.com/deepfence/package-scanner/sbom/syft"
	"github.com/deepfence/package-scanner/utils"
	log "github.com/sirupsen/logrus"
)

var (
	scanConcurrency       int
	managementConsoleUrl  string
	managementConsolePort string
	workerPool            *tunny.Pool
)

const DefaultPackageScanConcurrency = 5

func init() {
	var err error
	scanConcurrency, err = strconv.Atoi(os.Getenv("PACKAGE_SCAN_CONCURRENCY"))
	if err != nil {
		scanConcurrency = DefaultPackageScanConcurrency
	}
	workerPool = tunny.NewFunc(scanConcurrency, processRegistryMessage)
	managementConsoleUrl = os.Getenv("MGMT_CONSOLE_URL")
	managementConsolePort = os.Getenv("MGMT_CONSOLE_PORT")
	if managementConsolePort == "" {
		managementConsolePort = "443"
	}
}

func RunHttpServer(config utils.Config) error {
	if config.Port == "" {
		return fmt.Errorf("http-server mode requires port to be set")
	}
	http.HandleFunc("/registry", registryHandler)

	log.Infof("Starting server at port %s", config.Port)
	if err := http.ListenAndServe(fmt.Sprintf(":%s", config.Port), nil); err != nil {
		return err
	}
	return nil
}

func processRegistryMessage(rInterface interface{}) interface{} {
	r, ok := rInterface.(utils.Config)
	if !ok {
		log.Error("Error processing input config")
		return false
	}
	config := utils.Config{
		Output:                "",
		Quiet:                 true,
		ConsoleURL:            managementConsoleUrl,
		ConsolePort:           managementConsolePort,
		DeepfenceKey:          "",
		Source:                r.Source,
		ScanType:              r.ScanType,
		VulnerabilityScan:     true,
		ScanId:                r.ScanId,
		NodeType:              r.NodeType,
		NodeId:                r.NodeId,
		HostName:              r.HostName,
		ImageId:               r.ImageId,
		ContainerName:         r.ContainerName,
		KubernetesClusterName: r.KubernetesClusterName,
		RegistryId:            r.RegistryId,
	}
	ctx, _ := context.WithCancel(context.Background())
	_, err := syft.GenerateSBOM(ctx, config)
	if err != nil {
		log.Errorf("Error processing SBOM: %s", err.Error())
		return false
	}
	return true
}

func registryHandler(w http.ResponseWriter, req *http.Request) {
	if req.Method != "POST" {
		http.Error(w, "Method is not supported.", http.StatusBadRequest)
		return
	}

	decoder := json.NewDecoder(req.Body)
	var config utils.Config
	err := decoder.Decode(&config)
	if err != nil {
		http.Error(w, "Unable to decode input JSON request", http.StatusBadRequest)
		return
	}
	if config.Source == "" {
		config.Source = fmt.Sprintf("registry:%s", config.NodeId)
	}

	go workerPool.Process(config)

	w.WriteHeader(http.StatusOK)
	w.Write([]byte("Success"))
}
