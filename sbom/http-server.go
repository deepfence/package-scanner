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
	"github.com/rs/zerolog/log"
)

var (
	scanConcurrency       int
	managementConsoleURL  string
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
	managementConsoleURL = os.Getenv("MGMT_CONSOLE_URL")
	managementConsolePort = os.Getenv("MGMT_CONSOLE_PORT")
	if managementConsolePort == "" {
		managementConsolePort = "443"
	}
}

func RunHTTPServer(config utils.Config) error {
	if config.Port == "" {
		return fmt.Errorf("http-server mode requires port to be set")
	}
	http.HandleFunc("/registry", registryHandler)

	log.Info().Str("port", config.Port).Msg("Starting server")
	if err := http.ListenAndServe(fmt.Sprintf(":%s", config.Port), nil); err != nil {
		return err
	}
	return nil
}

func processRegistryMessage(rInterface interface{}) interface{} {
	r, ok := rInterface.(utils.Config)
	if !ok {
		log.Error().Msg("Error processing input config")
		return false
	}
	config := utils.Config{
		Output:                "",
		Quiet:                 true,
		ConsoleURL:            managementConsoleURL,
		ConsolePort:           managementConsolePort,
		DeepfenceKey:          "",
		Source:                r.Source,
		ScanType:              r.ScanType,
		VulnerabilityScan:     true,
		ScanID:                r.ScanID,
		NodeType:              r.NodeType,
		NodeID:                r.NodeID,
		HostName:              r.HostName,
		ImageID:               r.ImageID,
		ContainerName:         r.ContainerName,
		KubernetesClusterName: r.KubernetesClusterName,
		RegistryID:            r.RegistryID,
	}
	ctx := context.Background()
	_, err := syft.GenerateSBOM(ctx, config)
	if err != nil {
		log.Error().Err(err).Msg("Error processing SBOM")
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
		config.Source = fmt.Sprintf("registry:%s", config.NodeID)
	}

	go workerPool.Process(config)

	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("Success"))
}
