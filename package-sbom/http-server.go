package package_sbom

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strconv"

	"github.com/Jeffail/tunny"
	"github.com/deepfence/package-scanner/internal/deepfence"
	"github.com/deepfence/package-scanner/util"
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

func RunHttpServer(config util.Config) error {
	if config.Port == "" {
		return fmt.Errorf("http-server mode requires port to be set")
	}
	http.HandleFunc("/registry", registryHandler)

	fmt.Printf("Starting server at port %s\n", config.Port)
	if err := http.ListenAndServe(fmt.Sprintf(":%s", config.Port), nil); err != nil {
		return err
	}
	return nil
}

func processRegistryMessage(rInterface interface{}) interface{} {
	r, ok := rInterface.(util.Config)
	if !ok {
		log.Error("Error processing input config")
		return false
	}
	config := util.Config{
		Output:                "",
		Quiet:                 true,
		ManagementConsoleUrl:  managementConsoleUrl,
		ManagementConsolePort: managementConsolePort,
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

	flock := deepfence.NewFlock()
	if err := flock.LockFile(); err != nil {
		log.Error(err.Error())
		return false
	}
	defer flock.UnlockFile()

	_, err := GenerateSBOM(config)
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
	var config util.Config
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
