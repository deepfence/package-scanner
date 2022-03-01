package package_sbom

import (
	"encoding/json"
	"fmt"
	"github.com/deepfence/package-scanner/util"
	log "github.com/sirupsen/logrus"
	"net/http"
	"os"
	"strconv"
	"sync"
)

type registryChannelMessage struct {
	config util.Config
}

var (
	registryChannel           chan registryChannelMessage
	registryChannelCount      int
	registryChannelCountMutex sync.Mutex
	scanConcurrency           int
	managementConsoleUrl      string
	managementConsolePort     string
)

func init() {
	var err error
	scanConcurrency, err = strconv.Atoi(os.Getenv("PACKAGE_SCAN_CONCURRENCY"))
	if err != nil {
		scanConcurrency = 5
	}
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
	err := createRegistryMessageChannel()
	if err != nil {
		return err
	}
	http.HandleFunc("/registry", registryHandler)

	fmt.Printf("Starting server at port %s\n", config.Port)
	if err = http.ListenAndServe(fmt.Sprintf(":%s", config.Port), nil); err != nil {
		return err
	}
	close(registryChannel)
	return nil
}

func createRegistryMessageChannel() error {
	registryChannel = make(chan registryChannelMessage)
	registryChannelCount = 0
	go receiveRegistryMessages(registryChannel)
	return nil
}

func receiveRegistryMessages(ch chan registryChannelMessage) {
	for {
		if getRegistryChannelProcessCount() >= scanConcurrency {
			continue
		}
		registryMessage, ok := <-ch
		if ok {
			incrementRegistryChannelProcessCount()
			go processRegistryMessage(registryMessage)
		}
	}
}

func getRegistryChannelProcessCount() int {
	registryChannelCountMutex.Lock()
	defer registryChannelCountMutex.Unlock()
	return registryChannelCount
}

func incrementRegistryChannelProcessCount() {
	registryChannelCountMutex.Lock()
	registryChannelCount++
	registryChannelCountMutex.Unlock()
}

func decrementRegistryChannelProcessCount() {
	registryChannelCountMutex.Lock()
	registryChannelCount--
	registryChannelCountMutex.Unlock()
}

func processRegistryMessage(r registryChannelMessage) {
	defer decrementRegistryChannelProcessCount()
	config := util.Config{
		Output:                "",
		Quiet:                 true,
		ManagementConsoleUrl:  managementConsoleUrl,
		ManagementConsolePort: managementConsolePort,
		DeepfenceKey:          "",
		Source:                r.config.Source,
		ScanType:              r.config.ScanType,
		VulnerabilityScan:     true,
		ScanId:                r.config.ScanId,
		NodeType:              r.config.NodeType,
		NodeId:                r.config.NodeId,
		HostName:              r.config.HostName,
		ImageId:               r.config.ImageId,
		ContainerName:         r.config.ContainerName,
		KubernetesClusterName: r.config.KubernetesClusterName,
		RegistryId:            r.config.RegistryId,
	}
	_, err := GenerateSBOM(config)
	if err != nil {
		log.Errorf("Error processing SBOM: %s", err.Error())
		return
	}
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
		fmt.Println("Unable to decode input JSON request:", err)
	}
	if config.Source == "" {
		config.Source = fmt.Sprintf("registry:%s", config.NodeId)
	}

	regMessage := registryChannelMessage{config: config}
	registryChannel <- regMessage

	w.WriteHeader(http.StatusOK)
	w.Write([]byte("Success"))
}
