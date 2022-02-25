package package_sbom

import (
	"encoding/json"
	"fmt"
	"github.com/deepfence/package-scanner/internal/deepfence"
	"github.com/deepfence/package-scanner/util"
	log "github.com/sirupsen/logrus"
	"net/http"
	"sync"
)

type registryChannelMessage struct {
	config util.Config
}

var registryChannel chan registryChannelMessage
var registryChannelCount int
var registryChannelCountMutex sync.Mutex
var deepfenceClient *deepfence.Client

func RunHttpServer(config util.Config) error {
	if config.Port == "" {
		return fmt.Errorf("http-server mode requires port to be set")
	}
	err := createRegistryMessageChannel()
	if err != nil {
		return err
	}
	deepfenceClient, err = deepfence.NewClient(config)
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
		if getRegistryChannelProcessCount() >= 5 {
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

func processRegistryMessage(registryMessage registryChannelMessage) {
	defer decrementRegistryChannelProcessCount()
	sbom, err := GenerateSBOM(registryMessage.config)
	if err != nil {
		log.Errorf("Error processing SBOM: %s", err.Error())
	}
	err = deepfenceClient.SendSBOMtoConsole(sbom)
	if err != nil {
		log.Errorf("Error sending SBOM to console: %s", err.Error())
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

	regMessage := registryChannelMessage{config: config}
	registryChannel <- regMessage

	w.WriteHeader(http.StatusOK)
	w.Write([]byte("Success"))
}
