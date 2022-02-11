package syft

import (
	"fmt"
	"os/exec"

	log "github.com/sirupsen/logrus"
)

// TODO: Add support to filter based on language
func GetJSONSBOM(userInput string) ([]byte, error) {
	if userInput == "" {
		return nil, fmt.Errorf("user input is empty")
	}
	log.Infof("Getting JSON BOM for: %s", userInput)
	cmd := exec.Command("syft", "packages", userInput, "-o", "json")

	return cmd.Output()
}
