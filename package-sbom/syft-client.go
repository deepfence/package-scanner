package package_sbom

import (
	"encoding/json"
	"fmt"
	pb "github.com/deepfence/agent-plugins-grpc/proto"
	log "github.com/sirupsen/logrus"
	"os/exec"
	"strings"
)

var (
	linuxExcludeDirs = []string{"/var/lib/docker", "/var/lib/containerd", "/mnt", "/run", "/proc", "/dev", "/boot", "/etc", "/sys", "/lost+found"}
)

func GenerateSBOM(source string, scanType string) (*pb.SBOMResult, error) {
	if source == "" {
		return nil, fmt.Errorf("source is empty")
	}
	syftArgs := []string{"packages", source, "-o", "json", "-q"}
	if strings.HasPrefix(source, "dir:") {
		for _, excludeDir := range linuxExcludeDirs {
			syftArgs = append(syftArgs, "--exclude")
			syftArgs = append(syftArgs, "'."+excludeDir+"/**'")
		}
	} else {
		for _, excludeDir := range linuxExcludeDirs {
			syftArgs = append(syftArgs, "--exclude")
			syftArgs = append(syftArgs, "'"+excludeDir+"'")
		}
	}
	log.Infof("Generating SBOM: %s %s", source, syftArgs)
	cmd := exec.Command("syft", syftArgs...)
	jsonBOM, err := cmd.Output()
	sbom := pb.SBOMResult{}
	err = json.Unmarshal(jsonBOM, &sbom)
	if err != nil {
		log.Error(err)
		return nil, err
	}
	return &sbom, nil
}
