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
	if strings.HasPrefix(source, "dir:") || source == "." {
		for _, excludeDir := range linuxExcludeDirs {
			syftArgs = append(syftArgs, "--exclude")
			syftArgs = append(syftArgs, "."+excludeDir+"/**")
		}
	} else {
		for _, excludeDir := range linuxExcludeDirs {
			syftArgs = append(syftArgs, "--exclude")
			syftArgs = append(syftArgs, ""+excludeDir+"")
		}
	}
	log.Infof("Generating SBOM: %s - syft %s", source, syftArgs)
	cmd := exec.Command("syft", syftArgs...)
	sBOM, err := cmd.Output()
	if err != nil {
		log.Error(err)
		return nil, err
	}
	var sbomDocument Document
	err = json.Unmarshal(sBOM, &sbomDocument)
	if err != nil {
		log.Error(err)
		return nil, err
	}
	// TODO: filter by scanType
	//var filteredArtifacts []*Package
	//for _, artifact := range sbomDocument.Artifacts {
	//	if artifact.MetadataType == "" {
	//		filteredArtifacts = append(filteredArtifacts, artifact)
	//	}
	//}
	//sbomDocument.Artifacts = filteredArtifacts
	sBOM, err = json.Marshal(sbomDocument)
	if err != nil {
		log.Error(err)
		return nil, err
	}
	sbom := pb.SBOMResult{Sbom: string(sBOM)}
	return &sbom, nil
}
