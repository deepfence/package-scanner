package package_sbom

import (
	"fmt"
	"github.com/deepfence/package-scanner/output"
	"github.com/deepfence/package-scanner/util"
	"os"
	"os/exec"
	"strings"
)

var (
	linuxExcludeDirs = []string{"/var/lib/docker", "/var/lib/containerd", "/mnt", "/run", "/proc", "/dev", "/boot", "/etc", "/sys", "/lost+found"}
)

func GenerateSBOM(config util.Config) ([]byte, error) {
	syftArgs := []string{"packages", config.Source, "-o", "json", "-q"}
	if strings.HasPrefix(config.Source, "dir:") || config.Source == "." {
		for _, excludeDir := range linuxExcludeDirs {
			syftArgs = append(syftArgs, "--exclude", "."+excludeDir+"/**")
		}
	} else {
		for _, excludeDir := range linuxExcludeDirs {
			syftArgs = append(syftArgs, "--exclude", excludeDir)
		}
	}
	if config.ScanType != "" && config.ScanType != "all" {
		scanTypes := strings.Split(config.ScanType, ",")
		for _, scanType := range scanTypes {
			if scanType == "base" {
				syftArgs = append(syftArgs, "--enable-cataloger", "dpkgdb-cataloger", "--enable-cataloger", "rpmdb-cataloger", "--enable-cataloger", "apkdb-cataloger")
			} else if scanType == "ruby" {
				syftArgs = append(syftArgs, "--enable-cataloger", "ruby-gemfile-cataloger", "--enable-cataloger", "ruby-gemspec-cataloger")
			} else if scanType == "python" {
				syftArgs = append(syftArgs, "--enable-cataloger", "python-index-cataloger", "--enable-cataloger", "python-package-cataloger")
			} else if scanType == "javascript" {
				syftArgs = append(syftArgs, "--enable-cataloger", "javascript-lock-cataloger", "--enable-cataloger", "javascript-package-cataloger")
			} else if scanType == "php" {
				syftArgs = append(syftArgs, "--enable-cataloger", "php-composer-installed-cataloger", "--enable-cataloger", "php-composer-lock-cataloger")
			} else if scanType == "golang" {
				syftArgs = append(syftArgs, "--enable-cataloger", "go-mod-file-cataloger")
			} else if scanType == "java" {
				syftArgs = append(syftArgs, "--enable-cataloger", "java-cataloger")
			} else if scanType == "rust" {
				syftArgs = append(syftArgs, "--enable-cataloger", "rust-cataloger")
			}
		}
	}

	var publisher *output.Publisher

	if config.VulnerabilityScan == true {
		publisher, err := output.NewPublisher(config)
		if err != nil {
			return nil, err
		}
		publisher.PublishScanStatus("GENERATING_SBOM")
	}

	cmd := exec.Command("syft", syftArgs...)
	if config.RegistryId != "" && config.NodeType == util.NodeTypeImage {
		// TODO: registry
		authFilePath, err := GetConfigFileFromRegistry(config.RegistryId)
		if err != nil {
			return nil, err
		}
		cmd.Env = os.Environ()
		cmd.Env = append(cmd.Env, fmt.Sprintf("DOCKER_CONFIG=%s", authFilePath))
	}

	//logrus.Infof("Generating SBOM: %s - syft %v", config.Source, syftArgs)
	sbom, err := cmd.Output()
	if err != nil {
		if config.VulnerabilityScan == true {
			publisher.PublishScanError(err.Error())
		}
		return nil, err
	}

	if config.VulnerabilityScan == true {
		publisher.StopPublishScanStatus()
		// Send sbom to Deepfence Management Console for Vulnerability Scan
		publisher.RunVulnerabilityScan(sbom)
		if config.Quiet == false {
			publisher.Output()
		}
	}

	return sbom, nil
}
