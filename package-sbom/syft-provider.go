package package_sbom

import (
	"github.com/deepfence/package-scanner/internal/deepfence"
	"github.com/deepfence/package-scanner/output"
	"github.com/deepfence/package-scanner/util"
	log "github.com/sirupsen/logrus"
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
	var err error

	if config.VulnerabilityScan == true {
		publisher, err = output.NewPublisher(config)
		if err != nil {
			return nil, err
		}
		publisher.PublishScanStatus("GENERATING_SBOM")
	}

	if config.RegistryId != "" && config.NodeType == util.NodeTypeImage {
		// TODO: registry
	}

	//logrus.Infof("Generating SBOM: %s - syft %v", config.Source, syftArgs)
	cmd := exec.Command("syft", syftArgs...)
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

		if config.Quiet == true && config.FailOnScore <= 0 && config.FailOnCount <= 0 {
			return sbom, nil
		}

		vulnerabilityScanDetail, err := publisher.GetVulnerabilityScanResults()
		if err != nil {
			return sbom, err
		}

		if config.Quiet == false {
			_ = publisher.Output(vulnerabilityScanDetail)
		}

		if config.FailOnCount > 0 {
			exitOnSeverity := func(count int, failOnCount int) {
				if count >= failOnCount {
					log.Fatalf("Exit vulnerability scan. Number of vulnerabilities (%d) reached/exceeded the limit (%d).", count, failOnCount)
					os.Exit(1)
				}
			}
			if config.FailOnSeverityCount == "" {
				exitOnSeverity(vulnerabilityScanDetail.Total, config.FailOnCount)
			} else if config.FailOnSeverityCount == deepfence.CriticalSeverity {
				exitOnSeverity(vulnerabilityScanDetail.Severity.Critical, config.FailOnCount)
			} else if config.FailOnSeverityCount == deepfence.HighSeverity {
				exitOnSeverity(vulnerabilityScanDetail.Severity.High, config.FailOnCount)
			} else if config.FailOnSeverityCount == deepfence.MediumSeverity {
				exitOnSeverity(vulnerabilityScanDetail.Severity.Medium, config.FailOnCount)
			} else if config.FailOnSeverityCount == deepfence.LowSeverity {
				exitOnSeverity(vulnerabilityScanDetail.Severity.Low, config.FailOnCount)
			}
		}
		if config.FailOnScore > 0.0 {
			exitOnSeverityScore := func(score float64, failOnScore float64) {
				if score >= failOnScore {
					log.Fatalf("Exit vulnerability scan. Vulnerability score (%f) reached/exceeded the limit (%f).", score, failOnScore)
					os.Exit(1)
				}
			}
			exitOnSeverityScore(vulnerabilityScanDetail.CveScore, config.FailOnScore)
		}
	}

	return sbom, nil
}
