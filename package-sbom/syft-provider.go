package package_sbom

import (
	"bufio"
	"fmt"
	vesselConstants "github.com/deepfence/vessel/constants"
	"io/ioutil"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/deepfence/package-scanner/output"
	"github.com/deepfence/package-scanner/util"
	log "github.com/sirupsen/logrus"
)

var (
	linuxExcludeDirs = []string{"/var/lib/docker", "/var/lib/containerd", "/mnt", "/run", "/proc", "/dev", "/boot", "/home/kubernetes/containerized_mounter", "/sys", "/lost+found"}
	mntDirs          = getNfsMountsDirs()
)

func GenerateSBOM(config util.Config) ([]byte, error) {
	jsonFile := filepath.Join("/var/tmp", util.RandomString(12)+"output.json")
	syftArgs := []string{"packages", config.Source, "-o", "json","--file",jsonFile, "-q"}
	if strings.HasPrefix(config.Source, "dir:") || config.Source == "." {
		for _, excludeDir := range linuxExcludeDirs {
			syftArgs = append(syftArgs, "--exclude", "."+excludeDir+"/**")
		}
		var scanDir = config.Source
		if strings.HasPrefix(config.Source, "dir:") {
			scanDir = strings.Split(scanDir, ":")[1]
		}
		scanDir, _ = filepath.Abs(scanDir)
		for _, excludeDir := range mntDirs {
			if strings.Index(excludeDir, scanDir) == 0 {
				excludeDir = strings.Replace(excludeDir, scanDir, "/", 1)
			}
			syftArgs = append(syftArgs, "--exclude", "."+excludeDir+"/**")
		}
	} else {
		for _, excludeDir := range linuxExcludeDirs {
			syftArgs = append(syftArgs, "--exclude", excludeDir)
		}
		if !strings.HasPrefix(config.Source, "registry:") {
			if config.ContainerRuntimeName == vesselConstants.CONTAINERD && config.ContainerRuntime != nil {
				// This means the underlying container runtime is containerd
				// in case of image scan, we need to generate image tar file and
				// feed it to syft, since syft does not support listing images from containerd
				// ref: https://github.com/anchore/syft/issues/1048
				//
				// TODO : Remove this commit after anchore/syft#1048 is resolved
				//
				// create a temp directory for tar
				tmpDir, err := ioutil.TempDir("", "syft-")
				if err != nil {
					log.Errorf("Error creating temp directory: %v", err)
					return nil, err
				}
				defer os.RemoveAll(tmpDir)
				// create a tar file for the image
				tarFile := filepath.Join(tmpDir, "image.tar")
				_, err = config.ContainerRuntime.Save(config.Source, tarFile)
				if err != nil {
					log.Errorf("Error creating tar file: %v", err)
					return nil, err
				}
				// feed the tar file to syft
				syftArgs[1] = "oci-archive:" + tarFile
			}
		}
	}
	if config.ScanType != "" && config.ScanType != "all" {
		scanTypes := strings.Split(config.ScanType, ",")
		for _, scanType := range scanTypes {
			if scanType == "base" {
				syftArgs = append(syftArgs, "--catalogers", "dpkgdb-cataloger", "--catalogers", "rpmdb-cataloger", "--catalogers", "apkdb-cataloger", "--catalogers", "alpmdb-cataloger")
			} else if scanType == "ruby" {
				syftArgs = append(syftArgs, "--catalogers", "ruby-gemfile-cataloger", "--catalogers", "ruby-gemspec-cataloger")
			} else if scanType == "python" {
				syftArgs = append(syftArgs, "--catalogers", "python-index-cataloger", "--catalogers", "python-package-cataloger")
			} else if scanType == "javascript" {
				syftArgs = append(syftArgs, "--catalogers", "javascript-lock-cataloger", "--catalogers", "javascript-package-cataloger")
			} else if scanType == "php" {
				syftArgs = append(syftArgs, "--catalogers", "php-composer-installed-cataloger", "--catalogers", "php-composer-lock-cataloger")
			} else if scanType == "golang" {
				syftArgs = append(syftArgs, "--catalogers", "go-mod-file-cataloger")
			} else if scanType == "java" {
				syftArgs = append(syftArgs, "--catalogers", "java-cataloger")
			} else if scanType == "rust" {
				syftArgs = append(syftArgs, "--catalogers", "rust-cataloger")
			} else if scanType == "dotnet" {
				syftArgs = append(syftArgs, "--catalogers", "dotnet-deps-cataloger")
			}
		}
	}

	var publisher *output.Publisher
	var err error

	if config.VulnerabilityScan == true {
		publisher, err = output.NewPublisher(config)
		if err != nil {
			log.Error("error in creating publisher")
			return nil, err
		}
		publisher.PublishScanStatus("GENERATING_SBOM")
	}

	cmd := exec.Command("syft", syftArgs...)
	if config.RegistryId != "" && config.NodeType == util.NodeTypeImage {
		authFilePath, err := GetConfigFileFromRegistry(config.RegistryId)
		if err != nil {
			log.Error("error in getting authFilePath")
			return nil, err
		}
		defer os.RemoveAll(authFilePath)
		cmd.Env = os.Environ()
		cmd.Env = append(cmd.Env, fmt.Sprintf("DOCKER_CONFIG=%s", authFilePath))
	}

	//logrus.Infof("Generating SBOM: %s - syft %v", config.Source, syftArgs)
	stat, err := cmd.CombinedOutput()
	if err != nil {
		log.Error("error from syft command for syftArgs:" + strings.Join(syftArgs, " "))
		log.Error("sbom output:" + string(stat))
		if config.VulnerabilityScan == true {
			publisher.PublishScanError(err.Error())
		}
		return nil, err
	}

	sbom, err := ioutil.ReadFile(jsonFile)
	if err != nil {
		log.Error("error reading internal file",err)
		return nil, err
	}
	defer os.RemoveAll(jsonFile)

	

	if config.VulnerabilityScan == true {
		publisher.StopPublishScanStatus()
		// Send sbom to Deepfence Management Console for Vulnerability Scan
		publisher.RunVulnerabilityScan(sbom)

		if config.Quiet == true && config.FailOnScore <= 0 && config.FailOnCount <= 0 {
			return sbom, nil
		}

		vulnerabilityScanDetail, err := publisher.GetVulnerabilityScanResults()
		if err != nil {
			log.Error("error in getting vulnerability scan detail")
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
			if vulnerabilityScanDetail.Total >= config.FailOnCount {
				exitOnSeverity(vulnerabilityScanDetail.Total, config.FailOnCount)
			} else if vulnerabilityScanDetail.Severity.Critical >= config.FailOnCriticalCount {
				exitOnSeverity(vulnerabilityScanDetail.Severity.Critical, config.FailOnCriticalCount)
			} else if vulnerabilityScanDetail.Severity.High >= config.FailOnHighCount {
				exitOnSeverity(vulnerabilityScanDetail.Severity.High, config.FailOnHighCount)
			} else if vulnerabilityScanDetail.Severity.Medium >= config.FailOnMediumCount {
				exitOnSeverity(vulnerabilityScanDetail.Severity.Medium, config.FailOnMediumCount)
			} else if vulnerabilityScanDetail.Severity.Low >= config.FailOnLowCount {
				exitOnSeverity(vulnerabilityScanDetail.Severity.Low, config.FailOnLowCount)
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

func getNfsMountsDirs() []string {
	outputFileName := "/tmp/nfs-mounts.txt"
	cmdFileName := "/tmp/get-nfs.sh"
	nfsCmd := fmt.Sprintf("findmnt -l -t nfs4,tmpfs -n --output=TARGET > %s", outputFileName)
	errVal := ioutil.WriteFile(cmdFileName, []byte(nfsCmd), 0600)
	if errVal != nil {
		log.Warnf("Error while writing mount read command %s \n", errVal.Error())
		return nil
	}
	cmdOutput, cmdErr := exec.Command("bash", cmdFileName).CombinedOutput()
	if cmdErr != nil {
		fileSize, _ := os.Stat(outputFileName)
		if (string(cmdOutput) == "") && (fileSize.Size() == 0) {
			log.Infoln("No mount points detected")
		} else {
			log.Warnf("Error getting mount points. %s %s \n", cmdErr.Error(), string(cmdOutput))
		}
		os.Remove(cmdFileName)
		return nil
	}
	file, err := os.Open(outputFileName)
	if err != nil {
		log.Warnf("Error while opening file %s\n", err.Error())
		os.Remove(outputFileName)
		os.Remove(cmdFileName)
		return nil
	}
	defer file.Close()
	var skipDirs []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		if scanner.Err() != nil {
			log.Warnf("Error while reading mounted files %s", scanner.Err().Error())
			os.Remove(outputFileName)
			os.Remove(cmdFileName)
			return nil
		}
		skipDirs = append(skipDirs, line)
	}
	os.Remove(outputFileName)
	os.Remove(cmdFileName)
	return skipDirs
}
