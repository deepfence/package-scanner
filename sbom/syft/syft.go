package syft

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/deepfence/package-scanner/utils"
	"github.com/deepfence/vessel"
	containerdRuntime "github.com/deepfence/vessel/containerd"
	crioRuntime "github.com/deepfence/vessel/crio"
	dockerRuntime "github.com/deepfence/vessel/docker"
	podmanRuntime "github.com/deepfence/vessel/podman"
	vesselConstants "github.com/deepfence/vessel/utils"
	log "github.com/sirupsen/logrus"
)

var (
	linuxExcludeDirs = []string{
		"/var/lib/docker", "/var/lib/containerd", "/var/lib/containers",
		"/var/lib/crio", "/var/run/containers", "/home/kubernetes/containerized_mounter",
		"/mnt", "/run", "/proc", "/dev", "/boot", "/sys", "/lost+found",
	}
	mntDirs = getNfsMountsDirs()
)

const registryPrefix = "registry:"

type ContainerScan struct {
	containerId string
	tempDir     string
	namespace   string
}

func (containerScan *ContainerScan) exportFileSystemTar() error {
	log.Infof("ContainerScan: %+v", containerScan)

	// Auto-detect underlying container runtime
	containerRuntime, endpoint, err := vessel.AutoDetectRuntime()
	if err != nil {
		return err
	}
	var containerRuntimeInterface vessel.Runtime
	switch containerRuntime {
	case vesselConstants.DOCKER:
		containerRuntimeInterface = dockerRuntime.New(endpoint)
	case vesselConstants.CONTAINERD:
		containerRuntimeInterface = containerdRuntime.New(endpoint)
	case vesselConstants.CRIO:
		containerRuntimeInterface = crioRuntime.New(endpoint)
	case vesselConstants.PODMAN:
		containerRuntimeInterface = podmanRuntime.New(endpoint)
	}
	if containerRuntimeInterface == nil {
		log.Error("Error: Could not detect container runtime")
		return fmt.Errorf("failed to detect container runtime")
	}

	err = containerRuntimeInterface.ExtractFileSystemContainer(
		containerScan.containerId, containerScan.namespace,
		containerScan.tempDir+".tar")
	if err != nil {
		log.Errorf("errored: %s", err)
		return err
	}
	tarCmd := exec.Command("tar", "-xf", strings.TrimSpace(containerScan.tempDir+".tar"), "-C", containerScan.tempDir)
	stdout, err := runCommand(tarCmd)
	if err != nil {
		log.Errorf("error: %s output: %s", err, stdout.String())
		return err
	}

	return nil
}

func runCommand(cmd *exec.Cmd) (*bytes.Buffer, error) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	errorOnRun := cmd.Run()
	if errorOnRun != nil {
		if errorOnRun != context.Canceled {
			log.Errorf("cmd: %s", cmd.String())
			log.Errorf("error: %s", errorOnRun)
			errorOnRun = errors.New(fmt.Sprint(errorOnRun) + ": " + stderr.String())
		}
		return nil, errorOnRun
	}
	return &stdout, nil
}

func GenerateSBOM(ctx context.Context, config utils.Config) ([]byte, error) {
	jsonFile := filepath.Join("/tmp", utils.RandomString(12)+"output.json")
	syftArgs := []string{"packages", config.Source, "-o", "json", "--file", jsonFile, "-q"}
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
				excludeDir = strings.Replace(excludeDir, scanDir, "", 1)
			}
			syftArgs = append(syftArgs, "--exclude", "."+excludeDir+"/**")
		}
	} else {
		if config.NodeType != utils.NodeTypeContainer {
			for _, excludeDir := range linuxExcludeDirs {
				syftArgs = append(syftArgs, "--exclude", excludeDir)
			}
		}

		if (config.ContainerRuntimeName == vesselConstants.CONTAINERD ||
			config.ContainerRuntimeName == vesselConstants.CRIO ||
			config.ContainerRuntimeName == vesselConstants.PODMAN) &&
			config.ContainerRuntime != nil {
			// This means the underlying container runtime is containerd
			// in case of image scan, we need to generate image tar file and
			// feed it to syft, since syft does not support listing images from containerd
			// ref: https://github.com/anchore/syft/issues/1048
			//
			// TODO : Remove this commit after anchore/syft#1048 is resolved
			//
			// create a temp directory for tar
			tmpDir, err := os.MkdirTemp("", "syft-")
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
			switch config.ContainerRuntimeName {
			case vesselConstants.CONTAINERD:
				syftArgs[1] = "oci-archive:" + tarFile
			case vesselConstants.CRIO:
				syftArgs[1] = "docker-archive:" + tarFile
			case vesselConstants.PODMAN:
				syftArgs[1] = "docker-archive:" + tarFile
			}
		} else if config.NodeType == utils.NodeTypeContainer {
			tmpDir, err := os.MkdirTemp("", "syft-")
			if err != nil {
				log.Errorf("Error creating temp directory: %v", err)
				return nil, err
			}

			defer os.RemoveAll(tmpDir)
			defer os.Remove(tmpDir + ".tar")

			var containerScan ContainerScan
			if config.KubernetesClusterName != "" {
				containerScan = ContainerScan{containerId: config.ContainerID, tempDir: tmpDir, namespace: ""}
			} else {
				containerScan = ContainerScan{containerId: config.ContainerID, tempDir: tmpDir, namespace: "default"}
			}

			err = containerScan.exportFileSystemTar()
			if err != nil {
				log.Error(err)
				return nil, err
			}
			syftArgs[1] = "dir:" + tmpDir
		}
	}

	if config.ScanType != "" && config.ScanType != "all" {
		isRegistry := config.RegistryId != "" && config.NodeType == utils.NodeTypeImage
		syftArgs = append(syftArgs, buildCatalogersArg(config.ScanType, isRegistry)...)
	}

	if config.RegistryCreds.AuthFilePath != "" {
		if !strings.HasPrefix(syftArgs[1], registryPrefix) {
			syftArgs[1] = registryPrefix + syftArgs[1]
		}
	} else {
		syftArgs[1] = strings.Replace(syftArgs[1], registryPrefix, "", -1)
	}

	syftEnv := []string{}
	if config.RegistryId != "" && config.NodeType == utils.NodeTypeImage {
		if config.RegistryCreds.AuthFilePath != "" {
			syftEnv = append(syftEnv, fmt.Sprintf("DOCKER_CONFIG=%s", config.RegistryCreds.AuthFilePath))
		}
		if config.RegistryCreds.SkipTLSVerify {
			syftEnv = append(syftEnv, fmt.Sprintf("SYFT_REGISTRY_INSECURE_SKIP_TLS_VERIFY=%s", "true"))
		}
		if config.RegistryCreds.UseHttp {
			syftEnv = append(syftEnv, fmt.Sprintf("SYFT_REGISTRY_INSECURE_USE_HTTP=%s", "true"))
		}
	}

	cmd := exec.CommandContext(ctx, config.SyftBinPath, syftArgs...)
	cmd.Env = os.Environ()
	cmd.Env = append(cmd.Env, syftEnv...)

	log.Debugf("execute command: %s", cmd.String())
	log.Debugf("execute command with env: %s", syftEnv)

	stdout, err := runCommand(cmd)
	if err != nil {
		if err == context.Canceled {
			log.Infof("Command cacelled as context was cancelled %v",
				context.Canceled)
		} else {
			log.Errorf("failed command: %s", cmd.String())
			log.Errorf("failed command Env: %s", cmd.Env)
			log.Errorf("err: %s", err)
			log.Errorf("stdout: %s", stdout.String())
		}
		return []byte(""), err
	}

	sbom, err := os.ReadFile(jsonFile)
	if err != nil {
		log.Error("error reading internal file", err)
		return nil, err
	}
	defer os.RemoveAll(jsonFile)

	return sbom, nil
}

func buildCatalogersArg(scanType string, isRegistry bool) []string {
	syftArgs := []string{}
	scanTypes := strings.Split(scanType, ",")
	for _, s := range scanTypes {
		switch s {
		case utils.ScanTypeBase:
			syftArgs = append(syftArgs, "--catalogers", "dpkgdb-cataloger", "--catalogers", "rpm-db-cataloger", "--catalogers", "rpm-file-cataloger", "--catalogers", "apkdb-cataloger", "--catalogers", "alpmdb-cataloger", "--catalogers", "linux-kernel-cataloger")
		case utils.ScanTypeRuby:
			syftArgs = append(syftArgs, "--catalogers", "ruby-gemfile-cataloger", "--catalogers", "ruby-gemspec-cataloger")
		case utils.ScanTypePython:
			syftArgs = append(syftArgs, "--catalogers", "python-index-cataloger", "--catalogers", "python-package-cataloger")
		case utils.ScanTypeJavaScript:
			syftArgs = append(syftArgs, "--catalogers", "javascript-lock-cataloger", "--catalogers", "javascript-package-cataloger")
		case utils.ScanTypePhp:
			syftArgs = append(syftArgs, "--catalogers", "php-composer-installed-cataloger", "--catalogers", "php-composer-lock-cataloger")
		case utils.ScanTypeGolang:
			syftArgs = append(syftArgs, "--catalogers", "go-mod-file-cataloger")
		case utils.ScanTypeGolangBinary:
			syftArgs = append(syftArgs, "--catalogers", "go-module-binary-cataloger")
		case utils.ScanTypeJava:
			syftArgs = append(syftArgs, "--catalogers", "java-cataloger", "--catalogers", "java-gradle-lockfile-cataloger", "--catalogers", "java-pom-cataloger")
		case utils.ScanTypeRust:
			syftArgs = append(syftArgs, "--catalogers", "rust-cargo-lock-cataloger")
		case utils.ScanTypeRustBinary:
			syftArgs = append(syftArgs, "--catalogers", "cargo-auditable-binary-cataloger")
		case utils.ScanTypeDotnet:
			syftArgs = append(syftArgs, "--catalogers", "dotnet-deps-cataloger")
		}
	}
	return syftArgs
}

func getNfsMountsDirs() []string {
	cmdOutput, err := exec.Command("findmnt", "-l", "-t", "nfs4,tmpfs", "-n", "--output=TARGET").CombinedOutput()
	if err != nil {
		return nil
	}
	dirs := strings.Split(string(cmdOutput), "\n")
	var mountDirs []string
	for _, i := range dirs {
		if strings.TrimSpace(i) != "" {
			mountDirs = append(mountDirs, i)
		}
	}
	return mountDirs
}
