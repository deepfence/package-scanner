package main

import (
	"flag"
	"strconv"
	"strings"

	"github.com/deepfence/vessel"

	package_sbom "github.com/deepfence/package-scanner/package-sbom"
	"github.com/deepfence/package-scanner/util"
	vesselConstants "github.com/deepfence/vessel/constants"
	containerdRuntime "github.com/deepfence/vessel/containerd"
	crioRuntime "github.com/deepfence/vessel/crio"
	dockerRuntime "github.com/deepfence/vessel/docker"
	log "github.com/sirupsen/logrus"
)

const (
	PluginName = "PackageScanner"
)

var (
	mode                  = flag.String("mode", util.ModeLocal, util.ModeLocal+" or "+util.ModeGrpcServer)
	socketPath            = flag.String("socket-path", "", "Socket path for grpc server")
	port                  = flag.String("port", "", "Port for grpc server")
	output                = flag.String("output", util.TableOutput, "Output format: json or table")
	quiet                 = flag.Bool("quiet", false, "Don't display any output in stdout")
	managementConsoleUrl  = flag.String("mgmt-console-url", "", "Deepfence Management Console URL")
	managementConsolePort = flag.Int("mgmt-console-port", 443, "Deepfence Management Console Port")
	vulnerabilityScan     = flag.Bool("vulnerability-scan", false, "Publish SBOM to Deepfence Management Console and run Vulnerability Scan")
	deepfenceKey          = flag.String("deepfence-key", "", "Deepfence key for auth")
	source                = flag.String("source", "", "Image name (nginx:latest) or directory (dir:/)")
	scanType              = flag.String("scan-type", "base,java,python,ruby,php,javascript,rust,golang,dotnet", "base,java,python,ruby,php,javascript,rust,golang,dotnet")
	scanId                = flag.String("scan-id", "", "(Optional) Scan id")
	failOnCount           = flag.Int("fail-on-count", -1, "Exit with status 1 if number of vulnerabilities found is >= this value (Default: -1)")
	failOnCriticalCount   = flag.Int("fail-on-critical-count", -1, "Exit with status 1 if number of critical vulnerabilities found is >= this value (Default: -1)")
	failOnHighCount       = flag.Int("fail-on-high-count", -1, "Exit with status 1 if number of high vulnerabilities found is >= this value (Default: -1)")
	failOnMediumCount     = flag.Int("fail-on-medium-count", -1, "Exit with status 1 if number of medium vulnerabilities found is >= this value (Default: -1)")
	failOnLowCount        = flag.Int("fail-on-low-count", -1, "Exit with status 1 if number of low vulnerabilities found is >= this value (Default: -1)")
	failOnSeverityCount   = flag.String("fail-on-count-severity", "", "Exit with status 1 if number of vulnerabilities of given severity found is >= fail-on-count")
	failOnScore           = flag.Float64("fail-on-score", -1, "Exit with status 1 if cumulative CVE score is >= this value (Default: -1)")
	maskCveIds            = flag.String("mask-cve-ids", "", "Comma separated cve id's to mask. Example: \"CVE-2019-9168,CVE-2019-9169\"")
)

func runOnce(config util.Config) {
	if config.Source == "" {
		log.Error("Error: source is required")
		return
	}
	if config.FailOnScore > 10.0 {
		log.Error("Error: fail-on-score should be between -1 and 10")
		return
	}
	if config.Output != util.TableOutput && config.Output != util.JsonOutput {
		log.Errorf("Error: output should be %s or %s", util.JsonOutput, util.TableOutput)
		return
	}
	hostname := util.GetHostname()
	if strings.HasPrefix(config.Source, "dir:") || config.Source == "." {
		hostname := util.GetHostname()
		config.HostName = hostname
		config.NodeId = hostname
		config.NodeType = util.NodeTypeHost
		if config.ScanId == "" {
			config.ScanId = hostname + "_" + util.GetDatetimeNow()
		}
	} else {
		config.NodeId = config.Source
		config.HostName = hostname
		config.NodeType = util.NodeTypeImage
		if config.ScanId == "" {
			config.ScanId = config.Source + "_" + util.GetDatetimeNow()
		}
	}
	
	sbom, err := package_sbom.GenerateSBOM(config)
	if err != nil {
		log.Errorf("Error: %v", err)
		return
	}
	if config.VulnerabilityScan == false && config.Quiet == false {
		log.Info(string(sbom))
	}
}

func main() {
	flag.Parse()
	customFormatter := new(log.TextFormatter)
	customFormatter.TimestampFormat = "2006-01-02 15:04:05"
	log.SetFormatter(customFormatter)
	customFormatter.FullTimestamp = true

	containerRuntime, endpoint, err := vessel.AutoDetectRuntime()
	if err != nil {
		log.Errorf("Error detecting container runtime: %v", err)
	} else {
		log.Debugf("Detected container runtime: %s", containerRuntime)
	}

	config := util.Config{
		Mode:                  *mode,
		SocketPath:            *socketPath,
		Port:                  *port,
		Output:                *output,
		Quiet:                 *quiet,
		ManagementConsoleUrl:  *managementConsoleUrl,
		ManagementConsolePort: strconv.Itoa(*managementConsolePort),
		DeepfenceKey:          *deepfenceKey,
		Source:                *source,
		ScanType:              *scanType,
		VulnerabilityScan:     *vulnerabilityScan,
		ScanId:                *scanId,
		FailOnScore:           *failOnScore,
		FailOnCount:           *failOnCount,
		FailOnCriticalCount:   *failOnCriticalCount,
		FailOnHighCount:       *failOnHighCount,
		FailOnMediumCount:     *failOnMediumCount,
		FailOnLowCount:        *failOnLowCount,
		FailOnSeverityCount:   *failOnSeverityCount,
		MaskCveIds:            *maskCveIds,
		ContainerRuntimeName:  containerRuntime,
	}

	if containerRuntime == vesselConstants.DOCKER {
		config.ContainerRuntime = dockerRuntime.New()
	} else if containerRuntime == vesselConstants.CONTAINERD {
		config.ContainerRuntime = containerdRuntime.New(endpoint)
	} else if containerRuntime == vesselConstants.CRIO {
		config.ContainerRuntime = crioRuntime.New(endpoint)
	}

	log.Infof("config for image %+v", config)

	if *mode == util.ModeLocal {
		runOnce(config)
	} else if *mode == util.ModeGrpcServer {
		err := package_sbom.RunGrpcServer(PluginName, config)
		if err != nil {
			log.Errorf("error: %v", err)
			return
		}
	} else if *mode == util.ModeHttpServer {
		err := package_sbom.RunHttpServer(config)
		log.Infof("config for image %+v", config)
		if err != nil {
			log.Errorf("Error running http server: %v", err)
			return
		}
	} else {
		log.Errorf("invalid mode")
		return
	}
}
