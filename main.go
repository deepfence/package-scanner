package main

import (
	"encoding/json"
	"flag"
	"os"
	"path"
	"runtime"
	"strconv"
	"strings"

	"github.com/deepfence/vessel"
	"github.com/gin-gonic/gin"

	"github.com/deepfence/package-scanner/sbom"
	"github.com/deepfence/package-scanner/scanner/grype"
	"github.com/deepfence/package-scanner/scanner/router"
	"github.com/deepfence/package-scanner/utils"
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
	mode                  = flag.String("mode", utils.ModeLocal, utils.ModeLocal+" or "+utils.ModeGrpcServer+" or "+utils.ModeHttpServer+" or "+utils.ModeScannerOnly)
	socketPath            = flag.String("socket-path", "", "Socket path for grpc server")
	port                  = flag.String("port", "", "Port for grpc server")
	output                = flag.String("output", utils.TableOutput, "Output format: json or table")
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

func runOnce(config utils.Config) {
	if config.Source == "" {
		log.Error("Error: source is required")
		return
	}
	if config.FailOnScore > 10.0 {
		log.Error("Error: fail-on-score should be between -1 and 10")
		return
	}
	if config.Output != utils.TableOutput && config.Output != utils.JsonOutput {
		log.Errorf("Error: output should be %s or %s", utils.JsonOutput, utils.TableOutput)
		return
	}
	hostname := utils.GetHostname()
	if strings.HasPrefix(config.Source, "dir:") || config.Source == "." {
		hostname := utils.GetHostname()
		config.HostName = hostname
		config.NodeId = hostname
		config.NodeType = utils.NodeTypeHost
		if config.ScanId == "" {
			config.ScanId = hostname + "_" + utils.GetDatetimeNow()
		}
	} else {
		config.NodeId = config.Source
		config.HostName = hostname
		config.NodeType = utils.NodeTypeImage
		if config.ScanId == "" {
			config.ScanId = config.Source + "_" + utils.GetDatetimeNow()
		}
	}
	sbom, err := sbom.GenerateSBOM(config)
	if err != nil {
		log.Errorf("Error: %v", err)
		return
	}
	// create a temporary file to store the user input(SBOM)
	file, err := utils.CreateTempFile(sbom)
	if err != nil {
		log.Errorf("error on CreateTempFile: %s", err.Error())
		return
	}

	defer os.Remove(file.Name())

	vulnerabilities, err := grype.Scan(file.Name())
	if err != nil {
		log.Errorf("error on grype.Scan: %s", err.Error())
		return
	}
	report, err := grype.PopulateFinalReport(vulnerabilities, config)
	if err != nil {
		log.Errorf("error on generate report: %s", err.Error())
	}
	data, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		log.Error(err)
	}
	log.Info(string(data))

}

func main() {

	// setup logger
	log.SetOutput(os.Stdout)
	log.SetReportCaller(true)
	log.SetFormatter(&log.TextFormatter{
		DisableColors: false,
		// ForceColors:   true,
		FullTimestamp: true,
		PadLevelText:  true,
		CallerPrettyfier: func(f *runtime.Frame) (string, string) {
			return "", " " + path.Base(f.File) + ":" + strconv.Itoa(f.Line)
		},
	})

	flag.Parse()

	containerRuntime, endpoint, err := vessel.AutoDetectRuntime()
	if err != nil {
		log.Errorf("Error detecting container runtime: %v", err)
	}

	config := utils.Config{
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

	if *mode == utils.ModeLocal {
		runOnce(config)
	} else if *mode == utils.ModeGrpcServer {
		err := sbom.RunGrpcServer(PluginName, config)
		if err != nil {
			log.Errorf("error: %v", err)
			return
		}
	} else if *mode == utils.ModeHttpServer {
		err := sbom.RunHttpServer(config)
		if err != nil {
			log.Errorf("Error running http server: %v", err)
			return
		}
	} else if *mode == utils.ModeScannerOnly {
		r := router.New()
		r.Use(gin.Logger())
		// Listen constantly on given port
		log.Info("LISTENING ON PORT: ", port)
		log.Fatal(r.Run(":" + *port))
	} else {
		log.Errorf("invalid mode")
		return
	}
}
