package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path"
	"runtime"
	"sort"
	"strconv"
	"strings"

	"github.com/deepfence/vessel"
	"github.com/gin-gonic/gin"

	out "github.com/deepfence/package-scanner/output"
	"github.com/deepfence/package-scanner/sbom"
	"github.com/deepfence/package-scanner/scanner/grype"
	"github.com/deepfence/package-scanner/scanner/router"
	"github.com/deepfence/package-scanner/utils"
	vc "github.com/deepfence/vessel/constants"
	containerdRuntime "github.com/deepfence/vessel/containerd"
	crioRuntime "github.com/deepfence/vessel/crio"
	dockerRuntime "github.com/deepfence/vessel/docker"
	log "github.com/sirupsen/logrus"
)

const (
	PluginName = "PackageScanner"
)

var (
	supportedRuntime = []string{vc.DOCKER, vc.CONTAINERD, vc.CRIO}
	modes            = []string{utils.ModeLocal, utils.ModeGrpcServer, utils.ModeHttpServer, utils.ModeScannerOnly}
	severities       = []string{utils.CRITICAL, utils.HIGH, utils.MEDIUM, utils.LOW}
)

var (
	mode                  = flag.String("mode", utils.ModeLocal, strings.Join(modes, "/"))
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
	c_runtime             = flag.String("container-runtime", "auto", "container runtime to be used can be one of "+strings.Join(supportedRuntime, "/"))
	severity              = flag.String("severity", "", "Filter Vulnerabilities by severity, can be one or comma separated values of "+strings.Join(severities, "/"))
)

func runOnce(config utils.Config) {
	if config.Source == "" {
		log.Fatal("error: source is required")
	}
	if config.FailOnScore > 10.0 {
		log.Fatal("error: fail-on-score should be between -1 and 10")
	}
	if config.Output != utils.TableOutput && config.Output != utils.JsonOutput {
		log.Errorf("error: output should be %s or %s", utils.JsonOutput, utils.TableOutput)
	}
	// trim any spaces from severities passed from command line
	c_severity := []string{}
	if len(*severity) > 0 {
		for _, s := range strings.Split(*severity, ",") {
			c_severity = append(c_severity, strings.TrimSpace(s))
		}
	}

	hostname := utils.GetHostname()
	if strings.HasPrefix(config.Source, "dir:") || config.Source == "." {
		hostname := utils.GetHostname()
		config.HostName = hostname
		config.NodeId = hostname
		config.NodeType = utils.NodeTypeHost
		if config.ScanId == "" {
			config.ScanId = hostname + "_" + utils.GetDateTimeNow()
		}
	} else {
		config.NodeId = config.Source
		config.HostName = hostname
		config.NodeType = utils.NodeTypeImage
		if config.ScanId == "" {
			config.ScanId = config.Source + "_" + utils.GetDateTimeNow()
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
		log.Fatalf("error on grype.Scan: %s", err.Error())
	}

	report, err := grype.PopulateFinalReport(vulnerabilities, config)
	if err != nil {
		log.Fatalf("error on generate vulnerability report: %s", err.Error())
	}

	filtered := out.FilterBySeverity(&report, c_severity)
	sort.Slice(filtered[:], func(i, j int) bool {
		return utils.SeverityToInt(filtered[i].CveSeverity) > utils.SeverityToInt(filtered[j].CveSeverity)
	})

	if *output != utils.JsonOutput {
		out.TableOutput(&filtered)
	} else {
		data, err := json.MarshalIndent(filtered, "", "  ")
		if err != nil {
			log.Fatalf("error converting report to json, %s", err)
		}
		fmt.Println(string(data))
	}
}

func main() {

	// setup logger
	log.SetOutput(os.Stderr)
	log.SetReportCaller(true)
	log.SetFormatter(&log.TextFormatter{
		DisableColors: false,
		ForceColors:   true,
		FullTimestamp: true,
		CallerPrettyfier: func(f *runtime.Frame) (string, string) {
			return "", " " + path.Base(f.File) + ":" + strconv.Itoa(f.Line)
		},
	})

	// make sure logs come to stdout in other modes except local
	// local logs go to stderr to keep stdout clean for redirecting to file
	if *mode != utils.ModeLocal {
		log.SetOutput(os.Stdout)
	}

	flag.Parse()

	var (
		containerRuntime string
		endpoint         string
		err              error
	)

	// no need to determine runtime if local directory
	if !strings.HasPrefix(*source, "dir:") {
		if *c_runtime != "auto" {
			if !utils.Contains(supportedRuntime, *c_runtime) {
				log.Fatalf("unsupported runtime has to be one of %s", strings.Join(supportedRuntime, "/"))
			}
			containerRuntime = *c_runtime
			switch *c_runtime {
			case vc.DOCKER:
				endpoint = vc.DOCKER_SOCKET_URI
			case vc.CONTAINERD:
				endpoint = vc.CONTAINERD_SOCKET_URI
			case vc.CRIO:
				endpoint = vc.CRIO_SOCKET_URI
			}
		} else {
			containerRuntime, endpoint, err = vessel.AutoDetectRuntime()
			if err != nil {
				log.Errorf("error detecting container runtime: %v", err)
			}
		}
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

	if !strings.HasPrefix(*source, "dir:") {
		switch containerRuntime {
		case vc.DOCKER:
			config.ContainerRuntime = dockerRuntime.New()
		case vc.CONTAINERD:
			config.ContainerRuntime = containerdRuntime.New(endpoint)
		case vc.CRIO:
			config.ContainerRuntime = crioRuntime.New(endpoint)
		default:
			log.Fatalf("unsupported container runtime %s", containerRuntime)
		}
	}

	switch *mode {
	case utils.ModeLocal:
		runOnce(config)
	case utils.ModeGrpcServer:
		err := sbom.RunGrpcServer(PluginName, config)
		if err != nil {
			log.Fatalf("error running grpc server: %v", err)
		}
	case utils.ModeHttpServer:
		err := sbom.RunHttpServer(config)
		if err != nil {
			log.Fatalf("error running http server: %v", err)
		}
	case utils.ModeScannerOnly:
		r := router.New()
		r.Use(gin.Logger())
		if *port == "" {
			*port = "8001"
		}
		log.Infof("listen on port: %s", *port)
		log.Fatal(r.Run(":" + *port))
	default:
		log.Fatalf("unsupported mode %s", *mode)
	}
}
