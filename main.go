package main

import (
	"flag"
	"github.com/deepfence/package-scanner/package-sbom"
	"github.com/deepfence/package-scanner/util"
	log "github.com/sirupsen/logrus"
	"strconv"
	"strings"
)

const (
	PluginName = "PackageScanner"
)

var (
	mode                  = flag.String("mode", util.ModeLocal, util.ModeLocal+" | "+util.ModeGrpcServer)
	socketPath            = flag.String("socket-path", "", "Socket path for grpc server")
	port                  = flag.String("port", "", "Port for grpc server")
	output                = flag.String("output", util.JsonOutput, "Output format: json")
	quiet                 = flag.Bool("quiet", false, "Don't display any output in stdout")
	managementConsoleUrl  = flag.String("mgmt-console-url", "", "Deepfence Management Console URL")
	managementConsolePort = flag.Int("mgmt-console-port", 443, "Deepfence Management Console Port")
	vulnerabilityScan     = flag.Bool("vulnerability-scan", false, "Publish SBOM to Deepfence Management Console and run Vulnerability Scan")
	deepfenceKey          = flag.String("deepfence-key", "", "Deepfence key for auth")
	source                = flag.String("source", "", "Image name (nginx:latest) or directory (dir:/)")
	scanType              = flag.String("scan-type", "base,java,python,ruby,php,javascript,rust,golang", "base,java,python,ruby,php,javascript,rust,golang")
	scanId                = flag.String("scan-id", "", "(Optional) Scan id")
)

func runOnce(config util.Config) {
	if config.Source == "" {
		log.Error("Error: source is required")
		return
	}
	hostname := util.GetHostname()
	if strings.HasPrefix(config.Source, "dir:") {
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
	log.Info(string(sbom))
}

func main() {
	flag.Parse()
	customFormatter := new(log.TextFormatter)
	customFormatter.TimestampFormat = "2006-01-02 15:04:05"
	log.SetFormatter(customFormatter)
	customFormatter.FullTimestamp = true

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
	}

	if *mode == util.ModeLocal {
		runOnce(config)
	} else if *mode == util.ModeGrpcServer {
		err := package_sbom.RunServer(PluginName, config)
		if err != nil {
			log.Errorf("error: %v", err)
			return
		}
	} else if *mode == util.ModeHttpServer {
		err := package_sbom.RunHttpServer(config)
		if err != nil {
			log.Errorf("Error running http server: %v", err)
			return
		}
	} else {
		log.Errorf("invalid mode")
		return
	}
}
