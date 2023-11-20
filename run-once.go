package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path"
	"sort"
	"strings"
	"time"

	out "github.com/deepfence/package-scanner/output"
	"github.com/deepfence/package-scanner/sbom/syft"
	"github.com/deepfence/package-scanner/scanner"
	"github.com/deepfence/package-scanner/scanner/grype"
	"github.com/deepfence/package-scanner/utils"
	"github.com/google/uuid"
	log "github.com/sirupsen/logrus"
)

func RunOnce(config utils.Config) {
	if config.Source == "" {
		log.Fatal("error: source is required")
	}
	if config.FailOnScore > 10.0 {
		log.Fatal("error: fail-on-score should be between -1 and 10")
	}
	if config.Output != utils.TableOutput && config.Output != utils.JSONOutput {
		log.Errorf("error: output should be %s or %s", utils.JSONOutput, utils.TableOutput)
	}
	// trim any spaces from severities passed from command line
	cSeverity := []string{}
	if len(*severity) > 0 {
		for _, s := range strings.Split(*severity, ",") {
			cSeverity = append(cSeverity, strings.TrimSpace(s))
		}
	}

	hostname := utils.GetHostname()
	if strings.HasPrefix(config.Source, "dir:") || config.Source == "." {
		hostname := utils.GetHostname()
		config.HostName = hostname
		config.NodeID = hostname
		config.NodeType = utils.NodeTypeHost
		if config.ScanID == "" {
			config.ScanID = fmt.Sprintf("%s_%d", hostname, utils.GetIntTimestamp())
		}
	} else {
		config.NodeID = config.Source
		config.HostName = hostname
		config.NodeType = utils.NodeTypeImage
		if config.ScanID == "" {
			config.ScanID = fmt.Sprintf("%s_%d", hostname, utils.GetIntTimestamp())
		}
		if imageID, err := config.ContainerRuntime.GetImageID(config.Source); err != nil {
			log.Error(err)
			// generate image_id if we are unable to get it from runtime
			imageID = []byte(uuid.New().String())
			config.ImageID = string(imageID)
			config.NodeID = string(imageID)
		} else {
			sp := strings.Split(strings.TrimSpace(string(imageID)), ":")
			config.ImageID = sp[len(sp)-1]
			config.NodeID = sp[len(sp)-1]
		}
		log.Debugf("image_id: %s", config.ImageID)
	}

	// try to get image id

	var pub *out.Publisher
	var err error
	// send sbom to console if console url and key are configured
	if len(config.ConsoleURL) != 0 && len(config.DeepfenceKey) != 0 {
		pub, err = out.NewPublisher(config)
		if err != nil {
			log.Error(err)
		}
		pub.SendReport()
		scanID := pub.StartScan()
		if scanID == "" {
			log.Warn("console scan id is empty")
			scanID = fmt.Sprintf("%s-%d", config.ImageID, time.Now().UnixMilli())
		}
		config.ScanID = scanID
		pub.SetScanID(scanID)
	}
	log.Infof("scan id %s", config.ScanID)

	log.Debugf("config: %+v", config)

	log.Debugf("generating sbom for %s ...", config.Source)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	sbomResult, err := syft.GenerateSBOM(ctx, config)
	if err != nil {
		log.Errorf("Error: %v", err)
		return
	}

	// send sbom to console if console url and key are configured
	if len(config.ConsoleURL) != 0 && len(config.DeepfenceKey) != 0 {
		log.Infof("sending sbom to console at %s", config.ConsoleURL)
		pub.RunVulnerabilityScan(sbomResult)
	}

	// create a temporary file to store the user input(SBOM)
	file, err := utils.CreateTempFile(sbomResult)
	if err != nil {
		log.Errorf("error on CreateTempFile: %s", err.Error())
		return
	}
	if !config.KeepSbom {
		defer os.Remove(file.Name())
	} else {
		log.Infof("generated sbom file at %s", file.Name())
	}

	// get user cache dir
	cacheDir, dirErr := os.UserCacheDir()
	if dirErr != nil {
		log.Panic(dirErr)
	}

	env := []string{
		fmt.Sprintf("GRYPE_DB_CACHE_DIR=%s", path.Join(cacheDir, "grype", "db")),
	}

	log.Debug("scanning sbom for vulnerabilities ...")
	vulnerabilities, err := grype.Scan(config.GrypeBinPath, config.GrypeConfigPath, file.Name(), &env)
	if err != nil {
		log.Panicf("error on sbom scan: %s %s", err.Error(), vulnerabilities)
	}

	report, err := grype.PopulateFinalReport(vulnerabilities, config)
	if err != nil {
		log.Panicf("error on generate vulnerability report: %s", err.Error())
	}

	// send vulnerability scan results to console
	if len(config.ConsoleURL) != 0 && len(config.DeepfenceKey) != 0 {
		log.Infof("sending scan result to console at %s", config.ConsoleURL)
		_ = pub.SendScanResultToConsole(report)
	}

	// scan details
	details := out.CountBySeverity(&report)
	// filter by severity
	filtered := FilterBySeverity(&report, cSeverity)
	// sort by severity
	sort.Slice(filtered, func(i, j int) bool {
		return severityToInt(filtered[i].CveSeverity) > severityToInt(filtered[j].CveSeverity)
	})

	exploitable, others := GroupByExploitability(&filtered)

	if *output != utils.JSONOutput {
		fmt.Printf("summary:\n total=%d %s=%d %s=%d %s=%d %s=%d\n",
			details.Total,
			utils.CRITICAL, details.Severity.Critical,
			utils.HIGH, details.Severity.High,
			utils.MEDIUM, details.Severity.Medium,
			utils.LOW, details.Severity.Low)
		if len(exploitable) > 0 {
			fmt.Println("\nMost Exploitable Vulnerabilities:")
			_ = out.TableOutput(&exploitable)
		}
		if len(others) > 0 {
			fmt.Println("\nOther Vulnerabilities:")
			_ = out.TableOutput(&others)
		}
		// out.TableOutput(&filtered)
	} else {
		final := map[string]interface{}{
			"summary":                          details,
			"most_exploitable_vulnerabilities": exploitable,
			"other_vulnerabilities":            others,
		}
		data, err := json.MarshalIndent(final, "", "  ")
		if err != nil {
			log.Panicf("error converting report to json, %s", err)
		}
		fmt.Println(string(data))
	}
	out.FailOn(&config, details)
}

func severityToInt(severity string) int {
	switch severity {
	case utils.CRITICAL:
		return 5
	case utils.HIGH:
		return 4
	case utils.MEDIUM:
		return 3
	case utils.LOW:
		return 2
	case utils.NEGLIGIBLE:
		return 1
	case utils.UNKNOWN:
		return 0
	default:
		return -1
	}
}

func FilterBySeverity(
	report *[]scanner.VulnerabilityScanReport,
	severity []string,
) []scanner.VulnerabilityScanReport {

	// if there are no filters return original report
	if len(severity) < 1 {
		return *report
	}

	filtered := []scanner.VulnerabilityScanReport{}

	for _, r := range *report {
		if utils.Contains(severity, r.CveSeverity) {
			filtered = append(filtered, r)
		}
	}

	return filtered
}

func GroupByExploitability(
	reports *[]scanner.VulnerabilityScanReport,
) (
	exploitable []scanner.VulnerabilityScanReport,
	others []scanner.VulnerabilityScanReport,
) {

	for _, r := range *reports {
		if r.ExploitabilityScore > 0 {
			exploitable = append(exploitable, r)
		} else {
			others = append(others, r)
		}
	}
	return
}
