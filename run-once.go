package main

import (
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
			config.ScanId = fmt.Sprintf("%s_%d", hostname, utils.GetIntTimestamp())
		}
	} else {
		config.NodeId = config.Source
		config.HostName = hostname
		config.NodeType = utils.NodeTypeImage
		if config.ScanId == "" {
			config.ScanId = fmt.Sprintf("%s_%d", hostname, utils.GetIntTimestamp())
		}
		if image_id, err := config.ContainerRuntime.GetImageID(config.Source); err != nil {
			log.Error(err)
			// generate image_id if we are unable to get it from runtime
			image_id = []byte(uuid.New().String())
			config.ImageId = string(image_id)
			config.NodeId = string(image_id)
		} else {
			sp := strings.Split(strings.TrimSpace(string(image_id)), ":")
			config.ImageId = sp[len(sp)-1]
			config.NodeId = sp[len(sp)-1]
		}
		log.Debugf("image_id: %s", config.ImageId)
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
		scanId := pub.StartScan()
		if scanId == "" {
			log.Warn("console scan id is empty")
			scanId = fmt.Sprintf("%s-%d", config.ImageId, time.Now().UnixMilli())
		}
		config.ScanId = scanId
		pub.SetScanId(scanId)
	}
	log.Infof("scan id %s", config.ScanId)

	log.Debugf("config: %+v", config)

	log.Debugf("generating sbom for %s ...", config.Source)
	sbomResult, err := syft.GenerateSBOM(config)
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
		log.Fatal(dirErr)
	}

	env := []string{
		fmt.Sprintf("GRYPE_DB_CACHE_DIR=%s", path.Join(cacheDir, "grype", "db")),
	}

	log.Debug("scanning sbom for vulnerabilities ...")
	vulnerabilities, err := grype.Scan(config.GrypeBinPath, config.GrypeConfigPath, file.Name(), &env)
	if err != nil {
		log.Fatalf("error on sbom scan: %s %s", err.Error(), vulnerabilities)
	}

	report, err := grype.PopulateFinalReport(vulnerabilities, config)
	if err != nil {
		log.Fatalf("error on generate vulnerability report: %s", err.Error())
	}

	// send vulnerability scan results to console
	if len(config.ConsoleURL) != 0 && len(config.DeepfenceKey) != 0 {
		log.Infof("sending scan result to console at %s", config.ConsoleURL)
		pub.SendScanResultToConsole(report)
	}

	// scan details
	details := out.CountBySeverity(&report)
	// filter by severity
	filtered := FilterBySeverity(&report, c_severity)
	// sort by severity
	sort.Slice(filtered[:], func(i, j int) bool {
		return severityToInt(filtered[i].CveSeverity) > severityToInt(filtered[j].CveSeverity)
	})

	exploitable, others := GroupByExploitability(&filtered)

	if *output != utils.JsonOutput {
		fmt.Printf("summary:\n total=%d %s=%d %s=%d %s=%d %s=%d\n",
			details.Total,
			utils.CRITICAL, details.Severity.Critical,
			utils.HIGH, details.Severity.High,
			utils.MEDIUM, details.Severity.Medium,
			utils.LOW, details.Severity.Low)
		if len(exploitable) > 0 {
			fmt.Println("\nMost Exploitable Vulnerabilities:")
			out.TableOutput(&exploitable)
		}
		if len(others) > 0 {
			fmt.Println("\nOther Vulnerabilities:")
			out.TableOutput(&others)
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
			log.Fatalf("error converting report to json, %s", err)
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
