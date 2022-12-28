package main

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"

	out "github.com/deepfence/package-scanner/output"
	"github.com/deepfence/package-scanner/sbom"
	"github.com/deepfence/package-scanner/scanner"
	"github.com/deepfence/package-scanner/scanner/grype"
	"github.com/deepfence/package-scanner/utils"
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

	vulnerabilities, err := grype.Scan(config.GrypeBinPath, config.GrypeConfigPath, file.Name())
	if err != nil {
		log.Fatalf("error on grype.Scan: %s", err.Error())
	}

	report, err := grype.PopulateFinalReport(vulnerabilities, config)
	if err != nil {
		log.Fatalf("error on generate vulnerability report: %s", err.Error())
	}

	// filter by severity
	filtered := FilterBySeverity(&report, c_severity)
	// sort by severity
	sort.Slice(filtered[:], func(i, j int) bool {
		return severityToInt(filtered[i].CveSeverity) > severityToInt(filtered[j].CveSeverity)
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
