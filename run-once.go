package main

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/deepfence/YaraHunter/pkg/threatintel"
	out "github.com/deepfence/package-scanner/output"
	"github.com/deepfence/package-scanner/sbom/syft"
	"github.com/deepfence/package-scanner/scanner"
	"github.com/deepfence/package-scanner/scanner/grype"
	"github.com/deepfence/package-scanner/utils"
	"github.com/google/uuid"
	log "github.com/sirupsen/logrus"
)

var (
	checksumFile = "checksum.txt"
	grypeDBPath  = "grype/db/5"
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

	ctx := context.Background()
	// update vulnerability db
	updateRules(ctx, config)

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

	env := []string{
		fmt.Sprintf("XDG_CACHE_HOME=%s", userCacheDir),
		fmt.Sprintf("GRYPE_DB_CACHE_DIR=%s", path.Join(userCacheDir, "grype", "db")),
		"GRYPE_DB_AUTO_UPDATE=false",
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
		fmt.Printf("summary:\n total=%d %s=%d %s=%d %s=%d %s=%d %s=%d\n",
			details.Total,
			utils.CRITICAL, details.Severity.Critical,
			utils.HIGH, details.Severity.High,
			utils.MEDIUM, details.Severity.Medium,
			utils.LOW, details.Severity.Low,
			utils.UNKNOWN, details.Severity.Unknown)
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
		if r.InitExploitabilityScore > 0 {
			exploitable = append(exploitable, r)
		} else {
			others = append(others, r)
		}
	}
	return
}

func updateRules(ctx context.Context, opts utils.Config) {
	log.Infof("check and update vulnerability db")

	listing, err := threatintel.FetchThreatIntelListing(ctx, version, opts.Product, opts.License)
	if err != nil {
		log.Fatal(err)
	}

	rulesInfo, err := listing.GetLatest(version, "vulnerability")
	if err != nil {
		log.Fatal(err)
	}
	log.Debugf("rulesInfo: %+v", rulesInfo)

	rulesPath := filepath.Join(userCacheDir, grypeDBPath)

	log.Debugf("database path: %s", rulesPath)

	// make sure output rules directory exists
	os.MkdirAll(rulesPath, fs.ModePerm)

	// check if update required
	if threatintel.SkipRulesUpdate(filepath.Join(rulesPath, checksumFile), rulesInfo.Checksum) {
		log.Info("skip rules update")
		return
	}

	log.Info("download new rules")
	content, err := threatintel.DownloadFile(ctx, rulesInfo.URL)
	if err != nil {
		log.Fatal(err)
	}

	log.Infof("vulnerability db file size: %d bytes", content.Len())

	checksumPath := filepath.Join(rulesPath, checksumFile)
	log.Debugf("checksum path: %s", checksumPath)
	// write new checksum
	if err := os.WriteFile(
		checksumPath, []byte(rulesInfo.Checksum), fs.ModePerm); err != nil {
		log.Fatal(err)
	}

	// Uncompress the gzipped content
	gzipReader, err := gzip.NewReader(content)
	if err != nil {
		log.Fatal(err)
	}
	defer gzipReader.Close()

	// Create a tar reader to read the uncompressed data
	tarReader := tar.NewReader(gzipReader)

	// Iterate over the files in the tar archive
	for {
		header, err := tarReader.Next()
		if err == io.EOF {
			break // End of tar archive
		}
		if err != nil {
			log.Fatal(err)
		}

		// skip some files
		if header.FileInfo().IsDir() {
			continue
		}

		outPath := filepath.Join(rulesPath, header.Name)
		log.Infof("extract db file %s", outPath)

		outFile, err := os.Create(outPath)
		if err != nil {
			log.Fatal(err)
		}
		if _, err := io.Copy(outFile, tarReader); err != nil {
			log.Fatal(err)
		}
		outFile.Close()

	}
}
