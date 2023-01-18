package grype

import (
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"

	"github.com/deepfence/package-scanner/scanner"
	"github.com/deepfence/package-scanner/utils"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
)

var (
	matcherToLanguage map[string]string
)

func init() {
	matcherToLanguage = map[string]string{
		"UnknownMatcherType": "unknown",
		"stock-matcher":      "stock",
		"apk-matcher":        "base",
		"ruby-gem-matcher":   "ruby",
		"dpkg-matcher":       "base",
		"rpmdb-matcher":      "base",
		"java-matcher":       "java",
		"python-matcher":     "python",
		"dotnet-matcher":     "dotnet",
		"javascript-matcher": "javascript",
		"msrc-matcher":       "dotnet",
	}
}

func Scan(grypeBinPath, grypeConfigPath, bomPath string, env *[]string) ([]byte, error) {
	cmd := fmt.Sprintf("%s -c %s sbom:%s -o json", grypeBinPath, grypeConfigPath, bomPath)
	log.Debugf("grype command: %s", cmd)
	ecmd := exec.Command("bash", "-c", cmd)
	if env != nil {
		ecmd.Env = append(ecmd.Env, *env...)
	}
	return ecmd.CombinedOutput()
}

func Parse(p []byte) (Document, error) {
	var doc Document
	err := json.Unmarshal(p, &doc)
	if err != nil {
		return doc, err
	}
	return doc, nil
}

func PopulateFinalReport(vulnerabilities []byte, cfg utils.Config) ([]scanner.VulnerabilityScanReport, error) {
	grypeDocument, err := Parse(vulnerabilities)
	if err != nil {
		return []scanner.VulnerabilityScanReport{}, err
	}
	var cveJsonList string
	var currentlyMaskedCveIds []string
	var fullReport []scanner.VulnerabilityScanReport

	currentlyMaskedCveIds, err = utils.GetCurrentlyMaskedCveIds(cfg.NodeId, cfg.NodeType)
	if err != nil {
		currentlyMaskedCveIds = []string{}
	}

	maskCveIdsInArgs := strings.Split(cfg.MaskCveIds, ",")
	maskCveIds := append(currentlyMaskedCveIds, maskCveIdsInArgs...)
	for _, match := range grypeDocument.Matches {
		description := match.Vulnerability.Description
		if description == "" {
			relatedVulnerabilities := match.RelatedVulnerabilities
			if len(relatedVulnerabilities) > 0 {
				description = relatedVulnerabilities[0].Description
			}
		}
		cveFixedInVersionList := match.Vulnerability.Fix.Versions
		cveFixedInVersion := ""
		if len(cveFixedInVersionList) != 0 {
			cveFixedInVersion = cveFixedInVersionList[0]
		}
		cveCVSSScoreList := match.Vulnerability.Cvss
		var cvssScore float64
		var overallScore float64
		var attackVector string
		if len(cveCVSSScoreList) == 0 {
			if len(match.RelatedVulnerabilities) > 0 {
				cvssScore, overallScore, attackVector = GetCvss(match.RelatedVulnerabilities[0].Cvss)
			}
		} else {
			cvssScore, overallScore, attackVector = GetCvss(cveCVSSScoreList)
		}

		msfPoCURL, urls := utils.ExtractExploitPocUrl(match.Vulnerability.URLs)

		report := scanner.VulnerabilityScanReport{
			Type:                  "cve",
			Masked:                "false",
			Host:                  cfg.HostName,
			NodeType:              cfg.NodeType,
			NodeId:                cfg.NodeId,
			HostName:              cfg.HostName,
			KubernetesClusterName: cfg.KubernetesClusterName,
			ScanId:                cfg.ScanId,
			CveId:                 match.Vulnerability.ID,
			CveType:               getLanguageFromMatcher(match.MatchDetails[0].Matcher),
			CveContainerImage:     cfg.NodeId,
			CveContainerImageId:   cfg.ImageId,
			CveContainerName:      cfg.ContainerName,
			CveSeverity:           strings.ToLower(match.Vulnerability.Severity),
			CveCausedByPackage:    match.Artifact.Name + ":" + match.Artifact.Version,
			CveContainerLayer:     "",
			CveFixedIn:            cveFixedInVersion,
			CveLink:               match.Vulnerability.DataSource,
			CveDescription:        description,
			CveCvssScore:          cvssScore,
			CveOverallScore:       overallScore,
			CveAttackVector:       attackVector,
			URLs:                  urls,
			ExploitPOC:            msfPoCURL,
		}

		if utils.Contains(maskCveIds, report.CveId) {
			report.Masked = "true"
		}

		if report.CveType == "base" {
			report.CveCausedByPackagePath = ""
		} else {
			report.CveCausedByPackagePath = combinePaths(match.Artifact.Locations)
		}

		dfVulnerabilitiesStr, err := json.Marshal(report)
		if err != nil {
			return []scanner.VulnerabilityScanReport{}, errors.Wrap(err, "failed to marshal vulnerability report")
		}
		if err == nil && string(dfVulnerabilitiesStr) != "" {
			cveJsonList += string(dfVulnerabilitiesStr) + ","
		}
		fullReport = append(fullReport, report)
	}

	return fullReport, nil
}

func getLanguageFromMatcher(matcher string) string {
	lang := matcherToLanguage[matcher]
	if lang == "" {
		return "base"
	}
	return lang
}

func combinePaths(paths []Coordinates) string {
	var combinedPath string
	for _, path := range paths {
		combinedPath += path.RealPath + ":"
	}
	return utils.TrimSuffix(combinedPath, ":")
}
