package grype

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"strings"

	"github.com/deepfence/package-scanner/scanner"
	"github.com/deepfence/package-scanner/utils"
	"github.com/rs/zerolog/log"
	"gopkg.in/yaml.v3"
	"zombiezen.com/go/sqlite"
	"zombiezen.com/go/sqlite/sqlitex"
)

const (
	grypeDBVersion = "5"
)

var (
	matcherToLanguage = map[string]string{
		"UnknownMatcherType": "unknown",
		"stock-matcher":      "unknown",
		"apk-matcher":        utils.ScanTypeBase,
		"ruby-gem-matcher":   utils.ScanTypeRuby,
		"dpkg-matcher":       utils.ScanTypeBase,
		"rpmdb-matcher":      utils.ScanTypeBase,
		"rpm-matcher":        utils.ScanTypeBase,
		"java-matcher":       utils.ScanTypeJava,
		"python-matcher":     utils.ScanTypePython,
		"dotnet-matcher":     utils.ScanTypeDotnet,
		"javascript-matcher": utils.ScanTypeJavaScript,
		"msrc-matcher":       utils.ScanTypeDotnet,
		"portage-matcher":    utils.ScanTypeBase,
		"go-module-matcher":  utils.ScanTypeGolang,
	}
	attackVectorRegex = regexp.MustCompile(`.*av:n.*`)
)

func Scan(grypeBinPath, grypeConfigPath, bomPath string, env *[]string) (string, error) {
	cmd := fmt.Sprintf("%s -c %s sbom:%s -o json", grypeBinPath, grypeConfigPath, bomPath)
	log.Debug().Str("command", cmd).Msg("grype command")
	ecmd := exec.Command("bash", "-c", cmd)
	if env != nil {
		ecmd.Env = append(ecmd.Env, *env...)
	}
	output, err := ecmd.CombinedOutput()
	return string(output), err
}

func Parse(p []byte) (Document, error) {
	var doc Document
	err := json.Unmarshal(p, &doc)
	if err != nil {
		return doc, err
	}
	return doc, nil
}

func getGrypeDBPath(cfg utils.Config) (string, error) {
	yamlFile, err := os.ReadFile(cfg.GrypeConfigPath)
	if err != nil {
		return "", err
	}
	var c GrypeConfig
	err = yaml.Unmarshal(yamlFile, &c)
	if err != nil {
		return "", err
	}

	if !strings.HasPrefix(c.DB.Dir, "/") {
		c.DB.Dir = "/" + c.DB.Dir
	}

	return fmt.Sprintf("%s/%s/vulnerability.db", c.DB.Dir, grypeDBVersion), nil
}

func PopulateFinalReport(vulnerabilities string, cfg utils.Config) ([]scanner.VulnerabilityScanReport, error) {
	grypeDocument, err := Parse([]byte(vulnerabilities))
	if err != nil {
		return []scanner.VulnerabilityScanReport{}, err
	}

	var fullReport []scanner.VulnerabilityScanReport

	grypeDBPath, err := getGrypeDBPath(cfg)
	if err != nil {
		return fullReport, err
	}
	conn, err := sqlite.OpenConn(grypeDBPath, sqlite.OpenReadWrite)
	if err != nil {
		return fullReport, err
	}
	defer conn.Close()

	maskCveIdsInArgs := strings.Split(cfg.MaskCveIds, ",")
	maskCveIds := append([]string{}, maskCveIdsInArgs...)
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

		if cvssScore == 0.0 {
			switch strings.ToLower(match.Vulnerability.Severity) {
			case "critical":
				cvssScore = DefaultCVSSCritical
			case "high":
				cvssScore = DefaultCVSSHigh
			case "medium":
				cvssScore = DefaultCVSSMedium
			case "low":
				cvssScore = DefaultCVSSLow
			}
		}

		metasploitURL, urls := utils.ExtractExploitPocURL(match.Vulnerability.URLs)

		var cisaKev bool
		var epssScore float64
		err = sqlitex.Execute(conn, "SELECT cisakev,epss FROM vulnerability_metadata WHERE id=? AND namespace=?", &sqlitex.ExecOptions{
			ResultFunc: func(stmt *sqlite.Stmt) error {
				cisaKev = stmt.ColumnBool(0)
				epssScore = stmt.ColumnFloat(1)
				return nil
			},
			Args: []any{match.Vulnerability.ID, match.Vulnerability.Namespace},
		})
		if err != nil {
			log.Error().Err(err).Msg("failed to query vulnerability metadata")
			// Don't exit, continue with default values
		}

		report := scanner.VulnerabilityScanReport{
			Masked:             utils.Contains(maskCveIds, match.Vulnerability.ID),
			ScanID:             cfg.ScanID,
			CveID:              match.Vulnerability.ID,
			CveType:            getLanguageFromMatcher(match.MatchDetails[0].Matcher),
			CveSeverity:        strings.ToLower(match.Vulnerability.Severity),
			CveCausedByPackage: match.Artifact.Name + ":" + match.Artifact.Version,
			CveContainerLayer:  "",
			CveFixedIn:         cveFixedInVersion,
			CveLink:            match.Vulnerability.DataSource,
			CveDescription:     description,
			CveCvssScore:       cvssScore,
			CveOverallScore:    overallScore,
			CveAttackVector:    attackVector,
			URLs:               urls,
			ExploitPOC:         metasploitURL,
			ParsedAttackVector: "",
			Namespace:          match.Vulnerability.Namespace,
			CISAKEV:            cisaKev,
			EPSSScore:          epssScore,
		}

		if report.CveType == "base" {
			report.CveCausedByPackagePath = ""
		} else {
			report.CveCausedByPackagePath = combinePaths(match.Artifact.Locations)
		}

		// calculate exploit-ability score
		if attackVectorRegex.MatchString(report.CveAttackVector) ||
			report.CveAttackVector == "network" || report.CveAttackVector == "n" {
			report.ParsedAttackVector = "network"
		} else {
			report.ParsedAttackVector = "local"
		}

		score := 0
		if report.ParsedAttackVector == "network" {
			score = 2
		} else if report.CveSeverity == "critical" {
			score = 1
		}

		report.ExploitabilityScore = 0
		report.InitExploitabilityScore = score
		report.HasLiveConnection = false

		fullReport = append(fullReport, report)
	}

	return fullReport, nil
}

func getLanguageFromMatcher(matcher string) string {
	lang := matcherToLanguage[matcher]
	if lang == "" {
		return utils.ScanTypeBase
	}
	return lang
}

func combinePaths(paths []Coordinates) string {
	var combinedPath string
	for _, path := range paths {
		combinedPath += path.RealPath + ":"
	}
	return strings.TrimSuffix(combinedPath, ":")
}
