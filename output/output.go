package output

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"

	"github.com/deepfence/package-scanner/scanner"
	"github.com/deepfence/package-scanner/utils"
	tw "github.com/olekukonko/tablewriter"
	log "github.com/sirupsen/logrus"
)

type Publisher struct {
	config         utils.Config
	client         *Client
	stopScanStatus chan bool
}

func NewPublisher(config utils.Config) (*Publisher, error) {
	dfClient, err := NewClient(config)
	if err != nil {
		return nil, err
	}
	return &Publisher{
		config:         config,
		client:         dfClient,
		stopScanStatus: make(chan bool, 1),
	}, nil
}

func (p *Publisher) SetScanId(scanId string) {
	p.config.ScanId = scanId
	p.client.config.ScanId = scanId
}

func (p *Publisher) StartScan() string {
	scan_id, err := p.client.StartScanToConsole()
	if err != nil {
		log.Errorf("scan_id: %s error: %s", p.config.ScanId, err)
	}
	return scan_id
}

func (p *Publisher) PublishScanStatusMessage(message string, status string) {
	err := p.client.SendScanStatusToConsole(message, status)
	if err != nil {
		log.Errorf("scan_id: %s error: %s", p.config.ScanId, err)
	}
}

func (p *Publisher) PublishScanError(errMsg string) {
	p.stopScanStatus <- true
	time.Sleep(3 * time.Second)
	p.PublishScanStatusMessage(errMsg, "ERROR")
}

func (p *Publisher) PublishDocument(requestUrl string, postReader io.Reader) error {
	_, err := p.client.HttpRequest(http.MethodPost, requestUrl,
		postReader, nil, "application/json")
	return err
}

func (p *Publisher) PublishScanStatus(status string) {
	go func() {
		p.PublishScanStatusMessage("", status)
		ticker := time.NewTicker(60 * time.Second)
		for {
			select {
			case <-ticker.C:
				p.PublishScanStatusMessage("", status)
			case <-p.stopScanStatus:
				return
			}
		}
	}()
}

func (p *Publisher) StopPublishScanStatus() {
	p.stopScanStatus <- true
	time.Sleep(3 * time.Second)
}

func (p *Publisher) RunVulnerabilityScan(sbom []byte) {
	p.PublishScanStatusMessage("", "GENERATED_SBOM")
	defer p.StopPublishScanStatus()

	time.Sleep(3 * time.Second)

	err := p.client.SendSbomToConsole(sbom)
	if err != nil {
		p.PublishScanError(err.Error())
		log.Error(p.config.ScanId, " ", err.Error())
	}
}

func (p *Publisher) GetVulnerabilityScanResults() (*VulnerabilityScanDetail, error) {
	err := p.client.WaitForScanToComplete()
	if err != nil {
		return nil, err
	}
	return p.client.GetVulnerabilityScanSummary()
}

func (p *Publisher) PublishSBOMtoES(sbom []byte) error {
	return p.client.SendSBOMtoES(sbom)
}

func (p *Publisher) Output(vulnerabilityScanDetail *VulnerabilityScanDetail) error {
	log.Infof("Total Vulnerabilities: %d\n", vulnerabilityScanDetail.Total)
	log.Infof("Critical Vulnerabilities: %d\n", vulnerabilityScanDetail.Severity.Critical)
	log.Infof("High Vulnerabilities: %d\n", vulnerabilityScanDetail.Severity.High)
	log.Infof("Medium Vulnerabilities: %d\n", vulnerabilityScanDetail.Severity.Medium)
	log.Infof("Low Vulnerabilities: %d\n", vulnerabilityScanDetail.Severity.Low)
	log.Infof("Vulnerability Score: %f\n", vulnerabilityScanDetail.CveScore)

	vulnerabilities, err := p.client.GetVulnerabilities()
	if err != nil {
		return err
	}
	if len(vulnerabilities.Data.Hits) > 0 {
		fmt.Print("\nVulnerabilities\n\n")
	}
	if p.config.Output == utils.JsonOutput {
		var vuln []byte
		for _, cve := range vulnerabilities.Data.Hits {
			vuln, err = json.MarshalIndent(cve, "", "  ")
			if err == nil {
				fmt.Println(string(vuln))
			}
		}
	} else if p.config.Output == utils.TableOutput {
		table := tw.NewWriter(os.Stdout)
		table.SetHeader([]string{"CVE ID", "Severity", "Package", "Description"})
		table.SetHeaderLine(true)
		table.SetBorder(true)
		table.SetAutoWrapText(true)
		table.SetAutoFormatHeaders(true)
		table.SetColMinWidth(0, 15)
		table.SetColMinWidth(1, 15)
		table.SetColMinWidth(2, 15)
		table.SetColMinWidth(3, 50)
		var packageName string
		for _, cve := range vulnerabilities.Data.Hits {
			packageName = cve.Source.CveCausedByPackage
			if packageName == "" {
				packageName = cve.Source.CveCausedByPackagePath
			}
			table.Append([]string{cve.Source.CveID, cve.Source.CveSeverity,
				packageName, cve.Source.CveDescription})
		}
		table.Render()
	}
	return nil
}

func TableOutput(report *[]scanner.VulnerabilityScanReport) error {

	table := tw.NewWriter(os.Stdout)
	table.SetHeader([]string{"CVE ID", "Severity", "Package", "Description"})
	table.SetHeaderLine(true)
	table.SetBorder(true)
	table.SetAutoWrapText(true)
	table.SetAutoFormatHeaders(true)
	table.SetColMinWidth(0, 15)
	table.SetColMinWidth(1, 15)
	table.SetColMinWidth(2, 15)
	table.SetColMinWidth(3, 50)

	for _, r := range *report {
		if r.CveCausedByPackage == "" {
			r.CveCausedByPackage = r.CveCausedByPackagePath
		}
		table.Append([]string{r.CveId, r.CveSeverity, r.CveCausedByPackage, r.CveDescription})
	}
	table.Render()
	return nil
}

func ExitOnSeverityScore(score float64, failOnScore float64) {
	log.Debugf("ExitOnSeverityScore count=%f failOnCount=%f", score, failOnScore)
	if score >= failOnScore {
		log.Fatalf("Exit vulnerability scan. Vulnerability score (%f) reached/exceeded the limit (%f).",
			score, failOnScore)
	}
}

func ExitOnSeverity(severity string, count int, failOnCount int) {
	log.Debugf("ExitOnSeverity severity=%s count=%d failOnCount=%d", severity, count, failOnCount)
	if count >= failOnCount {
		if len(severity) > 0 {
			msg := "Exit vulnerability scan. Number of %s vulnerabilities (%d) reached/exceeded the limit (%d)."
			log.Fatalf(msg, severity, count, failOnCount)
		}
		msg := "Exit vulnerability scan. Number of vulnerabilities (%d) reached/exceeded the limit (%d)."
		log.Fatalf(msg, count, failOnCount)
	}
}

func FailOn(cfg *utils.Config, details *VulnerabilityScanDetail) {
	if cfg.FailOnCount > 0 {
		ExitOnSeverity("", details.Total, cfg.FailOnCount)
	} else if cfg.FailOnCriticalCount > 0 {
		ExitOnSeverity(utils.CRITICAL, details.Severity.Critical, cfg.FailOnCriticalCount)
	} else if cfg.FailOnHighCount > 0 {
		ExitOnSeverity(utils.HIGH, details.Severity.High, cfg.FailOnHighCount)
	} else if cfg.FailOnMediumCount > 0 {
		ExitOnSeverity(utils.MEDIUM, details.Severity.Medium, cfg.FailOnMediumCount)
	} else if cfg.FailOnLowCount > 0 {
		ExitOnSeverity(utils.LOW, details.Severity.Low, cfg.FailOnLowCount)
	}
	if cfg.FailOnScore > 0.0 {
		ExitOnSeverityScore(details.CveScore, cfg.FailOnScore)
	}
}
