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
	dfClient       *Client
	stopScanStatus chan bool
}

func NewPublisher(config utils.Config) (*Publisher, error) {
	dfClient, err := NewClient(config)
	if err != nil {
		return nil, err
	}
	return &Publisher{
		config:         config,
		dfClient:       dfClient,
		stopScanStatus: make(chan bool, 1),
	}, nil
}

func (p *Publisher) PublishScanStatusMessage(message string, status string) {
	err := p.dfClient.SendScanStatusToConsole(message, status)
	if err != nil {
		log.Error(p.config.ScanId, " ", err.Error())
	}
}

func (p *Publisher) PublishScanError(errMsg string) {
	p.stopScanStatus <- true
	time.Sleep(3 * time.Second)
	p.PublishScanStatusMessage(errMsg, "ERROR")
}

func (p *Publisher) PublishDocument(requestUrl string, postReader io.Reader) error {
	_, err := p.dfClient.HttpRequest(http.MethodPost, requestUrl,
		postReader, nil, "application/json")
	return err
}

func (p *Publisher) PublishScanStatus(status string) {
	go func() {
		p.PublishScanStatusMessage("", status)
		ticker := time.NewTicker(2 * time.Minute)
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
	time.Sleep(3 * time.Second)
	err := p.dfClient.SendSbomToConsole(sbom)
	if err != nil {
		p.PublishScanError(err.Error())
		log.Error(p.config.ScanId, " ", err.Error())
	}
}

func (p *Publisher) GetVulnerabilityScanResults() (*VulnerabilityScanDetail, error) {
	err := p.dfClient.WaitForScanToComplete()
	if err != nil {
		return nil, err
	}
	return p.dfClient.GetVulnerabilityScanSummary()
}

func (p *Publisher) PublishSBOMtoES(sbom []byte) error {
	return p.dfClient.SendSBOMtoES(sbom)
}

func (p *Publisher) Output(vulnerabilityScanDetail *VulnerabilityScanDetail) error {
	log.Infof("Total Vulnerabilities: %d\n", vulnerabilityScanDetail.Total)
	log.Infof("Critical Vulnerabilities: %d\n", vulnerabilityScanDetail.Severity.Critical)
	log.Infof("High Vulnerabilities: %d\n", vulnerabilityScanDetail.Severity.High)
	log.Infof("Medium Vulnerabilities: %d\n", vulnerabilityScanDetail.Severity.Medium)
	log.Infof("Low Vulnerabilities: %d\n", vulnerabilityScanDetail.Severity.Low)
	log.Infof("Vulnerability Score: %f\n", vulnerabilityScanDetail.CveScore)

	vulnerabilities, err := p.dfClient.GetVulnerabilities()
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
		table.Append([]string{r.CveId, r.CveSeverity, r.CveCausedByPackage, r.CveDescription})
	}
	table.Render()
	return nil
}
