package output

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/containerd/containerd/log"
	"github.com/deepfence/package-scanner/internal/deepfence"
	"github.com/deepfence/package-scanner/util"
	"github.com/olekukonko/tablewriter"
	"github.com/sirupsen/logrus"
)

type Publisher struct {
	config         util.Config
	dfClient       *deepfence.Client
	stopScanStatus chan bool
}

func NewPublisher(config util.Config) (*Publisher, error) {
	dfClient, err := deepfence.NewClient(config)
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
	logrus.Infof("from pulsih scan status %+v", p.config)
	err := p.dfClient.SendScanStatustoConsole(message, status)
	if err != nil {
		logrus.Error(p.config.ScanId, " ", err.Error())
	}
}

func (p *Publisher) PublishScanError(errMsg string) {
	p.stopScanStatus <- true
	time.Sleep(3 * time.Second)
	p.PublishScanStatusMessage(errMsg, "ERROR")
}

func (p *Publisher) PublishDocument(requestUrl string, postReader io.Reader) error {
	_, err := p.dfClient.HttpRequest(deepfence.MethodPost, requestUrl, postReader, nil, "application/vnd.kafka.json.v2+json")
	return err
}

func (p *Publisher) PublishScanStatus(status string) {
	logrus.Infof("from pulsih scan status %+v", p.config)
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
	err := p.dfClient.SendSBOMtoConsole(sbom)
	if err != nil {
		p.PublishScanError(err.Error())
		logrus.Error(p.config.ScanId, " ", err.Error())
	}
}

func (p *Publisher) GetVulnerabilityScanResults() (*deepfence.VulnerabilityScanDetail, error) {
	err := p.dfClient.WaitForScanToComplete()
	if err != nil {
		return nil, err
	}
	return p.dfClient.GetVulnerabilityScanSummary()
}

func (p *Publisher) PublishSBOMtoES(sbom []byte) error {
	return p.dfClient.SendSBOMtoES(sbom)
}

func (p *Publisher) Output(vulnerabilityScanDetail *deepfence.VulnerabilityScanDetail) error {
	logrus.Infof("Total Vulnerabilities: %d\n", vulnerabilityScanDetail.Total)
	logrus.Infof("Critical Vulnerabilities: %d\n", vulnerabilityScanDetail.Severity.Critical)
	logrus.Infof("High Vulnerabilities: %d\n", vulnerabilityScanDetail.Severity.High)
	logrus.Infof("Medium Vulnerabilities: %d\n", vulnerabilityScanDetail.Severity.Medium)
	logrus.Infof("Low Vulnerabilities: %d\n", vulnerabilityScanDetail.Severity.Low)
	logrus.Infof("Vulnerability Score: %f\n", vulnerabilityScanDetail.CveScore)

	vulnerabilities, err := p.dfClient.GetVulnerabilities()
	if err != nil {
		return err
	}
	if len(vulnerabilities.Data.Hits) > 0 {
		fmt.Print("\nVulnerabilities\n\n")
	}
	if p.config.Output == util.JsonOutput {
		var vuln []byte
		for _, cve := range vulnerabilities.Data.Hits {
			vuln, err = json.MarshalIndent(cve, "", "  ")
			if err == nil {
				fmt.Println(string(vuln))
			}
		}
	} else if p.config.Output == util.TableOutput {
		table := tablewriter.NewWriter(os.Stdout)
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
			table.Append([]string{cve.Source.CveID, cve.Source.CveSeverity, packageName, cve.Source.CveDescription})
		}
		table.Render()
	}
	return nil
}
