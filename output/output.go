package output

import (
	"github.com/deepfence/package-scanner/internal/deepfence"
	"github.com/deepfence/package-scanner/util"
	"github.com/sirupsen/logrus"
	"time"
)

type Publisher struct {
	config         util.Config
	dfClient       *deepfence.Client
	sbom           *util.Sbom
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

func (p *Publisher) RunVulnerabilityScan(sbom *util.Sbom) {
	p.PublishScanStatusMessage("", "GENERATED_SBOM")
	time.Sleep(3 * time.Second)
	err := p.dfClient.SendSBOMtoConsole(sbom)
	if err != nil {
		p.PublishScanError(err.Error())
		logrus.Error(p.config.ScanId, " ", err.Error())
	}
}

func (p *Publisher) Output() {
	if p.config.Output == util.JsonOutput {
		// TODO: Get scan results from management console
	}
}
