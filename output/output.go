package output

import (
	"context"
	"io"
	"os"
	"strings"
	"time"

	dsc "github.com/deepfence/golang_deepfence_sdk/client"
	oahttp "github.com/deepfence/golang_deepfence_sdk/utils/http"
	"github.com/deepfence/package-scanner/scanner"
	"github.com/deepfence/package-scanner/utils"
	tw "github.com/olekukonko/tablewriter"
	log "github.com/sirupsen/logrus"
)

type Publisher struct {
	config         utils.Config
	client         *oahttp.OpenapiHttpClient
	stopScanStatus chan bool
}

func NewPublisher(config utils.Config) (*Publisher, error) {
	client := oahttp.NewHttpsConsoleClient(config.ConsoleURL, config.ConsolePort)
	if err := client.APITokenAuthenticate(config.DeepfenceKey); err != nil {
		return nil, err
	}
	return &Publisher{
		config:         config,
		client:         client,
		stopScanStatus: make(chan bool, 1),
	}, nil
}

func (p *Publisher) SetScanId(scanId string) {
	p.config.ScanId = scanId
}

func (p *Publisher) SendReport() {

	report := dsc.IngestersReportIngestionData{}

	host := map[string]string{
		"node_id":        p.config.HostName,
		"hostname":       p.config.HostName,
		"cloud_region":   "cli",
		"cloud_provider": "cli",
	}
	report.HostBatch = []map[string]string{host}

	if !(strings.HasPrefix(p.config.Source, "dir:") || (p.config.Source == ".")) {
		image := map[string]string{
			"image_name": p.config.Source,
			"image_id":   p.config.ImageId,
			"node_id":    p.config.ImageId,
		}
		s := strings.Split(p.config.Source, ":")
		if len(s) == 2 {
			image["docker_image_name"] = s[0]
			image["docker_image_tag"] = s[1]
		}
		containerImageEdge := map[string]interface{}{
			"source":       p.config.HostName,
			"destinations": p.config.ImageId,
		}
		report.ContainerImageBatch = []map[string]string{image}
		report.ContainerImageEdgeBatch = []map[string]interface{}{containerImageEdge}
	}

	log.Debugf("report: %+v", report)

	req := p.client.Client().TopologyApi.IngestSyncAgentReport(context.Background())
	req = req.IngestersReportIngestionData(report)

	resp, err := p.client.Client().TopologyApi.IngestSyncAgentReportExecute(req)
	if err != nil {
		log.Error(err)
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, resp.Body)
	log.Debugf("report response %s", resp.Status)
}

func (p *Publisher) StartScan() string {

	trigger := dsc.ModelVulnerabilityScanTriggerReq{
		NodeId:     p.config.NodeId,
		NodeType:   "image",
		ScanConfig: p.config.ScanType,
	}

	if strings.HasPrefix(p.config.Source, "dir:") || (p.config.Source == ".") {
		trigger.NodeType = "host"
	}

	req := p.client.Client().VulnerabilityApi.StartVulnerabilityScan(context.Background())
	req = req.ModelVulnerabilityScanTriggerReq(trigger)
	res, resp, err := p.client.Client().VulnerabilityApi.StartVulnerabilityScanExecute(req)
	if err != nil {
		log.Error(err)
		return ""
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, resp.Body)

	log.Debugf("start scan response: %+v", res)

	return res.GetScanId()
}

func (p *Publisher) PublishScanStatusMessage(message string, status string) {
	data := dsc.IngestersVulnerabilityScanStatus{}
	data.SetContainerName(p.config.ContainerName)
	data.SetScanId(p.config.ScanId)
	data.SetHostName(p.config.HostName)
	data.SetKubernetesClusterName(p.config.KubernetesClusterName)
	data.SetMasked("false")
	data.SetNodeId(p.config.NodeId)
	data.SetNodeType(p.config.NodeType)
	data.SetTimestamp(time.Now())
	data.SetScanStatus(status)
	data.SetNodeName(p.config.NodeId)

	req := p.client.Client().VulnerabilityApi.IngestVulnerabilitiesScanStatus(context.Background())
	req = req.IngestersVulnerabilityScanStatus([]dsc.IngestersVulnerabilityScanStatus{data})

	resp, err := p.client.Client().VulnerabilityApi.IngestVulnerabilitiesScanStatusExecute(req)
	if err != nil {
		log.Error(err)
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, resp.Body)

	log.Debugf("publish scan status response: %s", resp.Status)
}

func (p *Publisher) PublishScanError(errMsg string) {
	p.stopScanStatus <- true
	time.Sleep(3 * time.Second)
	p.PublishScanStatusMessage(errMsg, "ERROR")
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

	err := p.SendSbomToConsole(sbom)
	if err != nil {
		p.PublishScanError(err.Error())
		log.Error(p.config.ScanId, " ", err.Error())
	}
}

func (p *Publisher) SendSbomToConsole(sbom []byte) error {
	data := dsc.UtilsSbomRequest{}
	data.SetImageName(p.config.NodeId)
	data.SetImageId(p.config.ImageId)
	data.SetScanId(p.config.ScanId)
	data.SetKubernetesClusterName(p.config.KubernetesClusterName)
	data.SetHostName(p.config.HostName)
	data.SetNodeId(p.config.NodeId)
	data.SetNodeType(p.config.NodeType)
	data.SetScanType(p.config.ScanType)
	data.SetContainerName(p.config.ContainerName)
	data.SetMode(p.config.Mode)
	data.SetSbom(string(sbom))

	req := p.client.Client().VulnerabilityApi.IngestSbom(context.Background())
	req = req.UtilsSbomRequest(data)

	resp, err := p.client.Client().VulnerabilityApi.IngestSbomExecute(req)
	if err != nil {
		log.Error(err)
		return err
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, resp.Body)

	log.Debugf("publish sbom to console response: %s", resp.Status)

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
