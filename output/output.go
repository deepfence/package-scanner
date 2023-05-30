package output

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/base64"
	"fmt"
	"math"
	"os"
	"strings"
	"sync"
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

type JobStatus struct {
	Status string
	Msg    string
}

const (
	IN_PROGRESS string = "IN_PROGRESS"
	COMPLETE           = "COMPLETE"
	ABORT              = "ABORT"
	CANCELLED          = "CANCELLED"
	ERROR              = "ERROR"
)

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

	host := map[string]interface{}{
		"node_id":               p.config.HostName,
		"host_name":             p.config.HostName,
		"node_name":             p.config.HostName,
		"node_type":             "host",
		"cloud_region":          "cli",
		"cloud_provider":        "cli",
		"kubernetes_cluster_id": "",
	}
	report.HostBatch = []map[string]interface{}{host}

	if !(strings.HasPrefix(p.config.Source, "dir:") || (p.config.Source == ".")) {
		image := map[string]interface{}{
			"docker_image_name_with_tag": p.config.Source,
			"docker_image_id":            p.config.ImageId,
			"node_id":                    p.config.ImageId,
			"node_name":                  p.config.ImageId,
			"node_type":                  p.config.NodeType,
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
		report.ContainerImageBatch = []map[string]interface{}{image}
		report.ContainerImageEdgeBatch = []map[string]interface{}{containerImageEdge}
	}

	log.Debugf("report: %+v", report)

	req := p.client.Client().TopologyAPI.IngestSyncAgentReport(context.Background())
	req = req.IngestersReportIngestionData(report)

	resp, err := p.client.Client().TopologyAPI.IngestSyncAgentReportExecute(req)
	if err != nil {
		log.Error(err)
	}
	// defer resp.Body.Close()
	// io.Copy(io.Discard, resp.Body)
	log.Debugf("report response %s", resp.Status)
}

func (p *Publisher) StartScan() string {

	scanTrigger := dsc.ModelVulnerabilityScanTriggerReq{
		Filters:    *dsc.NewModelScanFilterWithDefaults(),
		NodeIds:    []dsc.ModelNodeIdentifier{},
		ScanConfig: []dsc.ModelVulnerabilityScanConfigLanguage{},
	}

	nodeIds := dsc.ModelNodeIdentifier{NodeId: p.config.NodeId, NodeType: "image"}
	if strings.HasPrefix(p.config.Source, "dir:") || (p.config.Source == ".") {
		nodeIds.NodeType = "host"
	}

	scanTrigger.NodeIds = append(scanTrigger.NodeIds, nodeIds)

	for _, t := range strings.Split(p.config.ScanType, ",") {
		scanTrigger.ScanConfig = append(scanTrigger.ScanConfig,
			*dsc.NewModelVulnerabilityScanConfigLanguage(t))
	}

	req := p.client.Client().VulnerabilityAPI.StartVulnerabilityScan(context.Background())
	req = req.ModelVulnerabilityScanTriggerReq(scanTrigger)
	res, resp, err := p.client.Client().VulnerabilityAPI.StartVulnerabilityScanExecute(req)
	if err != nil {
		log.Error(err)
		return ""
	}
	// defer resp.Body.Close()
	// io.Copy(io.Discard, resp.Body)

	log.Debugf("start scan response: %+v", res)
	log.Debugf("start scan response status: %s", resp.Status)

	return res.GetScanIds()[0]
}

func (p *Publisher) PublishScanStatusMessage(message string, status string) {
	data := dsc.IngestersVulnerabilityScanStatus{}
	data.SetScanId(p.config.ScanId)
	data.SetTimestamp(time.Now())
	data.SetScanStatus(status)
	data.SetScanMessage(message)

	req := p.client.Client().VulnerabilityAPI.IngestVulnerabilitiesScanStatus(context.Background())
	req = req.IngestersVulnerabilityScanStatus([]dsc.IngestersVulnerabilityScanStatus{data})

	resp, err := p.client.Client().VulnerabilityAPI.IngestVulnerabilitiesScanStatusExecute(req)
	if err != nil {
		log.Error(err)
	}
	// defer resp.Body.Close()
	// io.Copy(io.Discard, resp.Body)

	log.Debugf("publish scan status response: %v", resp)
}

func (p *Publisher) PublishScanError(errMsg string) {
	p.PublishScanStatusMessage(errMsg, "ERROR")
}

func (p *Publisher) PublishScanStatusPeriodic(status string) {
	go func() {
		p.PublishScanStatusMessage("", status)
		ticker := time.NewTicker(30 * time.Second)
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
	time.Sleep(5 * time.Second)
}

func (p *Publisher) RunVulnerabilityScan(sbom []byte) {
	p.PublishScanStatusMessage("", "IN_PROGRESS")
	defer p.StopPublishScanStatus()

	time.Sleep(3 * time.Second)

	err := p.SendSbomToConsole(sbom)
	if err != nil {
		p.PublishScanError(err.Error())
		log.Error(p.config.ScanId, " ", err.Error())
	}
}

func (p *Publisher) SendSbomToConsole(sbom []byte) error {
	data := dsc.UtilsScanSbomRequest{}
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

	// compress sbom and encode to base64
	var out bytes.Buffer
	gzw := gzip.NewWriter(&out)
	if _, err := gzw.Write(sbom); err != nil {
		log.Errorf("compress error: %s", err)
		return err
	}
	gzw.Close()

	log.Infof("sbom size: %.4fmb compressed: %.4fmb",
		float64(len(sbom))/1000.0/1000.0, float64(out.Len())/1000.0/1000.0)

	bb := out.Bytes()
	c_sbom := make([]byte, base64.StdEncoding.EncodedLen(len(bb)))
	base64.StdEncoding.Encode(c_sbom, bb)

	data.SetSbom(string(c_sbom))

	req := p.client.Client().VulnerabilityAPI.IngestSbom(context.Background())
	req = req.UtilsScanSbomRequest(data)

	resp, err := p.client.Client().VulnerabilityAPI.IngestSbomExecute(req)
	if err != nil {
		log.Error(err)
		return err
	}
	// defer resp.Body.Close()
	// io.Copy(io.Discard, resp.Body)

	log.Infof("publish sbom to console response: %v", resp)

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

func CountBySeverity(report *[]scanner.VulnerabilityScanReport) *VulnerabilityScanDetail {
	detail := VulnerabilityScanDetail{}

	cveScore := 0.0

	for _, r := range *report {
		detail.Total += 1
		cveScore += r.CveOverallScore
		switch r.CveSeverity {
		case utils.CRITICAL:
			detail.Severity.Critical += 1
		case utils.HIGH:
			detail.Severity.High += 1
		case utils.MEDIUM:
			detail.Severity.Medium += 1
		case utils.LOW:
			detail.Severity.Low += 1
		}
	}

	detail.CveScore = math.Min((cveScore*10.0)/500.0, 10.0)

	detail.TimeStamp = time.Now()

	return &detail
}

func (p *Publisher) StartStatusReporter(statusChan chan JobStatus,
	wg *sync.WaitGroup) {
	scanID := p.config.ScanId

	go func() {
		log.Info("StartStatusReporter started, scanid:", scanID)
		defer wg.Done()

		ticker := time.NewTicker(30 * time.Second)
		var err error
		var msg string
		var statusIn JobStatus
		abort := false
		start := time.Now()
		threshold := 5 * 60 * 60 //5 hours
	loop:
		for {
			select {
			case statusIn = <-statusChan:
				status := statusIn.Status
				if status == IN_PROGRESS {
					p.PublishScanStatusMessage(statusIn.Msg, "IN_PROGRESS")
				} else if status == COMPLETE {
					break loop
				} else if status == ABORT {
					abort = true
					msg = statusIn.Msg
					break loop
				} else if status == ERROR {
					err = fmt.Errorf(statusIn.Msg)
					msg = statusIn.Msg
					break loop
				}
			case <-ticker.C:
				ts := int(time.Since(start).Seconds())
				if ts > threshold {
					err = fmt.Errorf("Scan job aborted due to inactivity")
					p.PublishScanStatusMessage(err.Error(), ERROR)
					//We will restart the program after this.
					log.Info("Aborting scan job, total time taken is more than threshold, scanid:", scanID)
					os.Exit(0)
				} else {
					p.PublishScanStatusMessage("", "IN_PROGRESS")
				}
			}
		}

		if abort == true {
			p.PublishScanStatusMessage(msg, CANCELLED)
		} else if err != nil {
			p.PublishScanStatusMessage(err.Error(), ERROR)
		}

		log.Info("StartStatusReporter exited, scanid:", scanID)
	}()
}
