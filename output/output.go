package output

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/base64"
	"math"
	"os"
	"strings"
	"time"

	dsc "github.com/deepfence/golang_deepfence_sdk/client"
	oahttp "github.com/deepfence/golang_deepfence_sdk/utils/http"
	"github.com/deepfence/package-scanner/scanner"
	"github.com/deepfence/package-scanner/utils"
	tw "github.com/olekukonko/tablewriter"
	"github.com/rs/zerolog/log"
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
	StatusInProgress = "IN_PROGRESS"
	StatusComplete   = "COMPLETE"
	StatusAbort      = "ABORT"
	StatisCancelled  = "CANCELLED"
	StatusError      = "ERROR"
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

func (p *Publisher) SetScanID(scanID string) {
	p.config.ScanID = scanID
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
			"docker_image_id":            p.config.ImageID,
			"node_id":                    p.config.ImageID,
			"node_name":                  p.config.ImageID,
			"node_type":                  p.config.NodeType,
		}
		s := strings.Split(p.config.Source, ":")
		if len(s) == 2 {
			image["docker_image_name"] = s[0]
			image["docker_image_tag"] = s[1]
		}
		containerImageEdge := map[string]interface{}{
			"source":       p.config.HostName,
			"destinations": p.config.ImageID,
		}
		report.ContainerImageBatch = []map[string]interface{}{image}
		report.ContainerImageEdgeBatch = []map[string]interface{}{containerImageEdge}
	}

	log.Debug().Interface("report", report).Msg("sending report")

	req := p.client.Client().TopologyAPI.IngestSyncAgentReport(context.Background())
	req = req.IngestersReportIngestionData(report)

	resp, err := p.client.Client().TopologyAPI.IngestSyncAgentReportExecute(req)
	if err != nil {
		log.Error().Err(err).Msg("failed to send report")
	}
	log.Debug().Str("status", resp.Status).Msg("report response")
}

func (p *Publisher) StartScan() string {

	scanTrigger := dsc.ModelVulnerabilityScanTriggerReq{
		Filters:    *dsc.NewModelScanFilterWithDefaults(),
		NodeIds:    []dsc.ModelNodeIdentifier{},
		ScanConfig: []dsc.ModelVulnerabilityScanConfigLanguage{},
	}

	nodeIds := dsc.ModelNodeIdentifier{NodeId: p.config.NodeID, NodeType: "image"}
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
		log.Error().Err(err).Msg("failed to start scan")
		return ""
	}

	log.Debug().Interface("response", res).Msg("start scan response")
	log.Debug().Str("status", resp.Status).Msg("start scan response status")

	return res.GetScanIds()[0]
}

func (p *Publisher) PublishScanStatusMessage(message string, status string) {
	data := dsc.IngestersVulnerabilityScanStatus{}
	data.SetScanId(p.config.ScanID)
	data.SetScanStatus(status)
	data.SetScanMessage(message)

	req := p.client.Client().VulnerabilityAPI.IngestVulnerabilitiesScanStatus(context.Background())
	req = req.IngestersVulnerabilityScanStatus([]dsc.IngestersVulnerabilityScanStatus{data})

	resp, err := p.client.Client().VulnerabilityAPI.IngestVulnerabilitiesScanStatusExecute(req)
	if err != nil {
		log.Error().Err(err).Msg("failed to publish scan status")
	}

	log.Debug().Interface("response", resp).Msg("publish scan status response")
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

	// skip sbom scan on console
	err := p.SendSbomToConsole(sbom, true)
	if err != nil {
		p.PublishScanError(err.Error())
		log.Error().Str("scan_id", p.config.ScanID).Err(err).Msg("failed to send SBOM to console")
	}
}

func (p *Publisher) SendSbomToConsole(sbom []byte, skipScan bool) error {
	data := dsc.UtilsScanSbomRequest{}
	data.SetImageName(p.config.NodeID)
	data.SetImageId(p.config.ImageID)
	data.SetScanId(p.config.ScanID)
	data.SetKubernetesClusterName(p.config.KubernetesClusterName)
	data.SetHostName(p.config.HostName)
	data.SetNodeId(p.config.NodeID)
	data.SetNodeType(p.config.NodeType)
	data.SetScanType(p.config.ScanType)
	data.SetContainerName(p.config.ContainerName)
	data.SetMode(p.config.Mode)
	data.SetSkipScan(skipScan)

	// compress sbom and encode to base64
	var out bytes.Buffer
	gzw := gzip.NewWriter(&out)
	if _, err := gzw.Write(sbom); err != nil {
		log.Error().Err(err).Msg("compress error")
		return err
	}
	gzw.Close()

	log.Info().Float64("sbom_mb", float64(len(sbom))/1000.0/1000.0).
		Float64("compressed_mb", float64(out.Len())/1000.0/1000.0).Msg("sbom size")

	bb := out.Bytes()
	cSBOM := make([]byte, base64.StdEncoding.EncodedLen(len(bb)))
	base64.StdEncoding.Encode(cSBOM, bb)

	data.SetSbom(string(cSBOM))

	req := p.client.Client().VulnerabilityAPI.IngestSbom(context.Background())
	req = req.UtilsScanSbomRequest(data)

	resp, err := p.client.Client().VulnerabilityAPI.IngestSbomExecute(req)
	if err != nil {
		log.Error().Err(err).Msg("failed to send SBOM")
		return err
	}

	log.Debug().Interface("response", resp).Msg("publish sbom to console response")

	return nil
}

func (p *Publisher) SendScanResultToConsole(vulnerabilities []scanner.VulnerabilityScanReport) error {
	data := []dsc.IngestersVulnerability{}

	for _, v := range vulnerabilities {
		n := dsc.NewIngestersVulnerability()
		n.SetScanId(v.ScanID)
		n.SetCveAttackVector(v.CveAttackVector)
		n.SetCveCausedByPackage(v.CveCausedByPackage)
		n.SetCveCausedByPackagePath(v.CveCausedByPackagePath)
		n.SetCveContainerLayer(v.CveContainerLayer)
		n.SetCveCvssScore(float32(v.CveCvssScore))
		n.SetCveDescription(v.CveDescription)
		n.SetCveFixedIn(v.CveFixedIn)
		n.SetCveId(v.CveID)
		n.SetCveLink(v.CveLink)
		n.SetCveOverallScore(float32(v.CveOverallScore))
		n.SetCveSeverity(v.CveSeverity)
		n.SetExploitPoc(v.ExploitPOC)
		n.SetExploitabilityScore(int32(v.ExploitabilityScore))
		n.SetHasLiveConnection(v.HasLiveConnection)
		n.SetInitExploitabilityScore(int32(v.InitExploitabilityScore))
		n.SetParsedAttackVector(v.ParsedAttackVector)
		n.SetUrls(v.URLs)
		n.SetNamespace(v.Namespace)

		data = append(data, *n)
	}

	req := p.client.Client().VulnerabilityAPI.IngestVulnerabilities(context.Background())
	req = req.IngestersVulnerability(data)

	resp, err := p.client.Client().VulnerabilityAPI.IngestVulnerabilitiesExecute(req)
	if err != nil {
		log.Error().Err(err).Msg("failed to send scan results")
		return err
	}

	log.Debug().Interface("response", resp).Msg("publish sbom scan result to console response")

	return nil
}

func TableOutput(report *[]scanner.VulnerabilityScanReport) error {
	table := tw.NewTable(os.Stdout,
		tw.WithHeader([]string{"CVE ID", "SEVERITY", "CVE TYPE", "PACKAGE", "CVE LINK"}),
	)

	for _, r := range *report {
		if r.CveCausedByPackage == "" {
			r.CveCausedByPackage = r.CveCausedByPackagePath
		}
		table.Append([]string{r.CveID, r.CveSeverity, r.CveType, r.CveCausedByPackage, r.CveLink})
	}
	table.Render()
	return nil
}

func ExitOnSeverityScore(score float64, failOnScore float64) {
	log.Debug().Float64("score", score).Float64("failOnScore", failOnScore).Msg("ExitOnSeverityScore")
	if score >= failOnScore {
		log.Fatal().Float64("score", score).Float64("limit", failOnScore).
			Msg("Exit vulnerability scan. Vulnerability score reached/exceeded the limit.")
	}
}

func ExitOnSeverity(severity string, count int, failOnCount int) {
	log.Debug().Str("severity", severity).Int("count", count).Int("failOnCount", failOnCount).Msg("ExitOnSeverity")
	if count >= failOnCount {
		if len(severity) > 0 {
			log.Fatal().Str("severity", severity).Int("count", count).Int("limit", failOnCount).
				Msg("Exit vulnerability scan. Number of vulnerabilities reached/exceeded the limit.")
		}
		log.Fatal().Int("count", count).Int("limit", failOnCount).
			Msg("Exit vulnerability scan. Number of vulnerabilities reached/exceeded the limit.")
	}
}

func FailOn(cfg *utils.Config, details *VulnerabilityScanDetail) {
	if cfg.FailOnCriticalCount > 0 {
		ExitOnSeverity(utils.CRITICAL, details.Severity.Critical, cfg.FailOnCriticalCount)
	}
	if cfg.FailOnHighCount > 0 {
		ExitOnSeverity(utils.HIGH, details.Severity.High, cfg.FailOnHighCount)
	}
	if cfg.FailOnMediumCount > 0 {
		ExitOnSeverity(utils.MEDIUM, details.Severity.Medium, cfg.FailOnMediumCount)
	}
	if cfg.FailOnLowCount > 0 {
		ExitOnSeverity(utils.LOW, details.Severity.Low, cfg.FailOnLowCount)
	}
	if cfg.FailOnCount > 0 {
		ExitOnSeverity("", details.Total, cfg.FailOnCount)
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
		case utils.UNKNOWN:
			detail.Severity.Unknown += 1
		}

	}

	detail.CveScore = math.Min((cveScore*10.0)/500.0, 10.0)

	detail.TimeStamp = time.Now()

	return &detail
}
