package output

import (
	"crypto/tls"
	"crypto/x509"
	"io"
	stdlog "log"
	"net"
	"net/http"
	"time"

	rhttp "github.com/hashicorp/go-retryablehttp"
	log "github.com/sirupsen/logrus"
)

func toTimePtr(t time.Time) *time.Time {
	return &t
}

func buildHttpClient() (*http.Client, error) {
	rhc := rhttp.NewClient()
	rhc.RetryMax = 3
	rhc.RetryWaitMin = 1 * time.Second
	rhc.RetryWaitMax = 15 * time.Second
	rhc.Logger = stdlog.New(io.Discard, "", stdlog.LstdFlags)
	// rhc.RequestLogHook = func(_ rhttp.Logger, req *http.Request, attempt int) {
	// 	log.WithFields(log.Fields{
	// 		"host":    req.URL.Host,
	// 		"path":    req.URL.Path,
	// 		"attempt": attempt,
	// 	}).Debug("Sending request")
	// }
	rhc.ResponseLogHook = func(_ rhttp.Logger, resp *http.Response) {
		log.WithFields(log.Fields{
			"url":  resp.Request.URL.String(),
			"code": resp.StatusCode,
		}).Debug(resp.Status)
	}
	// Set up our own certificate pool
	tlsConfig := &tls.Config{RootCAs: x509.NewCertPool(), InsecureSkipVerify: true}
	rhc.HTTPClient = &http.Client{
		Transport: &http.Transport{
			TLSClientConfig:     tlsConfig,
			DisableKeepAlives:   false,
			MaxIdleConnsPerHost: 1024,
			DialContext: (&net.Dialer{
				Timeout:   15 * time.Minute,
				KeepAlive: 15 * time.Minute,
			}).DialContext,
			TLSHandshakeTimeout:   30 * time.Second,
			ResponseHeaderTimeout: 5 * time.Minute,
		},
		Timeout: 15 * time.Minute,
	}
	return rhc.StandardClient(), nil
}

type dfApiAuthResponse struct {
	Success     bool        `json:"success"`
	Message     string      `json:"message"`
	ErrorFields interface{} `json:"error_fields"`
	Data        struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
	} `json:"data"`
}

type vulnerabilityScanStatus struct {
	Data struct {
		Timestamp             time.Time `json:"@timestamp"`
		ID                    string    `json:"_id"`
		Action                string    `json:"action"`
		CveScanMessage        string    `json:"cve_scan_message"`
		Host                  string    `json:"host"`
		HostName              string    `json:"host_name"`
		KubernetesClusterName string    `json:"kubernetes_cluster_name"`
		Masked                string    `json:"masked"`
		NodeID                string    `json:"node_id"`
		NodeType              string    `json:"node_type"`
		ScanID                string    `json:"scan_id"`
		ScanType              string    `json:"scan_type"`
		TimeStamp             int64     `json:"time_stamp"`
		Type                  string    `json:"type"`
	} `json:"data"`
	Error struct {
		Message string `json:"message"`
	} `json:"error"`
	Success bool `json:"success"`
}

type VulnerabilityScanDetail struct {
	Action           string  `json:"action,omitempty"`
	ActiveContainers int     `json:"active_containers,omitempty"`
	CveScanMessage   string  `json:"cve_scan_message,omitempty"`
	CveScore         float64 `json:"cve_score,omitempty"`
	NodeName         string  `json:"node_name,omitempty"`
	NodeType         string  `json:"node_type,omitempty"`
	ScanID           string  `json:"scan_id,omitempty"`
	Severity         struct {
		Critical int `json:"critical,omitempty"`
		High     int `json:"high,omitempty"`
		Medium   int `json:"medium,omitempty"`
		Low      int `json:"low,omitempty"`
	} `json:"severity,omitempty"`
	TimeStamp time.Time `json:"time_stamp,omitempty"`
	Total     int       `json:"total,omitempty"`
}

type VulnerabilityScanSummary struct {
	Data struct {
		Data []struct {
			ErrorCount int                       `json:"error_count"`
			NodeName   string                    `json:"node_name"`
			NodeType   string                    `json:"node_type"`
			Scans      []VulnerabilityScanDetail `json:"scans"`
			TimeStamp  time.Time                 `json:"time_stamp"`
			TotalCount int                       `json:"total_count"`
		} `json:"data"`
		Total int `json:"total"`
	} `json:"data"`
	Error struct {
		Message string `json:"message"`
	} `json:"error"`
	Success bool `json:"success"`
}

type VulnerabilityDetail struct {
	CveAttackVector        string `json:"cve_attack_vector"`
	CveCausedByPackage     string `json:"cve_caused_by_package"`
	CveCausedByPackagePath string `json:"cve_caused_by_package_path"`
	CveContainerImage      string `json:"cve_container_image"`
	CveDescription         string `json:"cve_description"`
	CveFixedIn             string `json:"cve_fixed_in"`
	CveID                  string `json:"cve_id"`
	CveLink                string `json:"cve_link"`
	CveSeverity            string `json:"cve_severity"`
	CveType                string `json:"cve_type"`
	HostName               string `json:"host_name"`
}

type Vulnerabilities struct {
	Data struct {
		Hits []struct {
			Source VulnerabilityDetail `json:"_source"`
		} `json:"hits"`
		Total int `json:"total"`
	} `json:"data"`
	Error struct {
		Message string `json:"message"`
	} `json:"error"`
	Success bool `json:"success"`
}
