package deepfence

import (
	"bytes"
	"errors"
	"fmt"
	"github.com/deepfence/package-scanner/util"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

type Client struct {
	config         util.Config
	httpClient     *http.Client
	mgmtConsoleUrl string
}

func NewClient(config util.Config) (*Client, error) {
	httpClient, err := buildHttpClient()
	if err != nil {
		return nil, err
	}
	mgmtConsoleUrl := config.ManagementConsoleUrl + ":" + config.ManagementConsolePort
	if mgmtConsoleUrl == "" {
		return nil, fmt.Errorf("management console url is required")
	}
	return &Client{config: config, httpClient: httpClient, mgmtConsoleUrl: mgmtConsoleUrl}, nil
}

func (c *Client) SendScanStatustoConsole(vulnerabilityScanMsg string, status string) error {
	vulnerabilityScanMsg = strings.Replace(vulnerabilityScanMsg, "\n", " ", -1)
	scanLog := fmt.Sprintf("{\"scan_id\":\"%s\",\"time_stamp\":%d,\"cve_scan_message\":\"%s\",\"action\":\"%s\",\"type\":\"cve-scan\",\"node_type\":\"%s\",\"node_id\":\"%s\",\"scan_type\":\"%s\",\"host_name\":\"%s\",\"host\":\"%s\",\"kubernetes_cluster_name\":\"%s\"}", c.config.ScanId, util.GetIntTimestamp(), vulnerabilityScanMsg, status, c.config.NodeType, c.config.NodeId, c.config.ScanType, c.config.HostName, c.config.HostName, c.config.KubernetesClusterName)
	postReader := bytes.NewReader([]byte(scanLog))
	ingestScanStatusAPI := fmt.Sprintf("https://" + c.mgmtConsoleUrl + "/df-api/ingest?doc_type=cve-scan")
	return c.SendDocumentToConsole(ingestScanStatusAPI, postReader)
}

func (c *Client) SendSBOMtoConsole(sbom []byte) error {
	urlValues := url.Values{}
	urlValues.Set("image_name", c.config.NodeId)
	urlValues.Set("image_id", c.config.ImageId)
	urlValues.Set("scan_id", c.config.ScanId)
	urlValues.Set("kubernetes_cluster_name", c.config.KubernetesClusterName)
	urlValues.Set("host_name", c.config.HostName)
	urlValues.Set("node_id", c.config.NodeId)
	urlValues.Set("node_type", c.config.NodeType)
	urlValues.Set("scan_type", c.config.ScanType)
	urlValues.Set("container_name", c.config.ContainerName)
	requestUrl := fmt.Sprintf("https://"+c.mgmtConsoleUrl+"/vulnerability-mapper-api/vulnerability-scan?%s", urlValues.Encode())
	return c.SendDocumentToConsole(requestUrl, bytes.NewReader(sbom))
}

func (c *Client) SendDocumentToConsole(requestUrl string, postReader io.Reader) error {
	retryCount := 0
	httpClient, err := buildHttpClient()
	if err != nil {
		return err
	}
	for {
		httpReq, err := http.NewRequest("POST", requestUrl, postReader)
		if err != nil {
			return err
		}
		httpReq.Close = true
		httpReq.Header.Add("deepfence-key", c.config.DeepfenceKey)
		resp, err := httpClient.Do(httpReq)
		if err != nil {
			return err
		}
		if resp.StatusCode == 200 {
			resp.Body.Close()
			break
		} else {
			if retryCount > 2 {
				errMsg := fmt.Sprintf("Unable to complete request. Got %d ", resp.StatusCode)
				resp.Body.Close()
				return errors.New(errMsg)
			}
			resp.Body.Close()
			retryCount += 1
			time.Sleep(5 * time.Second)
		}
	}
	return nil
}
