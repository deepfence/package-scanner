package deepfence

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/deepfence/package-scanner/util"
	"io"
	"io/ioutil"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const (
	MethodGet  = "GET"
	MethodPost = "POST"
)

type Client struct {
	config         util.Config
	httpClient     *http.Client
	mgmtConsoleUrl string
	accessToken    string
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
	c := &Client{config: config, httpClient: httpClient, mgmtConsoleUrl: mgmtConsoleUrl}
	return c, nil
}

func (c *Client) SendScanStatustoConsole(vulnerabilityScanMsg string, status string) error {
	vulnerabilityScanMsg = strings.Replace(vulnerabilityScanMsg, "\n", " ", -1)
	scanLog := fmt.Sprintf("{\"scan_id\":\"%s\",\"time_stamp\":%d,\"cve_scan_message\":\"%s\",\"action\":\"%s\",\"type\":\"cve-scan\",\"node_type\":\"%s\",\"node_id\":\"%s\",\"scan_type\":\"%s\",\"host_name\":\"%s\",\"host\":\"%s\",\"kubernetes_cluster_name\":\"%s\"}", c.config.ScanId, util.GetIntTimestamp(), vulnerabilityScanMsg, status, c.config.NodeType, c.config.NodeId, c.config.ScanType, c.config.HostName, c.config.HostName, c.config.KubernetesClusterName)
	postReader := bytes.NewReader([]byte(scanLog))
	ingestScanStatusAPI := fmt.Sprintf("https://" + c.mgmtConsoleUrl + "/df-api/ingest?doc_type=cve-scan")
	_, err := c.HttpRequest(MethodPost, ingestScanStatusAPI, postReader, nil)
	return err
}

func (c *Client) getApiAccessToken() string {
	if c.accessToken != "" {
		return c.accessToken
	}
	accessToken, err := c.GetApiAccessToken()
	if err != nil {
		return ""
	}
	c.accessToken = accessToken
	return c.accessToken
}

func (c *Client) GetApiAccessToken() (string, error) {
	resp, err := c.HttpRequest(MethodPost,
		"https://"+c.mgmtConsoleUrl+"/deepfence/v1.5/users/auth",
		bytes.NewReader([]byte(`{"api_key":"`+c.config.DeepfenceKey+`"}`)),
		nil)
	if err != nil {
		return "", err
	}
	var dfApiAuthResponse dfApiAuthResponse
	err = json.Unmarshal(resp, &dfApiAuthResponse)
	if err != nil {
		return "", err
	}
	if dfApiAuthResponse.Success == false {
		return "", errors.New(dfApiAuthResponse.Error.Message)
	}
	return dfApiAuthResponse.Data.AccessToken, nil
}

func (c *Client) getVulnerabilityScanStatus() (string, error) {
	resp, err := c.HttpRequest(MethodGet,
		"https://"+c.mgmtConsoleUrl+"/deepfence/v1.5/cve-scan/"+url.PathEscape(c.config.NodeId),
		nil, map[string]string{"Authorization": "Bearer " + c.getApiAccessToken()})
	if err != nil {
		return "", err
	}
	var vulnerabilityScanStatusResponse vulnerabilityScanStatus
	err = json.Unmarshal(resp, &vulnerabilityScanStatusResponse)
	if err != nil {
		return "", err
	}
	if vulnerabilityScanStatusResponse.Success == false {
		return "", errors.New(vulnerabilityScanStatusResponse.Error.Message)
	}
	return vulnerabilityScanStatusResponse.Data.Action, err
}

func (c *Client) WaitForScanToComplete() error {
	retryCount := 0
	for {
		status, err := c.getVulnerabilityScanStatus()
		if err != nil {
			return err
		}
		if status == "COMPLETED" || status == "ERROR" {
			break
		}
		retryCount += 1
		time.Sleep(10 * time.Second)
		if retryCount > 100 {
			return errors.New("retry limit exceeded")
		}
	}
	return nil
}

func (c *Client) GetVulnerabilityScanSummary() (*VulnerabilityScanDetail, error) {
	resp, err := c.HttpRequest(MethodPost,
		"https://"+c.mgmtConsoleUrl+"/deepfence/v1.5/vulnerabilities/image_report?lucene_query=&number=30&time_unit=day",
		bytes.NewReader([]byte(`{"filters":{"cve_container_image":"`+c.config.NodeId+`","scan_id":"`+c.config.ScanId+`"}}`)),
		map[string]string{"Authorization": "Bearer " + c.getApiAccessToken()})
	if err != nil {
		return nil, err
	}
	var vulnerabilityScanSummary VulnerabilityScanSummary
	err = json.Unmarshal(resp, &vulnerabilityScanSummary)
	if err != nil {
		return nil, err
	}
	if vulnerabilityScanSummary.Success == false {
		return nil, errors.New(vulnerabilityScanSummary.Error.Message)
	}
	for _, scanSummary := range vulnerabilityScanSummary.Data.Data {
		for _, scan := range scanSummary.Scans {
			if scan.ScanID == c.config.ScanId {
				return &scan, err
			}
		}
	}
	return nil, errors.New("not found")
}

func (c *Client) GetVulnerabilities() (*Vulnerabilities, error) {
	var vulnerabilities Vulnerabilities
	var err error
	pageSize := 1000
	from := 0
	total := 0
	totalResp := 0
	for {
		var resp []byte
		resp, err = c.HttpRequest(MethodPost,
			fmt.Sprintf("https://%s/deepfence/v1.5/search?from=%d&size=%d&lucene_query=&number=1&time_unit=hour", c.mgmtConsoleUrl, from, pageSize),
			bytes.NewReader([]byte(`{"_type":"cve","_source":[],"filters":{"masked":"false","type":["cve"],"cve_container_image":"`+c.config.NodeId+`","scan_id":"`+c.config.ScanId+`"},"node_filters":{}}`)),
			map[string]string{"Authorization": "Bearer " + c.getApiAccessToken()})
		var vuln Vulnerabilities
		err = json.Unmarshal(resp, &vuln)
		if err != nil || vuln.Success == false || len(vuln.Data.Hits) == 0 {
			break
		}
		if totalResp == 0 {
			totalResp = vuln.Data.Total
		}
		total += vuln.Data.Total
		vulnerabilities.Data.Hits = append(vulnerabilities.Data.Hits, vuln.Data.Hits...)
		if total >= totalResp {
			break
		}
		from += pageSize
	}
	return &vulnerabilities, err
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
	_, err := c.HttpRequest(MethodPost, requestUrl, bytes.NewReader(sbom), nil)
	return err
}

func (c *Client) SendSBOMtoES(sbom []byte) error {
	var sbomDoc = make(map[string]interface{})
	sbomDoc["scan_id"] = c.config.ScanId
	sbomDoc["node_id"] = c.config.NodeId
	sbomDoc["scan_type"] = c.config.ScanType
	sbomDoc["node_type"] = c.config.NodeType
	sbomDoc["masked"] = "false"
	sbomDoc["host_name"] = c.config.HostName
	sbomDoc["image_id"] = c.config.ImageId
	sbomDoc["container_name"] = c.config.ContainerName
	sbomDoc["kubernetes_cluster_name"] = c.config.KubernetesClusterName
	sbomDoc["@timestamp"] = time.Now().UTC().Format("2006-01-02T15:04:05.000") + "Z"
	sbomDoc["time_stamp"] = time.Now().UTC().UnixNano() / 1000000
	var resultSBOM map[string]interface{}
	err := json.Unmarshal(sbom, &resultSBOM)
	if err != nil {
		return err
	}
	sbomDoc["artifacts"] = resultSBOM["artifacts"].([]interface{})
	if c.config.NodeType == "host" {
		sbomDoc["source_host"] = resultSBOM["source"].(interface{})
	} else {
		sbomDoc["source"] = resultSBOM["source"].(interface{})
	}
	sbomDoc["distro"] = resultSBOM["distro"].(interface{})
	docBytes, err := json.Marshal(sbomDoc)
	if err != nil {
		return err
	}
	postReader := bytes.NewReader(docBytes)
	ingestScanStatusAPI := fmt.Sprintf("https://" + c.config.ManagementConsoleUrl + ":" + c.config.ManagementConsolePort + "/df-api/ingest?doc_type=sbom-cve-scan")
	_, err = c.HttpRequest("POST", ingestScanStatusAPI, postReader, nil)
	if err != nil {
		return err
	}
	return nil
}

func (c *Client) HttpRequest(method string, requestUrl string, postReader io.Reader, header map[string]string) ([]byte, error) {
	retryCount := 0
	var response []byte
	for {
		httpReq, err := http.NewRequest(method, requestUrl, postReader)
		if err != nil {
			return response, err
		}
		httpReq.Close = true
		httpReq.Header.Add("deepfence-key", c.config.DeepfenceKey)
		httpReq.Header.Set("Content-Type", "application/json")
		if header != nil {
			for k, v := range header {
				httpReq.Header.Add(k, v)
			}
		}
		resp, err := c.httpClient.Do(httpReq)
		if err != nil {
			return response, err
		}
		if resp.StatusCode == 200 {
			response, err = ioutil.ReadAll(resp.Body)
			if err != nil {
				return response, err
			}
			resp.Body.Close()
			break
		} else {
			if retryCount > 4 {
				errMsg := fmt.Sprintf("Unable to complete request. Got %d ", resp.StatusCode)
				resp.Body.Close()
				return response, errors.New(errMsg)
			}
			resp.Body.Close()
			retryCount += 1
			time.Sleep(5 * time.Second)
		}
	}
	return response, nil
}
