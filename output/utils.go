package output

import (
	"time"
)

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
