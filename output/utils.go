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
		Unknown  int `json:"unknown,omitempty"`
	} `json:"severity,omitempty"`
	TimeStamp time.Time `json:"time_stamp,omitempty"`
	Total     int       `json:"total,omitempty"`
}
