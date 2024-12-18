package scanner

type VulnerabilityScanReport struct {
	Masked                  bool     `json:"masked"`
	ScanID                  string   `json:"scan_id"`
	CveID                   string   `json:"cve_id"`
	CveType                 string   `json:"cve_type"`
	CveSeverity             string   `json:"cve_severity"`
	CveCausedByPackage      string   `json:"cve_caused_by_package"`
	CveCausedByPackagePath  string   `json:"cve_caused_by_package_path"`
	CveContainerLayer       string   `json:"cve_container_layer"`
	CveFixedIn              string   `json:"cve_fixed_in"`
	CveLink                 string   `json:"cve_link"`
	Namespace               string   `json:"namespace"`
	CveDescription          string   `json:"cve_description"`
	CveCvssScore            float64  `json:"cve_cvss_score"`
	CveOverallScore         float64  `json:"cve_overall_score"`
	CveAttackVector         string   `json:"cve_attack_vector"`
	URLs                    []string `json:"urls"`
	ExploitPOC              string   `json:"exploit_poc"`
	ParsedAttackVector      string   `json:"parsed_attack_vector"`
	ExploitabilityScore     int      `json:"exploitability_score"`
	InitExploitabilityScore int      `json:"init_exploitability_score"`
	HasLiveConnection       bool     `json:"has_live_connection"`
	CISAKEV                 bool     `json:"cisa_kev"`
	EPSSScore               float64  `json:"epss_score"`
}
