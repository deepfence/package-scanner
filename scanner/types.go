package scanner

type VulnerabilityScanReport struct {
	Type                   string   `json:"type"`
	Masked                 bool     `json:"masked"`
	ScanId                 string   `json:"scan_id"`
	CveId                  string   `json:"cve_id"`
	CveType                string   `json:"cve_type"`
	CveContainerImage      string   `json:"cve_container_image"`
	CveContainerImageId    string   `json:"cve_container_image_id"`
	CveContainerName       string   `json:"cve_container_name"`
	CveSeverity            string   `json:"cve_severity"`
	CveCausedByPackage     string   `json:"cve_caused_by_package"`
	CveCausedByPackagePath string   `json:"cve_caused_by_package_path"`
	CveContainerLayer      string   `json:"cve_container_layer"`
	CveFixedIn             string   `json:"cve_fixed_in"`
	CveLink                string   `json:"cve_link"`
	CveDescription         string   `json:"cve_description"`
	CveCvssScore           float64  `json:"cve_cvss_score"`
	CveOverallScore        float64  `json:"cve_overall_score"`
	CveAttackVector        string   `json:"cve_attack_vector"`
	URLs                   []string `json:"urls"`
	ExploitPOC             string   `json:"exploit_poc"`
}
