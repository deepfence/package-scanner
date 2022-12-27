package utils

import "github.com/deepfence/vessel"

type Config struct {
	Mode                  string         `json:"mode,omitempty"`
	SocketPath            string         `json:"socket_path,omitempty"`
	Port                  string         `json:"port,omitempty"`
	Output                string         `json:"output,omitempty"`
	Quiet                 bool           `json:"quiet,omitempty"`
	ManagementConsoleUrl  string         `json:"management_console_url,omitempty"`
	ManagementConsolePort string         `json:"management_console_port,omitempty"`
	DeepfenceKey          string         `json:"deepfence_key,omitempty"`
	Source                string         `json:"source,omitempty"`
	ScanType              string         `json:"scan_type,omitempty"`
	VulnerabilityScan     bool           `json:"vulnerability_scan,omitempty"`
	ScanId                string         `json:"scan_id,omitempty"`
	NodeType              string         `json:"node_type,omitempty"`
	NodeId                string         `json:"node_id,omitempty"`
	HostName              string         `json:"host_name,omitempty"`
	ImageId               string         `json:"image_id,omitempty"`
	ContainerName         string         `json:"container_name,omitempty"`
	KubernetesClusterName string         `json:"kubernetes_cluster_name,omitempty"`
	RegistryId            string         `json:"registry_id,omitempty"`
	FailOnCount           int            `json:"fail_on_count,omitempty"`
	FailOnCriticalCount   int            `json:"fail_on_critical_count,omitempty"`
	FailOnHighCount       int            `json:"fail_on_high_count,omitempty"`
	FailOnMediumCount     int            `json:"fail_on_medium_count,omitempty"`
	FailOnLowCount        int            `json:"fail_on_low_count,omitempty"`
	FailOnSeverityCount   string         `json:"fail_on_severity_count,omitempty"`
	FailOnScore           float64        `json:"fail_on_score,omitempty"`
	MaskCveIds            string         `json:"mask_cve_ids,omitempty"`
	ContainerRuntimeName  string         `json:"container_runtime_name,omitempty"`
	ContainerRuntime      vessel.Runtime `json:"container_runtime,omitempty"`
	ContainerID           string         `json:"container_id,omitempty"`
}

const (
	ModeLocal         = "local"
	ModeGrpcServer    = "grpc-server"
	ModeHttpServer    = "http-server"
	ModeScannerOnly   = "scanner-only"
	JsonOutput        = "json"
	TableOutput       = "table"
	NodeTypeHost      = "host"
	NodeTypeImage     = "container_image"
	NodeTypeContainer = "container"
)

// severity
const (
	CRITICAL   = "critical"
	HIGH       = "high"
	MEDIUM     = "medium"
	LOW        = "low"
	NEGLIGIBLE = "negligible"
	UNKNOWN    = "unknown"
)

func SeverityToInt(severity string) int {
	switch severity {
	case CRITICAL:
		return 5
	case HIGH:
		return 4
	case MEDIUM:
		return 3
	case LOW:
		return 2
	case NEGLIGIBLE:
		return 1
	case UNKNOWN:
		return 0
	default:
		return -1
	}
}
