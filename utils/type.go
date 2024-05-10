package utils

import "github.com/deepfence/vessel"

type Config struct {
	Mode                  string         `json:"mode,omitempty"`
	SocketPath            string         `json:"socket_path,omitempty"`
	Port                  string         `json:"port,omitempty"`
	Output                string         `json:"output,omitempty"`
	Quiet                 bool           `json:"quiet,omitempty"`
	ConsoleURL            string         `json:"console_url,omitempty"`
	ConsolePort           string         `json:"console_port,omitempty"`
	DeepfenceKey          string         `json:"deepfence_key,omitempty"`
	Source                string         `json:"source,omitempty"`
	ScanType              string         `json:"scan_type,omitempty"`
	VulnerabilityScan     bool           `json:"vulnerability_scan,omitempty"`
	ScanID                string         `json:"scan_id,omitempty"`
	NodeType              string         `json:"node_type,omitempty"`
	NodeID                string         `json:"node_id,omitempty"`
	HostName              string         `json:"host_name,omitempty"`
	ImageID               string         `json:"image_id,omitempty"`
	ContainerName         string         `json:"container_name,omitempty"`
	KubernetesClusterName string         `json:"kubernetes_cluster_name,omitempty"`
	RegistryID            string         `json:"registry_id,omitempty"`
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
	SyftBinPath           string         `json:"syft_bin_path,omitempty"`
	GrypeBinPath          string         `json:"grype_bin_path,omitempty"`
	GrypeConfigPath       string         `json:"grype_config_path,omitempty"`
	KeepSbom              bool           `json:"keep_sbom,omitempty"`
	RegistryCreds         RegistryCreds  `json:"registry_creds,omitempty"`
	IsRegistry            bool           `json:"is_registry,omitempty"`
}

type RegistryCreds struct {
	AuthFilePath  string
	SkipTLSVerify bool
	UseHTTP       bool
}

const (
	ModeLocal         = "local"
	ModeGRPCServer    = "grpc-server"
	ModeHTTPServer    = "http-server"
	ModeScannerOnly   = "scanner-only"
	JSONOutput        = "json"
	TableOutput       = "table"
	NodeTypeHost      = "host"
	NodeTypeImage     = "container_image"
	NodeTypeContainer = "container"
)

const (
	ScanTypeBase         = "base"
	ScanTypeRuby         = "ruby"
	ScanTypePython       = "python"
	ScanTypeJavaScript   = "javascript"
	ScanTypePhp          = "php"
	ScanTypeGolang       = "golang"
	ScanTypeGolangBinary = "golang-binary"
	ScanTypeJava         = "java"
	ScanTypeRust         = "rust"
	ScanTypeRustBinary   = "rust-binary"
	ScanTypeDotnet       = "dotnet"
	ScanTypeDotnetBinary = "dotnet-binary"
	ScanAll              = "all"
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
