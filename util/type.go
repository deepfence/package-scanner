package util

type Config struct {
	Mode                  string `json:"-"`
	SocketPath            string `json:"-"`
	Port                  string `json:"-"`
	Output                string `json:"-"`
	Quiet                 bool   `json:"-"`
	ManagementConsoleUrl  string `json:"management_console_url,omitempty"`
	ManagementConsolePort string `json:"-"`
	DeepfenceKey          string `json:"deepfence_key,omitempty"`
	Source                string `json:"source,omitempty"`
	ScanType              string `json:"scan_type,omitempty"`
	VulnerabilityScan     bool   `json:"vulnerability_scan,omitempty"`
	ScanId                string `json:"scan_id,omitempty"`
	NodeType              string `json:"node_type,omitempty"`
	NodeId                string `json:"node_id,omitempty"`
	HostName              string `json:"host_name,omitempty"`
	ImageId               string `json:"image_id,omitempty"`
	ContainerName         string `json:"container_name,omitempty"`
	KubernetesClusterName string `json:"kubernetes_cluster_name,omitempty"`
	RegistryId            string `json:"registry_id,omitempty"`
}

const (
	ModeLocal      = "local"
	ModeGrpcServer = "grpc-server"
	ModeHttpServer = "http-server"
	JsonOutput     = "json"
	NodeTypeHost   = "host"
	NodeTypeImage  = "container_image"
)
