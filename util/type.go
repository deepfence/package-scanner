package util

import (
	grypePkg "github.com/anchore/grype/grype/pkg"
)

type Sbom struct {
	Packages []grypePkg.Package
	Context  grypePkg.Context
}

type Config struct {
	Mode                  string
	SocketPath            string
	Output                string
	Quiet                 bool
	ManagementConsoleUrl  string
	ManagementConsolePort string
	DeepfenceKey          string
	Source                string
	ScanType              string
	VulnerabilityScan     bool
	ScanId                string
	NodeType              string
	NodeId                string
	HostName              string
	ImageId               string
	ContainerName         string
	KubernetesClusterName string
	RegistryId            string
}

const (
	ModeLocal      = "local"
	ModeGrpcServer = "grpc-server"
	JsonOutput     = "json"
	NodeTypeHost   = "host"
	NodeTypeImage  = "container_image"
)
