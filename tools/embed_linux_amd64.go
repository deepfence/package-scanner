package tools

import (
	_ "embed"
)

var (
	//go:embed syft-bin/syft_linux_amd64
	SyftBin []byte

	//go:embed grype-bin/grype_linux_amd64
	GrypeBin []byte
)
