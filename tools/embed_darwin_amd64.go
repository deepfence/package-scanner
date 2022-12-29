package tools

import (
	_ "embed"
)

var (
	//go:embed syft-bin/syft_darwin_amd64
	SyftBin []byte

	//go:embed grype-bin/grype_darwin_amd64
	GrypeBin []byte
)
