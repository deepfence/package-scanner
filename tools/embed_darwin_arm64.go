package tools

import (
	_ "embed"
)

var (
	//go:embed syft-bin/syft_darwin_arm64
	SyftBin []byte

	//go:embed grype-bin/grype_darwin_arm64
	GrypeBin []byte
)
