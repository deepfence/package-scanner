package tools

import (
	_ "embed"
)

var (
	//go:embed syft-bin/syft_linux_arm64
	SyftBin []byte

	//go:embed grype-bin/grype_linux_arm64
	GrypeBin []byte
)
