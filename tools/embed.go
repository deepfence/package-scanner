package tools

import (
	_ "embed"
)

var (
	//go:embed syft-bin/syft.bin
	SyftBin []byte

	//go:embed grype-bin/grype
	GrypeBin []byte
)
