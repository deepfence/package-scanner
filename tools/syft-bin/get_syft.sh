#!/bin/bash

set -x -e

git clone https://github.com/deepfence/syft.git --branch optimise-resolver-2 || true
cd syft/cmd/syft
export CGO_ENABLED=0
GOOS=linux GOARCH=amd64 go build -o syft_linux_amd64 .
GOOS=linux GOARCH=arm64 go build -o syft_linux_arm64 .
GOOS=darwin GOARCH=amd64 go build -o syft_darwin_amd64 .
GOOS=darwin GOARCH=arm64 go build -o syft_darwin_arm64 .
cp syft_* ../../../
