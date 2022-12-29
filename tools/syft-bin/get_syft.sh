#!/bin/bash

set -x -e

rm -rf syft syft_*
git clone https://github.com/anchore/syft
cd syft &&
git checkout 1d14f22e4538f03a1896b2d4e1d99a65e52b6f30
cd cmd/syft
export CGO_ENABLED=0
GOOS=linux GOARCH=amd64 go build -v -o syft_linux_amd64 .
GOOS=linux GOARCH=arm64 go build -v -o syft_linux_arm64 .
GOOS=darwin GOARCH=amd64 go build -v -o syft_darwin_amd64 .
GOOS=darwin GOARCH=arm64 go build -v -o syft_darwin_arm64 .
mv syft_* ../../../
