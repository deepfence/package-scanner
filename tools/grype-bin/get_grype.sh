#!/bin/bash

VERSION=0.72.0

set -x -e

rm -rf grype_*.tar.gz darwin_* linux_*

# linux
curl -L -O -s https://github.com/anchore/grype/releases/download/v${VERSION}/grype_${VERSION}_linux_arm64.tar.gz
mkdir linux_arm64 && tar -zxvf grype_${VERSION}_linux_arm64.tar.gz -C linux_arm64 && mv linux_arm64/grype grype_linux_arm64
curl -L -O -s https://github.com/anchore/grype/releases/download/v${VERSION}/grype_${VERSION}_linux_amd64.tar.gz
mkdir linux_amd64 && tar -zxvf grype_${VERSION}_linux_amd64.tar.gz -C linux_amd64 && mv linux_amd64/grype grype_linux_amd64

# macos
curl -L -O -s https://github.com/anchore/grype/releases/download/v${VERSION}/grype_${VERSION}_darwin_arm64.tar.gz
mkdir darwin_arm64 && tar -zxvf grype_${VERSION}_darwin_arm64.tar.gz -C darwin_arm64 && mv darwin_arm64/grype grype_darwin_arm64
curl -L -O -s https://github.com/anchore/grype/releases/download/v${VERSION}/grype_${VERSION}_darwin_amd64.tar.gz
mkdir darwin_amd64 && tar -zxvf grype_${VERSION}_darwin_amd64.tar.gz -C darwin_amd64 && mv darwin_amd64/grype grype_darwin_amd64

rm -rf darwin_* linux_*

