#!/bin/bash

set -x -e

rm -rf grype_0.40.1*tar.gz
rm -rf darwin_* linux_* grype_*

# linux
curl -L -O -s https://github.com/anchore/grype/releases/download/v0.40.1/grype_0.40.1_linux_arm64.tar.gz
mkdir linux_arm64 && tar -zxvf grype_0.40.1_linux_arm64.tar.gz -C linux_arm64 && mv linux_arm64/grype grype_linux_arm64
curl -L -O -s https://github.com/anchore/grype/releases/download/v0.40.1/grype_0.40.1_linux_amd64.tar.gz
mkdir linux_amd64 && tar -zxvf grype_0.40.1_linux_amd64.tar.gz -C linux_amd64 && mv linux_amd64/grype grype_linux_amd64

# macos
curl -L -O -s https://github.com/anchore/grype/releases/download/v0.40.1/grype_0.40.1_darwin_arm64.tar.gz
mkdir darwin_arm64 && tar -zxvf grype_0.40.1_darwin_arm64.tar.gz -C darwin_arm64 && mv darwin_arm64/grype grype_darwin_arm64
curl -L -O -s https://github.com/anchore/grype/releases/download/v0.40.1/grype_0.40.1_darwin_amd64.tar.gz
mkdir darwin_amd64 && tar -zxvf grype_0.40.1_darwin_amd64.tar.gz -C darwin_amd64 && mv darwin_amd64/grype grype_darwin_amd64

rm -rf darwin_* linux_* 