#!/bin/bash

set -eux

VERSION=0.73.1

HOST_OS=$(uname -s | tr '[:upper:]' '[:lower:]')
HOST_ARCH=$(uname -m)

if [ "$HOST_ARCH" = "x86_64" ]; then
    HOST_ARCH="amd64"
elif [ "$HOST_ARCH" = "aarch64" ]; then
    HOST_ARCH="arm64"
fi

ARCHITECTURE="${TARGETPLATFORM:-$HOST_OS/$HOST_ARCH}"

IFS=/ read BUILD_OS BUILD_ARCH <<< $ARCHITECTURE

rm -rf grype_*.tar.gz grype

curl -fsSLO https://github.com/anchore/grype/releases/download/v${VERSION}/grype_${VERSION}_${BUILD_OS}_${BUILD_ARCH}.tar.gz
tar -zxvf grype_${VERSION}_${BUILD_OS}_${BUILD_ARCH}.tar.gz grype
