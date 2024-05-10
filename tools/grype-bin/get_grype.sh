#!/bin/bash

set -eux

VERSION=v0.77.2

HOST_OS=$(uname -s | tr '[:upper:]' '[:lower:]')
HOST_ARCH="${GOARCH:=$(uname -m)}"

if [ "$HOST_ARCH" = "x86_64" ]; then
    HOST_ARCH="amd64"
elif [ "$HOST_ARCH" = "aarch64" ]; then
    HOST_ARCH="arm64"
elif [ "$HOST_ARCH" = "arm" ]; then
    HOST_ARCH="arm"
fi

ARCHITECTURE="${TARGETPLATFORM:-$HOST_OS/$HOST_ARCH}"

IFS=/ read BUILD_OS BUILD_ARCH <<< $ARCHITECTURE

rm -rf grype*

git clone https://github.com/anchore/grype.git --branch $VERSION || true
(
    cd grype/cmd/grype
    export CGO_ENABLED=0
    GOOS="$BUILD_OS" GOARCH="$BUILD_ARCH" go build -o grype.bin -ldflags="-s -w -extldflags=-static" .
    cp grype.bin ../../../ && chmod +x grype.bin
)
