#!/bin/bash

set -eux

# RELEASE=optimise-resolver-2
RELEASE=v1.3.0

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

rm -rf syft*

# git clone https://github.com/deepfence/syft.git --branch $RELEASE || true
git clone https://github.com/anchore/syft.git --branch $RELEASE || true
(
    cd syft/cmd/syft
    export CGO_ENABLED=0
    GOOS="$BUILD_OS" GOARCH="$BUILD_ARCH" go build -o syft.bin -ldflags="-s -w -extldflags=-static" .
    cp syft.bin ../../../ && chmod +x syft.bin
)
