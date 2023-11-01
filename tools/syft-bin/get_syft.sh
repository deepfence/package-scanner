#!/bin/bash

set -eux

HOST_OS=$(uname -s | tr '[:upper:]' '[:lower:]')
HOST_ARCH=$(uname -p)

if [ "$HOST_ARCH" = "x86_64" ]; then
    HOST_ARCH="amd64"
elif [ "$HOST_ARCH" = "aarch64" ]; then
    HOST_ARCH="arm64"
fi

ARCHITECTURE="${TARGETPLATFORM:-$HOST_OS/$HOST_ARCH}"

IFS=/ read BUILD_OS BUILD_ARCH <<< $ARCHITECTURE

git clone https://github.com/deepfence/syft.git --branch optimise-resolver-2 || true
(
    cd syft/cmd/syft
    export CGO_ENABLED=0
    GOOS="$BUILD_OS" GOARCH="$BUILD_ARCH" go build -o syft.bin .
    cp syft.bin ../../../
)
