FROM golang:1.19-bullseye AS build
RUN apt-get update \
    && apt-get install -y --no-install-recommends git gcc libc-dev libffi-dev bash make protobuf-compiler
ADD . /go/package-scanner/
WORKDIR /go/package-scanner/
RUN go install google.golang.org/protobuf/cmd/protoc-gen-go@v1.28.1 \
    && go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@v1.2.0 \
    && make \
    && cd /go \
    && git clone https://github.com/deepfence/syft.git \
    && cd syft \
    && git checkout optimise-resolver-1 \
    && cd /go/syft/cmd/syft \
    && go build -v -o syftCli .

FROM debian:bullseye-slim
MAINTAINER Deepfence Inc
LABEL deepfence.role=system

ENV PACKAGE_SCAN_CONCURRENCY=5

COPY --from=build /go/package-scanner/package-scanner /usr/local/bin/package-scanner
COPY --from=build /go/syft/cmd/syft/syftCli /usr/local/bin/syft
RUN apt-get update \
    && apt-get install -y --no-install-recommends curl bash util-linux ca-certificates podman \
    && curl -fsSLOk https://github.com/containerd/nerdctl/releases/download/v1.1.0/nerdctl-1.1.0-linux-amd64.tar.gz \
    && tar Cxzvvf /usr/local/bin nerdctl-1.1.0-linux-amd64.tar.gz \
    && rm nerdctl-1.1.0-linux-amd64.tar.gz
EXPOSE 8002 8005
ENTRYPOINT ["/usr/local/bin/package-scanner", "--mode", "grpc-server", "--port", "8002"]
