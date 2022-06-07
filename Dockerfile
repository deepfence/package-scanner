FROM golang:1.18-alpine3.15 AS build
RUN apk add --no-cache git \
    && apk add gcc libc-dev libffi-dev bash make protoc
ADD . /go/package-scanner/
WORKDIR /go/package-scanner/
RUN go install google.golang.org/protobuf/cmd/protoc-gen-go@v1.27.1 \
    && go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@v1.2.0 \
    && make \
    && cd /go \
    && git clone --depth 1 -b v0.46.3 https://github.com/deepfence/syft \
    && cd /go/syft/cmd/syft \
    && go build -v -o syftCli .

FROM alpine:3.15
MAINTAINER Deepfence Inc
LABEL deepfence.role=system

ENV PACKAGE_SCAN_CONCURRENCY=5

COPY --from=build /go/package-scanner/package-scanner /usr/local/bin/package-scanner
COPY --from=build /go/syft/cmd/syft/syftCli /usr/local/bin/syft
RUN apk add --no-cache --update bash gcompat findmnt
EXPOSE 8002 8005
ENTRYPOINT ["/usr/local/bin/package-scanner", "--mode", "grpc-server", "--port", "8002"]
