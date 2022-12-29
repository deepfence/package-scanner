FROM golang:1.18-bullseye AS build
RUN apt-get clean && apt-get update \
    && apt-get install -y --no-install-recommends \
    build-essential git gcc libc-dev libffi-dev bash make protobuf-compiler apt-utils

ADD . /go/package-scanner/
WORKDIR /go/package-scanner/
RUN export CGO_ENABLED=0 && \
    go install google.golang.org/protobuf/cmd/protoc-gen-go@v1.27.1 \
    && go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@v1.2.0 \
    && make


FROM debian:bullseye-slim
LABEL MAINTAINER="Deepfence Inc"
LABEL deepfence.role=system

ENV PACKAGE_SCAN_CONCURRENCY=5

COPY --from=build /go/package-scanner/package-scanner /usr/local/bin/package-scanner
COPY --from=build /go/package-scanner/tools/grype-bin/grype_linux_amd64 /usr/local/bin/grype
COPY --from=build /go/package-scanner/tools/syft-bin/syft_linux_amd64 /usr/local/bin/syft

COPY grype.yaml /root/.grype.yaml
COPY entrypoint.sh /entrypoint.sh

RUN apt-get update \
    && apt-get install -y --no-install-recommends curl bash util-linux ca-certificates podman cron \
    && curl -fsSLOk https://github.com/containerd/nerdctl/releases/download/v0.23.0/nerdctl-0.23.0-linux-amd64.tar.gz \
    && tar Cxzvvf /usr/local/bin nerdctl-0.23.0-linux-amd64.tar.gz \
    && rm nerdctl-0.23.0-linux-amd64.tar.gz

#RUN echo "0 */4 * * * /usr/local/bin/grype db update" >> /etc/crontabs/root \
RUN crontab -l | { cat; echo "0 */4 * * * /usr/local/bin/grype db update"; } | crontab - \
    && chmod +x /entrypoint.sh

EXPOSE 8001 8002 8005
ENTRYPOINT ["/entrypoint.sh"]
CMD ["/usr/local/bin/package-scanner", "--mode", "grpc-server", "--port", "8002"]