FROM golang:1.20-bullseye AS build
RUN apt-get clean && apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
    build-essential git gcc libc-dev libffi-dev bash make apt-utils

ADD . /go/package-scanner/
WORKDIR /go/package-scanner/
RUN CGO_ENABLED=0 make package-scanner

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
    && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends curl bash util-linux ca-certificates podman cron \
    && nerdctl_version=1.4.0 \
    && curl -fsSLOk https://github.com/containerd/nerdctl/releases/download/v${nerdctl_version}/nerdctl-${nerdctl_version}-linux-amd64.tar.gz \
    && tar Cxzvvf /usr/local/bin nerdctl-${nerdctl_version}-linux-amd64.tar.gz \
    && rm nerdctl-${nerdctl_version}-linux-amd64.tar.gz

#RUN echo "0 */4 * * * /usr/local/bin/grype db update" >> /etc/crontabs/root \
RUN crontab -l | { cat; echo "0 */4 * * * /usr/local/bin/grype db update"; } | crontab - \
    && chmod +x /entrypoint.sh

EXPOSE 8001 8002 8005
ENTRYPOINT ["/entrypoint.sh"]
CMD ["/usr/local/bin/package-scanner", "--mode", "grpc-server", "--port", "8002"]
