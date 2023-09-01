FROM golang:1.20-bullseye AS build
RUN apt-get clean && apt-get update
RUN DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
    build-essential git gcc libc-dev libffi-dev bash make apt-utils
WORKDIR /go/package-scanner/
COPY . .
RUN make tools
RUN CGO_ENABLED=0 make package-scanner

FROM debian:bullseye-slim
LABEL MAINTAINER="Deepfence Inc"
LABEL deepfence.role=system

ENV PACKAGE_SCAN_CONCURRENCY=5
ENV DOCKER_VERSION=24.0.2
ENV NERDCTL_VERSION=1.4.0
ENV GRYPE_DB_UPDATE_URL="https://threat-intel.deepfence.io/vulnerability-db/listing.json"

COPY --from=build /go/package-scanner/package-scanner /usr/local/bin/package-scanner
COPY --from=build /go/package-scanner/tools/grype-bin/grype_linux_amd64 /usr/local/bin/grype
COPY --from=build /go/package-scanner/tools/syft-bin/syft_linux_amd64 /usr/local/bin/syft

COPY grype.yaml /root/.grype.yaml
COPY entrypoint.sh /entrypoint.sh

RUN apt-get update

RUN DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends curl bash util-linux ca-certificates podman cron

RUN curl -fsSLO https://download.docker.com/linux/static/stable/x86_64/docker-${DOCKER_VERSION}.tgz \
    && tar xzvf docker-${DOCKER_VERSION}.tgz --strip 1 -C /usr/local/bin docker/docker \
    && rm docker-${DOCKER_VERSION}.tgz

RUN curl -fsSLOk https://github.com/containerd/nerdctl/releases/download/v${NERDCTL_VERSION}/nerdctl-${NERDCTL_VERSION}-linux-amd64.tar.gz \
    && tar Cxzvvf /usr/local/bin nerdctl-${NERDCTL_VERSION}-linux-amd64.tar.gz \
    && rm nerdctl-${NERDCTL_VERSION}-linux-amd64.tar.gz

#RUN echo "0 */4 * * * /usr/local/bin/grype db update" >> /etc/crontabs/root \
RUN crontab -l | { cat; echo "0 */4 * * * /usr/local/bin/grype db update"; } | crontab - \
    && chmod +x /entrypoint.sh
RUN grype db update

EXPOSE 8001 8002 8005
ENTRYPOINT ["/entrypoint.sh"]
