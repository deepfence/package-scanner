FROM golang:1.23-bookworm AS build

RUN apt-get clean && apt-get update
RUN DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
    build-essential git gcc libc-dev libffi-dev bash make apt-utils
WORKDIR /go/package-scanner/
COPY . .

ARG TARGETPLATFORM
ARG MAKE_CMD=package-scanner
RUN TARGETPLATFORM=$TARGETPLATFORM make tools
RUN CGO_ENABLED=0 make $MAKE_CMD

FROM debian:bookworm-slim
LABEL MAINTAINER="Deepfence Inc"
LABEL deepfence.role=system

ENV PACKAGE_SCAN_CONCURRENCY=5 \
    DOCKER_VERSION=27.3.1 \
    NERDCTL_VERSION=1.7.7

# ENV GRYPE_DB_UPDATE_URL="https://threat-intel.deepfence.io/vulnerability-db/listing.json"

COPY --from=build /go/package-scanner/package-scanner /usr/local/bin/package-scanner
COPY --from=build /go/package-scanner/tools/grype-bin/grype.bin /usr/local/bin/grype
COPY --from=build /go/package-scanner/tools/syft-bin/syft.bin /usr/local/bin/syft

COPY grype.yaml /root/.grype.yaml
COPY entrypoint.sh /entrypoint.sh

RUN apt-get update

RUN DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends curl bash util-linux ca-certificates podman cron

ARG TARGETPLATFORM

RUN <<EOF
set -eux

if [ "$TARGETPLATFORM" = "linux/arm64" ]; then
    ARCHITECTURE="aarch64"
elif [ "$TARGETPLATFORM" = "linux/amd64" ]; then
    ARCHITECTURE="x86_64"
else
    echo "Unsupported architecture $TARGETPLATFORM" && exit 1;
fi

curl -fsSLO https://download.docker.com/linux/static/stable/${ARCHITECTURE}/docker-${DOCKER_VERSION}.tgz
tar xzvf docker-${DOCKER_VERSION}.tgz --strip 1 -C /usr/local/bin docker/docker
rm docker-${DOCKER_VERSION}.tgz
EOF

RUN <<EOF
set -eux

if [ "$TARGETPLATFORM" = "linux/arm64" ]; then
    ARCHITECTURE="arm64"
elif [ "$TARGETPLATFORM" = "linux/amd64" ]; then
    ARCHITECTURE="amd64"
else
    echo "Unsupported architecture $TARGETPLATFORM" && exit 1
fi

curl -fsSLO https://github.com/containerd/nerdctl/releases/download/v${NERDCTL_VERSION}/nerdctl-${NERDCTL_VERSION}-linux-${ARCHITECTURE}.tar.gz
tar Cxzvvf /usr/local/bin nerdctl-${NERDCTL_VERSION}-linux-${ARCHITECTURE}.tar.gz
rm nerdctl-${NERDCTL_VERSION}-linux-${ARCHITECTURE}.tar.gz
EOF

#RUN echo "0 */4 * * * /usr/local/bin/grype db update" >> /etc/crontabs/root \
#RUN crontab -l | { cat; echo "0 */4 * * * /usr/local/bin/grype db update"; } | crontab - \
#    && chmod +x /entrypoint.sh
#RUN grype db update

EXPOSE 8001 8002 8005
ENTRYPOINT ["/entrypoint.sh"]
