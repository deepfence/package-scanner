FROM golang:1.17-alpine3.15 AS build
RUN apk add --no-cache git \
    && apk add gcc libc-dev libffi-dev bash make protoc
ADD . /go/package-scanner/
WORKDIR /go/package-scanner/
RUN go install google.golang.org/protobuf/cmd/protoc-gen-go@v1.27.1 \
    && go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@v1.2.0 \
    && make \
    && cd /go \
    && git clone https://github.com/deepfence/syft \
    && cd /go/syft \
    && go build -v -o syftCli .

FROM alpine:3.15
MAINTAINER Deepfence Inc
LABEL deepfence.role=system

RUN mkdir -p /var/log/supervisor /etc/supervisor/conf.d
RUN apt-get install -y supervisor

ADD supervisord.conf /etc/supervisor/supervisord.conf
ADD supervisord_grpc.conf /etc/supervisor/supervisord_grpc.conf
ADD supervisord_http.conf /etc/supervisor/supervisord_http.conf

COPY --from=build /go/package-scanner/package-scanner /usr/local/bin/package-scanner
COPY --from=build /go/syft/syftCli /usr/local/bin/syft
RUN apk add --no-cache --update bash
EXPOSE 8002 8005
ENTRYPOINT ["/usr/bin/supervisord", "-c", "/etc/supervisor/supervisord.conf", "-n"]
