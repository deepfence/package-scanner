all: SYFTPLUGIN

$(PWD)/agent-plugins-grpc/proto/*.proto:
	$(PWD)/bootstrap.sh

$(PWD)/agent-plugins-grpc/proto/*.go: $(PWD)/agent-plugins-grpc/proto/*.proto
	(cd agent-plugins-grpc && make go)

clean:
	(cd agent-plugins-grpc && make clean)
	-rm -rf vulnerability-sbom-plugin
	-rm -rf vendor

SYFTPLUGIN: $(PWD)/**/*.go $(PWD)/agent-plugins-grpc/proto/*.go
	go mod vendor
	go build -v

.PHONY: clean