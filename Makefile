all: proto

$(PWD)/agent-plugins-grpc/proto/*.proto:
	$(PWD)/bootstrap.sh

$(PWD)/agent-plugins-grpc/proto/*.go: $(PWD)/agent-plugins-grpc/proto/*.proto
	(cd agent-plugins-grpc && make go)
	-rm -rf proto
	cp -r agent-plugins-grpc/proto .

clean:
	(cd agent-plugins-grpc && make clean)
	-rm -rf package-scanner proto

proto: $(PWD)/**/*.go $(PWD)/agent-plugins-grpc/proto/*.go
	env CGO_ENABLED=0 go build -buildvcs=false -v .

.PHONY: clean