all: proto

$(PWD)/agent-plugins-grpc/proto/*.proto:
	$(PWD)/bootstrap.sh

$(PWD)/agent-plugins-grpc/proto/*.go: $(PWD)/agent-plugins-grpc/proto/*.proto
	(cd agent-plugins-grpc && make go)
	-rm -rf proto
	cp -r agent-plugins-grpc/proto .

.PHONY: clean
clean:
	(cd agent-plugins-grpc && make clean)
	-rm -rf package-scanner proto

proto: $(PWD)/**/*.go $(PWD)/agent-plugins-grpc/proto/*.go
	go build -buildvcs=false -v .

.PHONY: docker
docker: 
	docker build -t deepfenceio/package-scanner:latest .