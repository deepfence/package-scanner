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

proto: $(PWD)/**/*.go $(PWD)/agent-plugins-grpc/proto/*.go $(PWD)/*.go
	CGO_ENABLED=0 go build -buildvcs=false -v .

.PHONY: docker
docker:
	docker build -t deepfenceio/deepfence_package_scanner:latest .

.PHONY: docker-multi-arch
docker-multi-arch:
	docker buildx build --platform linux/arm64,linux/amd64 --tag deepfenceio/deepfence_package_scanner:latest .

.PHONY: buildx
buildx:
	docker run --rm --privileged multiarch/qemu-user-static --reset -p yes
	docker buildx create --name cibuilder --driver docker-container --use
	docker buildx ls
	docker buildx inspect --bootstrap

.PHONY: rm-buildx
rm-buildx:
	docker buildx rm cibuilder

.PHONY: tools
tools:
	(cd tools/grype-bin && ./get_grype.sh)
	(cd tools/syft-bin && ./get_syft.sh)

.PHONY: install-goreleaser
install-goreleaser:
	go install github.com/goreleaser/goreleaser@latest

.PHONY: release
release: install-goreleaser
	goreleaser release --snapshot --rm-dist