all: package-scanner

.PHONY: bootstrap
bootstrap: vendor
	$(PWD)/bootstrap.sh

.PHONY: clean
clean:
	-rm package-scanner

.PHONY: clean-all
clean-all: clean
	-rm -rf vendor
	(cd tools/grype-bin && rm -rf grype*)
	(cd tools/syft-bin && rm -rf syft*)

.PHONY: vendor
vendor:
	go mod tidy -v
	go mod vendor

.PHONY: cli
cli: vendor $(PWD)/**/*.go $(PWD)/agent-plugins-grpc/**/*.go
	CGO_ENABLED=0 go build -tags cli -buildvcs=false -v -ldflags="-s -w -extldflags=-static" .

package-scanner: vendor $(PWD)/**/*.go $(PWD)/agent-plugins-grpc/**/*.go
	CGO_ENABLED=0 go build -buildvcs=false -v -ldflags="-s -w -extldflags=-static" .

.PHONY: docker
docker:
	docker build -t quay.io/deepfenceio/deepfence_package_scanner:2.2.0 .

.PHONY: docker-multi-arch
docker-multi-arch:
	docker buildx build --platform linux/arm64,linux/amd64 --tag quay.io/deepfenceio/deepfence_package_scanner:2.2.0 .

.PHONY: buildx
buildx:
	docker run --rm --privileged multiarch/qemu-user-static --reset -p yes
	docker buildx create --name builder --driver docker-container --driver-opt network=host --use
	docker buildx ls
	docker buildx inspect --bootstrap

.PHONY: rm-buildx
rm-buildx:
	docker buildx rm builder

.PHONY: tools
tools: grype syft

.PHONY: grype
grype:
	(cd tools/grype-bin && ./get_grype.sh)

.PHONY: syft
syft:
	(cd tools/syft-bin && ./get_syft.sh)

.PHONY: install-goreleaser
install-goreleaser:
	go install github.com/goreleaser/goreleaser@latest

.PHONY: release
release: install-goreleaser
	goreleaser release --snapshot --clean

.PHONY: update-sdk
update-sdk:
	go get -u -v github.com/deepfence/golang_deepfence_sdk/client@latest
	go get -u -v github.com/deepfence/golang_deepfence_sdk/utils@latest
