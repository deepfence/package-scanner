# Package Scanner

Scan for vulnerabilities in your docker image or a directory

## Download

Every [release](https://github.com/deepfence/package-scanner/releases) of package scanner provides binary releases for a variety of OSes. These binary versions can be manually downloaded and installed.

1. Go to the [releases](https://github.com/deepfence/package-scanner/releases) page and download the native client package based on your OS and CPU architecture.
2. Unpack it
    ```shell
   tar -zxvf package-scanner_Linux_x86_64.tar
    ```

## Usage

### Image scan
```shell
docker pull longhornio/csi-snapshotter:v6.2.1
./package-scanner -source longhornio/csi-snapshotter:v6.2.1 -container-runtime docker

docker pull nginx:latest
./package-scanner -source nginx:latest -severity critical
```

### Directory scan
```shell
./package-scanner --source dir:<directory full path>
```

## Build
1. make tools
2. make cli
3. This will generate `package-scanner` binary in the current directory

## Build docker image
1. make docker-cli
2. docker images should show new image with name quay.io/deepfenceio/deepfence_package_scanner_cli:2.3.1
```
$ docker images
REPOSITORY                                          TAG       IMAGE ID       CREATED             SIZE
quay.io/deepfenceio/deepfence_package_scanner_cli   2.3.1     e06fb1cd3868   About an hour ago   569MB
nginx                                               latest    1403e55ab369   8 days ago          142MB
```

## Docker image standalone usage example
```
docker pull nginx:latest
docker run -it --rm -v /var/run/docker.sock:/var/run/docker.sock --name package-scanner quay.io/deepfenceio/deepfence_package_scanner_cli:2.3.1 -source nginx:latest
```
