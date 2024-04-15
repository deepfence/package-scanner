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
2. make release
3. dist directory contains tar.gz packages for linux and macos as shown below
```
$ ls -lh dist/
total 256M
-rw-r--r-- 1 root root 3.6K Dec 29 09:40 artifacts.json
-rw-r--r-- 1 root root  408 Dec 29 09:40 checksums.txt
-rw-r--r-- 1 root root 3.4K Dec 29 09:40 config.yaml
-rw-r--r-- 1 root root  232 Dec 29 09:40 metadata.json
-rw-r--r-- 1 root root  65M Dec 29 09:40 package-scanner_Darwin_arm64.tar.gz
-rw-r--r-- 1 root root  67M Dec 29 09:40 package-scanner_Darwin_x86_64.tar.gz
-rw-r--r-- 1 root root  61M Dec 29 09:40 package-scanner_Linux_arm64.tar.gz
-rw-r--r-- 1 root root  65M Dec 29 09:40 package-scanner_Linux_x86_64.tar.gz
drwxr-xr-x 2 root root 4.0K Dec 29 09:40 package-scanner_darwin_amd64_v1
drwxr-xr-x 2 root root 4.0K Dec 29 09:40 package-scanner_darwin_arm64
drwxr-xr-x 2 root root 4.0K Dec 29 09:40 package-scanner_linux_amd64_v1
drwxr-xr-x 2 root root 4.0K Dec 29 09:40 package-scanner_linux_arm64
```

## Build docker image
1. make tools
2. make docker
3. docker images should show new image with name quay.io/deepfenceio/deepfence_package_scanner_ce:2.2.0
```
$ docker images
REPOSITORY                                      TAG       IMAGE ID       CREATED             SIZE
quay.io/deepfenceio/deepfence_package_scanner   2.2.0     e06fb1cd3868   About an hour ago   569MB
nginx                                           latest    1403e55ab369   8 days ago          142MB
```

## Docker image standalone usage example
```
docker run -it --rm -v /var/run/docker.sock:/var/run/docker.sock quay.io/deepfenceio/deepfence_package_scanner_ce:2.2.0 package-scanner -source nginx:latest
```
