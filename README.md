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

Run this command to generate a license key. Work/official email id has to be used.
```shell
curl https://license.deepfence.io/threatmapper/generate-license?first_name=<FIRST_NAME>&last_name=<LAST_NAME>&email=<EMAIL>&company=<ORGANIZATION_NAME>&resend_email=true
```

### Image scan
Set product and licence key to download the vulnerability database needed for the scan 

```shell
docker pull longhornio/csi-snapshotter:v6.2.1
export DEEPFENCE_PRODUCT=<ThreatMapper or ThreatStryker>
export DEEPFENCE_LICENSE=<ThreatMapper or ThreatStryker license key>
./package-scanner -source longhornio/csi-snapshotter:v6.2.1 -container-runtime docker

docker pull nginx:latest
export DEEPFENCE_PRODUCT=<ThreatMapper or ThreatStryker>
export DEEPFENCE_LICENSE=<ThreatMapper or ThreatStryker license key>
./package-scanner -source nginx:latest -severity critical
```

### Directory scan
```shell
export DEEPFENCE_PRODUCT=<ThreatMapper or ThreatStryker>
export DEEPFENCE_LICENSE=<ThreatMapper or ThreatStryker license key>
./package-scanner --source dir:<directory full path>
```

## Build
1. make tools
2. make cli
3. This will generate `package-scanner` binary in the current directory

## Build docker image
1. make docker-cli
2. docker images should show new image with name quay.io/deepfenceio/deepfence_package_scanner_cli:2.5.0
```
$ docker images
REPOSITORY                                          TAG       IMAGE ID       CREATED             SIZE
quay.io/deepfenceio/deepfence_package_scanner_cli   2.5.0     e06fb1cd3868   About an hour ago   569MB
nginx                                               latest    1403e55ab369   8 days ago          142MB
```

## Docker image standalone usage example
```
docker pull nginx:latest
docker run -it --rm -e DEEPFENCE_PRODUCT=<ThreatMapper or ThreatStryker> -e DEEPFENCE_LICENSE=<ThreatMapper or ThreatStryker license key> -v /var/run/docker.sock:/var/run/docker.sock --name package-scanner quay.io/deepfenceio/deepfence_package_scanner_cli:2.5.0 -source nginx:latest
```
