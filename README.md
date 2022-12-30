# package-scanner

### how to build cli
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

### cli usage examples
- please add security exception for MacOS to run package-scanner if required
- scan a docker image for vulnerabilities
```
./package-scanner -source nginx:latest
```
- scan a docker image, filter for critical vulnerabilities
```
./package-scanner -source nginx:latest -severity critical
```
- scan current directory for vulnerabilities
```
./package-scanner -source dir:./
```

### how to build docker image
1. make tools
2. make docker
3. docker images should show new image with name deepfenceio/deepfence_package_scanner:latest
```
$ docker images
REPOSITORY                              TAG       IMAGE ID       CREATED             SIZE
deepfenceio/deepfence_package_scanner   latest    e06fb1cd3868   About an hour ago   569MB
nginx                                   latest    1403e55ab369   8 days ago          142MB
```

### docker image standalone usage example
```
docker run -it --rm -v /var/run/docker.sock:/var/run/docker.sock deepfenceio/deepfence_package_scanner:latest package-scanner -source nginx:latest
```
