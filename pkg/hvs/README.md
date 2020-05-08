# Intel<sup>®</sup> Security Libraries for Data Center  - HVS
#### The Intel<sup>®</sup> SecL - DC HVS component performs remote attestation of physical servers, comparing Intel<sup>®</sup> TXT measurements of BIOS, OS, Asset Tag, and other components against a database of known-good values. The attested trust status of each server is used to make policy decisions for workload placement. As a server boots, Intel<sup>®</sup> TXT begins extending measurements to a Trusted Platform Module (TPM). Each chain of trust component is measured, and these measurements are remotely verified using the Attestation Server.

## Key features
- Remote attestation of platforms
- Provides storage for good known values for platforms
- Provides trust status evaluation of platforms against good known values
- RESTful APIs for easy and versatile access to above features

## System Requirements
- RHEL 8.1
- Epel 8 Repo
- Proxy settings if applicable

## Software requirements
- git
- makeself
- `go` version >= `go1.12.1` & <= `go1.14.1``

# Step By Step Build Instructions
## Install required shell commands
Please make sure that you have the right `http proxy` settings if you are behind a proxy
```shell
export HTTP_PROXY=http://<proxy>:<port>
export HTTPS_PROXY=https://<proxy>:<port>
```
### Install tools from `yum`
```shell
$ sudo yum install -y wget git makeself
```

### Install `go` version >= `go1.12.1` & <= `go1.14.1`
The `HVS` requires Go version 1.12.1 that has support for `go modules`. The build was validated with the latest version go1.14.1 of `go`. It is recommended that you use go1.14.1 version of `go`. You can use the following to install `go`.
```shell
wget https://dl.google.com/go/go1.14.1.linux-amd64.tar.gz
tar -xzf go1.14.1.linux-amd64.tar.gz
sudo mv go /usr/local
export GOROOT=/usr/local/go
export PATH=$GOPATH/bin:$GOROOT/bin:$PATH
```

## Build HVS

- Git clone the `HVS`
- Run scripts to build the `HVS`

```shell
$ git clone https://github.com/intel-secl/hvs.git
$ cd hvs
$ make installer
```

# Links
 - Use [Automated Build Steps](https://01.org/intel-secl/documentation/build-installation-scripts) to build all repositories in one go, this will also provide provision to install prerequisites and would handle order and version of dependent repositories.

***Note:** Automated script would install a specific version of the build tools, which might be different than the one you are currently using*
 - [Product Documentation](https://01.org/intel-secl/documentation/intel%C2%AE-secl-dc-product-guide)
