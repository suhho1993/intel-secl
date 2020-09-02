# Intel<sup>®</sup> Security Libraries for Data Center  - Key Broker Service
#### The Intel<sup>®</sup> SecL - DC Key Broker Service(KBS) component performs key distribution using platform trust to authorize key transfers. The KBS verifies the host's attestation from the Verification Service, verifies all digital signatures, and retains final control over whether the decryption key is issued. If the server's attestation meets the policy requirements, the KBS issues a decryption key itself wrapped using the AIK-derived binding key from the host that was attested, cryptographically ensuring that only the attested host can decrypt the requested image

## Key features
- Provides and retains encryption/decryption keys for virtual machine images / docker images
- The Key Broker Service connects to a back-end 3rd Party KMIP-compliant key management service, like OpenStack Barbican, for key creation and vaulting services

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
The `KBS` requires Go version 1.12.1 that has support for `go modules`. The build was validated with the latest version go1.14.1 of `go`. It is recommended that you use go1.14.1 version of `go`. You can use the following to install `go`.
```shell
wget https://dl.google.com/go/go1.14.1.linux-amd64.tar.gz
tar -xzf go1.14.1.linux-amd64.tar.gz
sudo mv go /usr/local
export GOROOT=/usr/local/go
export PATH=$GOPATH/bin:$GOROOT/bin:$PATH
```

## Build Key Broker Service

- Git clone the `Key Broker Service`
- Run scripts to build the `Key Broker Service`

```shell
$ git clone https://github.com/intel-secl/intel-secl.git
$ cd intel-secl
$ make kbs-installer
```

# Links
 - Use [Automated Build Steps](https://01.org/intel-secl/documentation/build-installation-scripts) to build all repositories in one go, this will also provide provision to install prerequisites and would handle order and version of dependent repositories.

***Note:** Automated script would install a specific version of the build tools, which might be different than the one you are currently using*
 - [Product Documentation](https://01.org/intel-secl/documentation/intel%C2%AE-secl-dc-product-guide)
