# Setup Library - Tasks

This is the document for describing the implementation for common setup tasks
shared in package `pkg/lib/common/setup`. These tasks provide developers with
ease to configure and run essential pre-flight tasks for all components.

## Terminologies

Abbreviation | Meaning | Reference
-------------|---------|----------
CMS | Certificate managing service | -
URL | Uniform Resource Locator | [Wikipedia](https://en.wikipedia.org/wiki/URL)
RSA | Rivest–Shamir–Adleman cipher | [Wikipedia](https://en.wikipedia.org/wiki/RSA_(cryptosystem))
SHA384 | SHA-2 truncated to 384 bits | [Wikipedia](https://en.wikipedia.org/wiki/SHA-2)
SAN | Subject Alternative Name | [Wikipedia](https://en.wikipedia.org/wiki/Subject_Alternative_Name)
Certificate | Public key certificate | [Wikipedia](https://en.wikipedia.org/wiki/Public_key_certificate)

## Types

### `Task`

Before the legacy codes are removed, this interface cannot be declared

```go
type Task interface {
	Validate() error
	Run() error
	PrintHelp(io.Writer)
}
```

Function | Signature | Description
---------|-----------|------------
Validate | `Validate() error` | Validates check if a task is completed. If certain requirement of successful state is not met, it returns an error containing message for such requirement. Otherwise returns nil if everything looks good
Run | `Run() error` | Run executes the setup task and returns any fatal error.
PrintHelp | `PrintHelp(io.Writer)` | Prints the help of this setup task into given `io.Writer`

Reference [runner.md](./runner.md) for more details

### `SelfSignedCert`

`SelfSignedCert` is the setup task for creating a self signed key and
certificate pair and save generated key and certificate to input key
and certificate file.

```go
type SelfSignedCert struct {
	KeyFile  string
	CertFile string

	CommonName   string
	SANList      string
	Issuer       string
	ValidityDays int

	PublicKey     crypto.PublicKey
	PrivateKey    crypto.PrivateKey
	ConsoleWriter io.Writer
    // un-exported fields omitted
}
```

Filed | Type | Description
------|------|------------
KeyPath | `string` | The file name to which the key will be stored
CertPath | `string` | The file name to which the certificate will be stored
CommonName | `string` | The common name for signing the certificate
SANList | `string` | The san list for signing the certificate. Including ip addresses and DNS names
Issuer | `string` | The issuer of the certificate, default to `intel`
ValidityDays | `int` | The time span in which the certificate is valid, measured in days
PublicKey | `crypto.PublicKey` | The public key for signing the certificate\*
PrivateKey | `crypto.PrivateKey` | The private for signing the certificate\*
ConsoleWriter | `io.Writer` | The `io.Writer` to which messages are written. All message ignored if set to `nil`

\* If either of the key is `nil`, the task will generate a pair of `RSA-3072`
key for signing the certificate

### `DownloadCMSCert`

`DownloadCMSCert` downloads the CA certificate from CMS and store it in
the configured directory. The file name used is the SHA1 value of the
downloaded certificate truncated to the first 8 characters.

```go
type DownloadCMSCert struct {
	CaCertDirPath string
	CmsBaseURL    string
	TlsCertDigest string
	ConsoleWriter io.Writer
}
```

Filed | Type | Description
------|------|------------
CaCertDirPath | `string` | The directory to which downloaded certificate should be stored
CmsBaseURL | `string` | The URL to access CMS api
TlsCertDigest | `string` | The `SHA384` digest of CMS certificate
ConsoleWriter | `io.Writer` | The `io.Writer` to which messages are written. All message ignored if set to `nil`

#### Environment override support

Following fields will be overwritten if corresponding environment variable is set

Filed | Environment Variable
------|----------------------
CmsBaseURL | `CMS_BASE_URL`
TlsCertDigest | `TLS_CERT_DIGEST`

#### Problem

Using the `SHA1` value as file name is not desired since it is not possible
to validate the setup task correctly before running it. Current implementation
is only verifying if the targeted directory is empty, which does not precisely
indicate if CMS CA certificate is correctly downloaded.

#### Suggested changes

Use the `SHA384` hash value and truncate it to the first 8 characters instead
of that derived from another `SHA1` operation

### `DownloadCert`

`DownloadCert` creates an RSA key pair and requests CMS for the signed CA
certificate of such key pair. Then it stores the key and certificate to
the configured file location.

```go
type DownloadCert struct {
	KeyFile            string
	CertFile           string
	KeyAlgorithm       string
	KeyAlgorithmLength int
	Subject            pkix.Name
	CertType           string
	CaCertsDir         string

	CmsBaseURL  string
	SanList     string
	BearerToken string

	ConsoleWriter io.Writer
}
```

Filed | Type | Description
------|------|------------
KeyPath | `string` | The file name to which the key will be stored
CertPath | `string` | The file name to which the certificate will be stored
KeyAlgorithm | `string` | Specify the key algorithm to use. Reference in package `pkg/lib/common/crypt`. Can be either `rsa` or `ecdsa`
KeyAlgorithmLength | `int` | The key length of the private key `pkg/lib/common/crypt`
Subject | `pkix.Name` | The subject of the certificate
CertType | `string` | An argument consumed by CMS API
CaCertsDir | `string` | The directory to which downloaded certificate should be stored
CmsBaseURL | `string` | The URL to access CMS api
SanList | `string` | The SAN list to sign into the certificate
BearerToken | `string` | The bearer For accessing CMS API
ConsoleWriter | `io.Writer` | The `io.Writer` to which messages are written. All message ignored if set to `nil`

#### Environment override support

Following fields will be overwritten if corresponding environment variable is set

Filed | Environment Variable
------|----------------------
CmsBaseURL | `CMS_BASE_URL`
SanList | `SAN_LIST`
BearerToken | `BEARER_TOKEN`