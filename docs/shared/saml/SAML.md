# SAML Library document

## Terminologies

Abbreviation | Meaning | Reference
-------------|---------|----------
RSA | Rivest–Shamir–Adleman cipher | [Wikipedia](https://en.wikipedia.org/wiki/RSA_(cryptosystem))
SAML | Security Assertion Markup Language | [Wikipedia](https://en.wikipedia.org/wiki/Security_Assertion_Markup_Language), [SAMLtool.com](https://www.samltool.com/generic_sso_res.php)
SP | SAML service provider | [Wikipedia](https://en.wikipedia.org/wiki/Service_provider_(SAML))
IDP | SAML identity provider | [Wikipedia](https://en.wikipedia.org/wiki/Identity_provider_(SAML))
URI | Uniform Resource Identifier | [Wikipedia](https://en.wikipedia.org/wiki/Uniform_Resource_Identifier)

## Types

### `SamlSigner` interface

### `IssuerConfiguration` structure

`IssuerConfiguration` is the configuration to which SAML library reference
to generate SAML reports

```Go
type IssuerConfiguration struct {
	PrivateKey        *rsa.PrivateKey
	Certificate       *x509.Certificate
	IssuerName        string
	IssuerServiceName string
	ValiditySeconds   int
}
```

Field | Type | Description
------|------|-------------
PrivateKey | Pointer to `rsa.PrivateKey` structure | The RSA private key for signing SAML reports
Certificate | Pointer to `x509.Certificate` | The certificate of the RSA private key used for signing
IssuerName | `string` | The URI to which SPs query SAML metadata (i.e. REST end point on IDP)
IssuerServiceName | `string` | The service name of SAML issuer, add to SAML report as an attribute
ValiditySeconds | `int` | The time span in which this SAML report is valid, starting from the point it is created. Measured in seconds

### `defaultSamlSigner` structure

The default structure implementing `SamlSigner` interface. No exported field in this structure

### `SamlAssertion` structure

`SamlAssertion` is the assertion generated from this library 

```Go
type SamlAssertion struct {
	Assertion   string
	CreatedTime time.Time
	ExpiryTime  time.Time
}
```

Field | Type | Description
------|------|-------------
Assertion | `string` | XML encoded string of the assertion
CreatedTime | `time.Time` | The time at which this assertion is generated
ExpiryTime | `time.Time` | The time at which this assertion will expire

## Functions


### `NewSAML`
```Go
func NewSAML(ic IssuerConfiguration) (SamlSigner, error)
```
NewSAML returns an exported interface `SamlSigner` configured according to input `IssuerConfiguration`


### `NewMapFormatter`
```Go
func NewMapFormatter(data map[string]string) assertionFormatter
```
NewMapFormatter returns an unexported interface `assertionFormatter` that formats XML tree according to input `map`

### Methods of `defaultSamlSigner` structure

```Go
func (ss defaultSamlSigner) GetKeyPair() (*rsa.PrivateKey, []byte, error)
```
GetKeyPair returns the RSA key pair for signing the assertion. This function is required for dependency `github.com/amdonov/xmlsig` to work properly.

```Go
func (ss defaultSamlSigner) GenerateSamlAssertion(f assertionFormatter) (SamlAssertion, error)
```
GenerateSamlAssertion generates SAML assertion with the input XML formatter

### `ValidateSamlAssertion`
```Go
ValidateSamlAssertion(sa SamlAssertion, root *x509.Certificate) (*etree.Element, error)
```
ValidateSamlAssertion validates the input SAML assertion and returned the content as parsed XML element tree

## Sample Usage

Following code snippet is an example of using functions in this library

```Go
package main

import saml

func main() {
	testMap := map[string]string{
		"test-field-1": "test-val-1",
		"test-field-2": "test-val-2",
		"test-field-3": "test-val-3",
		"test-field-4": "test-val-4",
		"test-field-5": "test-val-5",
	}
	key, cert, err := genKeyAndCert()
	if err != nil {
		panic("Failed to generate rsa key: "+err.Error())
	}
	testIc := IssuerConfiguration{
		IssuerName:        "http://idp.test.com/metadata.php",
		IssuerServiceName: "test-idp",
		ValiditySeconds:   100,
		PrivateKey:        key,
		Certificate:       cert,
	}
	testSAML, err := saml.NewSAML(testIc)
	if err != nil {
		panic("Failed to create saml object: "+err.Error())
	}
	testFormatter := saml.NewMapFormatter(testMap)
	assertion, err := testSAML.GenerateSamlAssertion(testFormatter)
	if err != nil {
		panic("Failed to create saml assertion: "+err.Error())
	}

	validElement, err := saml.ValidateSamlAssertion(assertion, cert)
	if err != nil {
		panic("Failed to validate assertion", err)
	}
	return
}
```

## Sample Output

Should generate the following XML document (times, signatures may vary)

```xml
<saml:Assertion
	xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
	xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
	xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
	xmlns:xsd="http://www.w3.org/2001/XMLSchema" Version="2.0" ID="6ce3937d-2148-4ee9-92c6-91063b905f7f" IssueInstant="2020-05-12T22:45:22.295Z">
	<saml:Issuer>http://idp.test.com/metadata</saml:Issuer>
	<saml:Subject>
		<saml:NameID Format="urn:oasis:names:tc:SAML:2.0:nameid-format:unspecified">http://idp.test.com/metadata</saml:NameID>
		<saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:sender-vouches">
			<saml:SubjectConfirmationData NotOnOrAfter="2020-05-12T22:47:02.295Z" NotBefore="2020-05-12T22:45:22.295Z"/>
			<saml:NameID Format="urn:oasis:names:tc:SAML:2.0:nameid-format:unspecified">Intel Security Libraries</saml:NameID>
		</saml:SubjectConfirmation>
	</saml:Subject>
	<saml:Conditions NotBefore="2020-05-12T22:45:22.295Z" NotOnOrAfter="2020-05-12T22:47:02.295Z">
		<saml:AudienceRestriction>
			<saml:Audience>https://sp.test.com/test/service/endpoint</saml:Audience>
		</saml:AudienceRestriction>
	</saml:Conditions>
	<saml:AttributeStatement>
		<saml:Attribute Name="IssuerServiceName" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic">
			<saml:AttributeValue xsi:type="xs:string">test-idp</saml:AttributeValue>
		</saml:Attribute>
		<saml:Attribute Name="test-field-4" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic">
			<saml:AttributeValue xsi:type="xs:string">test-val-4</saml:AttributeValue>
		</saml:Attribute>
		<saml:Attribute Name="test-field-5" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic">
			<saml:AttributeValue xsi:type="xs:string">test-val-5</saml:AttributeValue>
		</saml:Attribute>
		<saml:Attribute Name="test-field-1" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic">
			<saml:AttributeValue xsi:type="xs:string">test-val-1</saml:AttributeValue>
		</saml:Attribute>
		<saml:Attribute Name="test-field-2" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic">
			<saml:AttributeValue xsi:type="xs:string">test-val-2</saml:AttributeValue>
		</saml:Attribute>
		<saml:Attribute Name="test-field-3" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic">
			<saml:AttributeValue xsi:type="xs:string">test-val-3</saml:AttributeValue>
		</saml:Attribute>
	</saml:AttributeStatement>
</saml:Assertion>
```

```xml
<saml:Assertion
	xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
	xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
	xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
	xmlns:xsd="http://www.w3.org/2001/XMLSchema" Version="2.0" ID="7137703b-4c61-43d5-98f3-e726ba6f62a2" IssueInstant="2020-05-13T04:29:01.169Z">
	<saml:Issuer>http://idp.test.com/metadata.php</saml:Issuer>
	<saml:Subject>
		<saml:NameID Format="urn:oasis:names:tc:SAML:2.0:nameid-format:unspecified">http://idp.test.com/metadata.php</saml:NameID>
		<saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:sender-vouches">
			<saml:SubjectConfirmationData NotOnOrAfter="2020-05-13T04:30:41.169Z" NotBefore="2020-05-13T04:29:01.169Z"/>
			<saml:NameID Format="urn:oasis:names:tc:SAML:2.0:nameid-format:unspecified">Intel Security Libraries</saml:NameID>
		</saml:SubjectConfirmation>
	</saml:Subject>
	<saml:Conditions NotBefore="2020-05-13T04:29:01.169Z" NotOnOrAfter="2020-05-13T04:30:41.169Z"/>
	<saml:AttributeStatement>
		<saml:Attribute Name="IssuerServiceName" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic">
			<saml:AttributeValue xsi:type="xs:string">test-idp</saml:AttributeValue>
		</saml:Attribute>
		<saml:Attribute Name="test-field-4" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic">
			<saml:AttributeValue xsi:type="xs:string">test-val-4</saml:AttributeValue>
		</saml:Attribute>
		<saml:Attribute Name="test-field-5" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic">
			<saml:AttributeValue xsi:type="xs:string">test-val-5</saml:AttributeValue>
		</saml:Attribute>
		<saml:Attribute Name="test-field-1" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic">
			<saml:AttributeValue xsi:type="xs:string">test-val-1</saml:AttributeValue>
		</saml:Attribute>
		<saml:Attribute Name="test-field-2" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic">
			<saml:AttributeValue xsi:type="xs:string">test-val-2</saml:AttributeValue>
		</saml:Attribute>
		<saml:Attribute Name="test-field-3" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic">
			<saml:AttributeValue xsi:type="xs:string">test-val-3</saml:AttributeValue>
		</saml:Attribute>
	</saml:AttributeStatement>
	<ds:Signature
		xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
		<ds:SignedInfo>
			<ds:CanonicalizationMethod Algorithm="http://www.w3.org/2006/12/xml-c14n11"/>
			<ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/>
			<ds:Reference URI="#7137703b-4c61-43d5-98f3-e726ba6f62a2">
				<ds:Transforms>
					<ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/>
					<ds:Transform Algorithm="http://www.w3.org/2006/12/xml-c14n11"/>
				</ds:Transforms>
				<ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>
				<ds:DigestValue>5Tnw+oHQpiW7RvEH6O2cMFnspwn4Py5fyY3dmdxRvJ4=</ds:DigestValue>
			</ds:Reference>
		</ds:SignedInfo>
		<ds:SignatureValue>YcATGjZJjTlgK0i8olaW9GAROHRYfowonKEV0rgc2SgfTt0fj8JPzO+qoxKzczcLQcHduuR17CldlD1H7BpasOWVMUB9YwakpyznExauEgkBsMFTWQOmqwKtHzqgYZpT2hSGcT/sCnWgFXRrvqXH510mMFdHUX4EEWr4yLVDYXM=</ds:SignatureValue>
		<ds:KeyInfo>
			<ds:X509Data>
				<ds:X509Certificate>MIIBlTCB/6ADAgECAgEAMA0GCSqGSIb3DQEBCwUAMAAwHhcNMjAwNTEzMDQyNDAxWhcNMjEwNTEzMDQyOTAxWjAAMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDKgcV7urhnL5SXg1Z2MflezXwxPRh0/iiiz8+fMVWNuGG1xRCH4zu8tkLsU023RRUbTB3Ug0DOSS9pXACQ0pWJ/kDjnWjOIrPFOdAh/ElUCtdVdJ5jCxKpBYUWJZ9M/GkG92syUybTiOn6IfoqhWTIft5KkzUPQvcA8jIZVOUscQIDAQABoyAwHjAOBgNVHQ8BAf8EBAMCB4AwDAYDVR0TAQH/BAIwADANBgkqhkiG9w0BAQsFAAOBgQBi9KvTniGZmFSFiaaiCy5xJMVLIxScuHcejYKaUcKGhSI/I4hhbBoa0t/iUCLRIfA6KzJnmyxYalJWr8zX4R1KW6Qba6jxgnYWJN3b30uKj66ohBZsNeoU4m6XOVz5QQvaU7WQ2ofFkZYSobDSUIg+d0I+YwtN+Wd50592Pmc0Kw==</ds:X509Certificate>
			</ds:X509Data>
		</ds:KeyInfo>
	</ds:Signature>
</saml:Assertion>
```