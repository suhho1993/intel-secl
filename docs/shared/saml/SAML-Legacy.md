# SAML library for legacy support

Functions introduced in this document are for providing backward compatibility
with old Java components that use off-standard SAML assertion structure. All
functions are labeled `Legacy` but provides identical interfaces and
functionalities. The only difference will be the generated SAML-like assertions.


## Types

Reference [SAML.md](SAML.md)

### `legacySamlSigner` structure

The default structure implementing `SamlSigner` interface. No exported field in this structure


## Functions

### `NewLegacySAML`
```Go
func NewLegacySAML(ic IssuerConfiguration) (SamlSigner, error)
```
NewLegacySAML returns an exported interface `SamlSigner` configured according to input `IssuerConfiguration`. This `SamlSigner` generates legacy SAML assertions


### `NewLegacyMapFormatter`
```Go
func NewLegacyMapFormatter(data map[string]string) assertionFormatter
```
NewLegacyMapFormatter returns an unexported interface `assertionFormatter` that formats XML tree according to input `map`. Since there are xml namespace differences, this formatter is required being used with `NewLegacySAML`


### `ValidateLegacySamlAssertion`
```Go
ValidateLegacySamlAssertion(sa SamlAssertion, root *x509.Certificate) (*etree.Element, error)
```
ValidateLegacySamlAssertion validates the input SAML-like assertion and returned the content as parsed XML element tree. For the reason of different in xml structure, this function is required for verifying assertion generated with `NewLegacySAML` 


## Sample Usage

Reference [SAML.md](SAML.md)

## Sample Output

```xml
<saml2:Assertion ID="MapAssertion" IssueInstant="2020-05-14T01:02:15.823Z" Version="2.0"
	xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion"
	xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
	xmlns:xsd="http://www.w3.org/2001/XMLSchema">
	<saml2:Issuer>http://idp.test.com/metadata.php</saml2:Issuer>
	<saml2:Subject>
		<saml2:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified">test-idp</saml2:NameID>
		<saml2:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:sender-vouches">
			<saml2:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified"/>
			<saml2:SubjectConfirmationData NotBefore="2020-05-14T01:02:15.823Z" NotOnOrAfter="2020-05-14T01:03:55.823Z"/>
		</saml2:SubjectConfirmation>
	</saml2:Subject>
	<saml2:AttributeStatement>
		<saml2:Attribute Name="test-field-1" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic">
			<saml2:AttributeValue xsi:type="xs:string">test-val-1</saml2:AttributeValue>
		</saml2:Attribute>
		<saml2:Attribute Name="test-field-2" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic">
			<saml2:AttributeValue xsi:type="xs:string">test-val-2</saml2:AttributeValue>
		</saml2:Attribute>
		<saml2:Attribute Name="test-field-3" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic">
			<saml2:AttributeValue xsi:type="xs:string">test-val-3</saml2:AttributeValue>
		</saml2:Attribute>
		<saml2:Attribute Name="test-field-4" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic">
			<saml2:AttributeValue xsi:type="xs:string">test-val-4</saml2:AttributeValue>
		</saml2:Attribute>
		<saml2:Attribute Name="test-field-5" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic">
			<saml2:AttributeValue xsi:type="xs:string">test-val-5</saml2:AttributeValue>
		</saml2:Attribute>
	</saml2:AttributeStatement>
	<Signature
		xmlns="http://www.w3.org/2000/09/xmldsig#">
		<SignedInfo>
			<CanonicalizationMethod Algorithm="http://www.w3.org/2006/12/xml-c14n11"/>
			<SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/>
			<Reference URI="#MapAssertion">
				<Transforms>
					<Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/>
					<Transform Algorithm="http://www.w3.org/2006/12/xml-c14n11"/>
				</Transforms>
				<DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>
				<DigestValue>lmhS+/jVFj68y1yawPnJdX+zzAhjApfoE1wSC1C15lw=</DigestValue>
			</Reference>
		</SignedInfo>
		<SignatureValue>Eikwvy/dyQfhgREBNn1eRJxJN70T754dTXhj8WlFblgNyVvwhS4F7l4kvHc/ZVCdlzmaJWdKhlJr0sZ7k56TQgQoStLSDB8kkydeo5GQRgbvhXYd6Qj2tsAjcJbshKfWX6pY6R22CydWXHYyhUfOOIyck7yhL8rW3klT0roM6G0=</SignatureValue>
		<KeyInfo>
			<X509Data>
				<X509Certificate>MIIBlTCB/6ADAgECAgEAMA0GCSqGSIb3DQEBCwUAMAAwHhcNMjAwNTE0MDA1NzE1WhcNMjEwNTE0MDEwMjE1WjAAMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDClG9v59SjcfEae8CoVvxxuwG9Zo2KwKZqbXmuNuz8sKMfYXcNGxCbZY6/Vtm7RiE2vw55NuybhOJ6uyM+MUe0kBbeGuZv8/Lhnk2FLtg3E5XzNZmdcxOwPur21HkYHD7UntF0CgKSJDhZKkt1OmSZqtR+ZxAcNNgX09mhqt7iiQIDAQABoyAwHjAOBgNVHQ8BAf8EBAMCB4AwDAYDVR0TAQH/BAIwADANBgkqhkiG9w0BAQsFAAOBgQAclgN1rpTayvr6mlJ6HPsORHeWIRJwTlyKrYJovYmABakQCMgydPm2oG6D9EZCGbTrLnnsx3+mlGVFDwHUlR8s1+OAT1/AibJqwUw7azoIrCBNSwgRq8mxBU7hXuOQGZjvO0XzcN3gHKOZH9IAijeEi+D7ORCnULHcogSb2kdaYg==</X509Certificate>
			</X509Data>
		</KeyInfo>
	</Signature>
</saml2:Assertion>
```