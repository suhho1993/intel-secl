package saml

import (
	"crypto/rsa"
	"crypto/x509"
	"time"

	"github.com/beevik/etree"
	"github.com/pkg/errors"
	dsig "github.com/russellhaering/goxmldsig"
)

type legacySamlSigner struct {
	issuerConfig     IssuerConfiguration
	validityDuration time.Duration
	certBytes        []byte
}

type legacyMapFormatter struct {
	userData map[string]string
}

// NewLegacySAML returns an exported interface SamlSigner configured
// according to input IssuerConfiguration
func NewLegacySAML(ic IssuerConfiguration) (SamlSigner, error) {
	r := legacySamlSigner{}
	if ic.IssuerName == "" {
		return r, errors.New("Invalid IssuerName for IssuerConfiguration")
	}
	if ic.IssuerServiceName == "" {
		return r, errors.New("Invalid IssuerServiceName for IssuerConfiguration")
	}
	if ic.ValiditySeconds == 0 {
		return r, errors.New("Invalid ValiditySeconds for IssuerConfiguration")
	}
	if ic.PrivateKey == nil {
		return r, errors.New("No private key assigned to issuer configuration")
	}
	if ic.Certificate == nil {
		return r, errors.New("No certificate assigned to issuer configuration")
	}
	r.issuerConfig = ic
	r.validityDuration = time.Second * time.Duration(ic.ValiditySeconds)
	r.certBytes = ic.Certificate.Raw
	return r, nil
}

// GetKeyPair returns the RSA key pair for signing the assertion
func (ss legacySamlSigner) GetKeyPair() (*rsa.PrivateKey, []byte, error) {
	return ss.issuerConfig.PrivateKey, ss.certBytes, nil
}

// GenerateSamlAssertion generates SAML assertion with the input XML formatter
func (ss legacySamlSigner) GenerateSamlAssertion(f assertionFormatter) (SamlAssertion, error) {
	r := SamlAssertion{}
	// generate xml tree from formatter
	xml, err := f.generateXMLTree(ss.issuerConfig)
	if err != nil {
		return r, errors.Wrap(err, "Failed to generate XML tree for signing")
	}
	// sign the xml tree
	signedTree, err := signXMLTree(ss, xml)
	if err != nil {
		return r, err
	}
	// remove ds namespace prefix
	dsRoot := signedTree.SelectElement("ds:Signature")
	dsRoot.RemoveAttr("xmlns:ds")
	dsRoot.CreateAttr("xmlns", "http://www.w3.org/2000/09/xmldsig#")
	removeNS(dsRoot, "ds")

	// create xml document from the tree
	docAfterSign := etree.NewDocument()
	docAfterSign.SetRoot(signedTree)
	signedDocStr, err := docAfterSign.WriteToString()
	if err != nil {
		return r, errors.Wrap(err, "Failed to create signed document")
	}
	// prepare the assertion
	r.Assertion = signedDocStr
	r.CreatedTime = time.Now().UTC()
	r.ExpiryTime = time.Now().UTC().Add(ss.validityDuration)
	return r, nil
}

// NewLegacyMapFormatter returns an unexported interface assertionFormatter
// that formats XML tree according to input map
func NewLegacyMapFormatter(data map[string]string) assertionFormatter {
	return &legacyMapFormatter{
		userData: data,
	}
}

func (mf *legacyMapFormatter) generateXMLTree(ic IssuerConfiguration) (*etree.Element, error) {
	issueTime := time.Now().UTC().Format(rfc3339ms)
	d := time.Duration(ic.ValiditySeconds) * time.Second
	validTime := time.Now().Add(d).UTC().Format(rfc3339ms)
	// xml tree root
	root := etree.NewElement("saml2:Assertion")
	root.CreateAttr("ID", "MapAssertion")
	root.CreateAttr("IssueInstant", issueTime)
	root.CreateAttr("Version", "2.0")
	root.CreateAttr("xmlns:saml2", "urn:oasis:names:tc:SAML:2.0:assertion")
	root.CreateAttr("xmlns:xsi", "http://www.w3.org/2001/XMLSchema-instance")
	root.CreateAttr("xmlns:xsd", "http://www.w3.org/2001/XMLSchema")

	// issuer
	issuer := etree.NewElement("saml2:Issuer")
	issuer.CreateText(ic.IssuerName)
	root.AddChild(issuer)

	// subject
	subject := etree.NewElement("saml2:Subject")
	subjectNameID := etree.NewElement("saml2:NameID")
	subjectNameID.CreateAttr("Format", "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified")
	subjectNameID.CreateText(ic.IssuerServiceName)

	// subject confirmation
	subjectConfirmation := etree.NewElement("saml2:SubjectConfirmation")
	subjectConfirmation.CreateAttr("Method", "urn:oasis:names:tc:SAML:2.0:cm:sender-vouches")
	subjectConfirmationNameID := etree.NewElement("saml2:NameID")
	subjectConfirmationNameID.CreateAttr("Format", "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified")
	subjectConfirmationData := etree.NewElement("saml2:SubjectConfirmationData")
	subjectConfirmationData.CreateAttr("NotBefore", issueTime)
	subjectConfirmationData.CreateAttr("NotOnOrAfter", validTime)
	subjectConfirmation.AddChild(subjectConfirmationNameID)
	subjectConfirmation.AddChild(subjectConfirmationData)

	subject.AddChild(subjectNameID)
	subject.AddChild(subjectConfirmation)
	root.AddChild(subject)

	// attribute statement
	attributeStatement := etree.NewElement("saml2:AttributeStatement")
	for k, v := range mf.userData {
		attribute := etree.NewElement("saml2:Attribute")
		attribute.CreateAttr("Name", k)
		attribute.CreateAttr("NameFormat", "urn:oasis:names:tc:SAML:2.0:attrname-format:basic")
		attributeValue := etree.NewElement("saml2:AttributeValue")
		attributeValue.CreateAttr("xsi:type", "xs:string")
		attributeValue.CreateText(v)
		attribute.AddChild(attributeValue)
		attributeStatement.AddChild(attribute)
	}
	root.AddChild(attributeStatement)
	return root, nil
}

// ValidateLegacySamlAssertion validates the input SAML-like assertion
// and returned the content as parsed XML element tree
func ValidateLegacySamlAssertion(sa SamlAssertion, root *x509.Certificate) (*etree.Element, error) {
	if root == nil {
		return nil, errors.New("No certificate provided")
	}
	docStr := sa.Assertion
	if docStr == "" ||
		!isASCII(docStr) {
		return nil, errors.New("Invalid XML string: non-ASCII charactors detected")
	}
	doc := etree.NewDocument()
	if err := doc.ReadFromString(docStr); err != nil {
		return nil, errors.Wrap(err, "Failed to parse XML document")
	}
	// add ds namespace back
	dsRoot := doc.Root().SelectElement("Signature")
	setNS(dsRoot, "ds")
	dsRoot.RemoveAttr("xmlns")
	dsRoot.CreateAttr("xmlns:ds", "http://www.w3.org/2000/09/xmldsig#")

	ctx := dsig.NewDefaultValidationContext(&dsig.MemoryX509CertificateStore{
		Roots: []*x509.Certificate{root},
	})
	validated, err := ctx.Validate(doc.Root())
	if err != nil {
		return nil, errors.Wrap(err, "Failed to validate XML document")
	}
	return validated, nil
}

func setNS(root *etree.Element, ns string) {
	if root == nil {
		return
	}
	root.Space = ns
	for _, c := range root.ChildElements() {
		setNS(c, ns)
	}
	return
}

func removeNS(root *etree.Element, ns string) {
	if root == nil {
		return
	}
	if root.Space == ns {
		root.Space = ""
	}
	for _, c := range root.ChildElements() {
		removeNS(c, ns)
	}
	return
}
