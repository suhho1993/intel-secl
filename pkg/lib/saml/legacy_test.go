package saml

import (
	"testing"

	"github.com/beevik/etree"
)

func TestGenLegacyAssertion(t *testing.T) {
	testMap := map[string]string{
		"test-field-1": "test-val-1",
		"test-field-2": "test-val-2",
		"test-field-3": "test-val-3",
		"test-field-4": "test-val-4",
		"test-field-5": "test-val-5",
	}
	f := NewLegacyMapFormatter(testMap)
	root, err := f.generateXMLTree(IssuerConfiguration{
		IssuerName:        "http://idp.test.com/metadata",
		IssuerServiceName: "test-idp",
		ValiditySeconds:   100,
	})
	if err != nil || root == nil {
		t.Fatal("xml tree generate failed")
	}
	docBeforeSign := etree.NewDocument()
	docBeforeSign.SetRoot(root)
	docStr, err := docBeforeSign.WriteToString()
	if err != nil {
		t.Error("Failed to create unsigned document:", err.Error())
		t.Fail()
	}
	t.Log("Unsigned document:")
	t.Log(docStr)
}

func TestLegacyGenAndSign(t *testing.T) {
	testMap := map[string]string{
		"test-field-1": "test-val-1",
		"test-field-2": "test-val-2",
		"test-field-3": "test-val-3",
		"test-field-4": "test-val-4",
		"test-field-5": "test-val-5",
	}
	k, c, err := genKeyAndCert()
	if err != nil {
		t.Fatal("Failed to generate rsa key:", err.Error())
	}
	testIc := IssuerConfiguration{
		IssuerName:        "http://idp.test.com/metadata.php",
		IssuerServiceName: "test-idp",
		ValiditySeconds:   100,
		PrivateKey:        k,
		Certificate:       c,
	}
	testSAML, err := NewLegacySAML(testIc)
	if err != nil {
		t.Fatal("Failed to create saml object:", err.Error())
	}
	testFormatter := NewLegacyMapFormatter(testMap)
	assertion, err := testSAML.GenerateSamlAssertion(testFormatter)
	if err != nil {
		t.Fatal("Failed to create saml assertion:", err.Error())
	}
	t.Log(assertion)

	// validate
	v, err := ValidateLegacySamlAssertion(assertion, c)
	if err != nil {
		t.Fatal("Failed to validate saml assertion:", err.Error())
	}
	doc := etree.NewDocument()
	doc.SetRoot(v)
	str, err := doc.WriteToString()
	if err != nil {
		t.Fatal("Failed to write validated saml assertion to string", err.Error())
	}
	t.Log(str)
}
