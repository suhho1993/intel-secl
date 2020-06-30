package setup

import (
	"os"
	"testing"
)

func TestSign(t *testing.T) {
	testSign := SelfSignedCert{
		KeyFile:  "test.pem",
		CertFile: "test.crt",
	}
	if err := testSign.Run(); err != nil {
		t.Error("Failed to generate self-signed key and cert", err.Error())
	}
	if err := testSign.Validate(); err != nil {
		t.Error("Failed to validate self-signed key and cert", err.Error())
	}

	// cleanup
	_ = os.Remove("test.pem")
	_ = os.Remove("test.crt")
}
