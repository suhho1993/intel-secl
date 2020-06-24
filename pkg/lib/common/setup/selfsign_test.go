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
		t.Error("Failed to generate selfsigned key and cert", err.Error())
	}
	if err := testSign.Validate(); err != nil {
		t.Error("Failed to validate selfsigned key and cert", err.Error())
	}
	// t.Cleanup is go 1.14 only
	t.Cleanup(func() {
		os.Remove("test.pem")
		os.Remove("test.crt")
	})
}
