package saml

import (
	"crypto/rsa"
	"crypto/x509"
	"time"
)

type IssuerConfiguration struct {
	PrivateKey        *rsa.PrivateKey
	Certificate       *x509.Certificate
	IssuerName        string
	IssuerServiceName string
	ValiditySeconds   int
}

type SamlAssertion struct {
	Assertion   string
	ExpiryTime  time.Time
	CreatedTime time.Time
}
