/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package verifier

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"math/big"
	"testing"
	"time"
	"github.com/intel-secl/intel-secl/v3/pkg/lib/host-connector/types"
	"github.com/stretchr/testify/assert"
)

func newCertificateTemplate() (*x509.Certificate, error) {

	template := x509.Certificate{
		SerialNumber: big.NewInt(2020),
		Subject: pkix.Name{
			Organization:  []string{"Intel"},
			Country:       []string{"US"},
			Province:      []string{""},
			Locality:      []string{"Santa Clara"},
			StreetAddress: []string{"2200 Mission College Blvd."},
			PostalCode:    []string{"95054"},
		},

		NotBefore: time.Now().AddDate(-1, 0, 0),
		NotAfter: time.Now().AddDate(1, 0, 0),
	
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	return &template, nil

}

func newCACertificate() ([]byte, *rsa.PrivateKey, error) {

	caCertificate := x509.Certificate{
		SerialNumber: big.NewInt(2020),
		Subject: pkix.Name{
			Organization:  []string{"Intel"},
			Country:       []string{"US"},
			Province:      []string{""},
			Locality:      []string{"Santa Clara"},
			StreetAddress: []string{"2200 Mission College Blvd."},
			PostalCode:    []string{"95054"},
		},

		NotBefore: time.Now().AddDate(-1, 0, 0),
		NotAfter: time.Now().AddDate(1, 0, 0),

		IsCA:                  true,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	caPrivateKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return nil, nil, err
	}

	caBytes, err := x509.CreateCertificate(rand.Reader, &caCertificate, &caCertificate, &caPrivateKey.PublicKey, caPrivateKey)
	if err != nil {
		return nil, nil, err
	}

	caPemBytes := new(bytes.Buffer)
	pem.Encode(caPemBytes, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: caBytes,
	})

	return caPemBytes.Bytes(), caPrivateKey, nil
}


func getAikCertificateBytes(certificate *x509.Certificate, caPrivateKey *rsa.PrivateKey) ([]byte, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 999)
	if err != nil {
		return nil, err
	}

	// if the caPrivateKey was not provided, just self-sign the certificate
	if caPrivateKey == nil {
		caPrivateKey = privateKey
	}

	aikBytes, err := x509.CreateCertificate(rand.Reader, certificate, certificate, &privateKey.PublicKey, caPrivateKey)
	if err != nil {
		return nil, err
	}

	return aikBytes, nil
}

func TestAikCertificateMissingFault(t *testing.T) {

	// this test does not need ca certificates
	trustedAuthorityCerts := x509.CertPool{}

	// do not provide the aik certificate
	hostManifest := types.HostManifest{
		AIKCertificate : "",
	}

	rule, err := newAikCertificateTrusted(&trustedAuthorityCerts, "PLATFORM")
	assert.NoError(t, err)

	result, err := rule.Apply(&hostManifest)
	assert.NoError(t, err)
	assert.NotNil(t, result)
	assert.Equal(t, len(result.Faults), 1)
	assert.Equal(t, result.Faults[0].Name, FaultAikCertificateMissing)
	t.Logf("Fault description: %s", result.Faults[0].Description)
}

func TestAikCertificateExpiredFault(t *testing.T) {

	// this test does not need ca certificates
	trustedAuthorityCerts := x509.CertPool{}

	aikCertificate, err := newCertificateTemplate()
	assert.NoError(t, err)

	// set the 'before' to two years ago -- ok
	// set the 'after' to one year ago -- should cause in expired fault
	aikCertificate.NotBefore = time.Now().AddDate(-2, 0, 0)
	aikCertificate.NotAfter = time.Now().AddDate(-1, 0, 0)

	aikBytes, err := getAikCertificateBytes(aikCertificate, nil)
	assert.NoError(t, err)
	
	hostManifest := types.HostManifest{
		AIKCertificate : base64.StdEncoding.EncodeToString([]byte(aikBytes)),
	}

	rule, err := newAikCertificateTrusted(&trustedAuthorityCerts, "PLATFORM")
	assert.NoError(t, err)

	result, err := rule.Apply(&hostManifest)
	assert.NoError(t, err)
	assert.NotNil(t, result)
	assert.Equal(t, len(result.Faults), 1)
	assert.Equal(t, result.Faults[0].Name, FaultAikCertificateExpired)
	t.Logf("Fault description: %s", result.Faults[0].Description)
}

func TestAikCertificateNotBeforeFault(t *testing.T) {

	// this test does not need ca certificates
	trustedAuthorityCerts := x509.CertPool{}

	aikCertificate, err := newCertificateTemplate()
	assert.NoError(t, err)

	// set the 'before' to two years in the future -- should cause a 'not yet valid' fault
	// set the 'after' to two years in the future -- ok
	aikCertificate.NotBefore = time.Now().AddDate(1, 0, 0)
	aikCertificate.NotAfter = time.Now().AddDate(2, 0, 0)

	aikBytes, err := getAikCertificateBytes(aikCertificate, nil)
	assert.NoError(t, err)

	hostManifest := types.HostManifest{
		AIKCertificate : base64.StdEncoding.EncodeToString([]byte(aikBytes)),
	}

	rule, err := newAikCertificateTrusted(&trustedAuthorityCerts, "PLATFORM")
	assert.NoError(t, err)

	result, err := rule.Apply(&hostManifest)
	assert.NoError(t, err)
	assert.NotNil(t, result)
	assert.Equal(t, len(result.Faults), 1)
	assert.Equal(t, result.Faults[0].Name, FaultAikCertificateNotYetValid)
	t.Logf("Fault description: %s", result.Faults[0].Description)
}

func TestAikTrustedNotTrustedFault(t *testing.T) {

	// without any trusted certs, we expect the "Not Trusted" fault
	trustedAuthorityCerts := x509.CertPool{}

	aikCertificate, err := newCertificateTemplate()
	assert.NoError(t, err)

	aikBytes, err := getAikCertificateBytes(aikCertificate, nil)
	assert.NoError(t, err)

	hostManifest := types.HostManifest{
		AIKCertificate : base64.StdEncoding.EncodeToString([]byte(aikBytes)),
	}

	rule, err := newAikCertificateTrusted(&trustedAuthorityCerts, "PLATFORM")
	assert.NoError(t, err)

	result, err := rule.Apply(&hostManifest)
	assert.NoError(t, err)
	assert.NotNil(t, result)
	assert.Equal(t, len(result.Faults), 1)
	assert.Equal(t, result.Faults[0].Name, FaultAikCertificateNotTrusted)
	t.Logf("Fault description: %s", result.Faults[0].Description)
}

func TestAikTrustedValid(t *testing.T) {

	caPemBytes, caPrivateKey, err := newCACertificate()
	assert.NoError(t, err)

	trustedAuthorityCerts := x509.NewCertPool()
	ok := trustedAuthorityCerts.AppendCertsFromPEM(caPemBytes)
	assert.True(t, ok)

	aikCertificate, err := newCertificateTemplate()
	assert.NoError(t, err)

	aikBytes, err := getAikCertificateBytes(aikCertificate, caPrivateKey)
	assert.NoError(t, err)

	hostManifest := types.HostManifest{
		AIKCertificate : base64.StdEncoding.EncodeToString([]byte(aikBytes)),
	}

	rule, err := newAikCertificateTrusted(trustedAuthorityCerts, "PLATFORM")
	assert.NoError(t, err)

	result, err := rule.Apply(&hostManifest)
	assert.NoError(t, err)
	assert.NotNil(t, result)
	assert.Equal(t, len(result.Faults), 0)
}