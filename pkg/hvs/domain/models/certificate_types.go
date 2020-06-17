/*
* Copyright (C) 2020 Intel Corporation
* SPDX-License-Identifier: BSD-3-Clause
 */
package models

// CaCertTypes is an enumerated set of ca certificate types
type CaCertTypes string

const (
	CaCertTypesRootCa        CaCertTypes = "root"
	CaCertTypesEndorsementCa CaCertTypes = "endorsement"
	CaCertTypesEkCa          CaCertTypes = "ek"
	CaCertTypesPrivacyCa     CaCertTypes = "privacy"
	CaCertTypesAikCa         CaCertTypes = "aik"
	CaCertTypesTagCa         CaCertTypes = "tag"
)

func (cct CaCertTypes) String() string {
	return string(cct)
}

// GetCaCertTypes returns a list of ca certificate types as strings
func GetCaCertTypes() []CaCertTypes {
	return []CaCertTypes{CaCertTypesRootCa,
		CaCertTypesEndorsementCa,
		CaCertTypesEkCa,
		CaCertTypesPrivacyCa,
		CaCertTypesAikCa,
		CaCertTypesTagCa}
}

// CaCertTypes is an enumerated set of certificate types
type CertTypes string

const (
	CertTypesSaml          CertTypes = "saml"
	CertTypesTls           CertTypes = "tls"
)

func (ct CertTypes) String() string {
	return string(ct)
}

func GetCertTypes() []CertTypes {
	return []CertTypes{CertTypesSaml, CertTypesTls}
}

// Get list of certificate types including ca certificate types
func GetSupportedCerts() []string {
	var supportedCerts []string
	for _, c := range GetCaCertTypes() {
		supportedCerts = append(supportedCerts, c.String())
	}
	for _, c := range GetCertTypes() {
		supportedCerts = append(supportedCerts, c.String())
	}
	return supportedCerts
}

// Validate if certificate type is present in all certificate types including ca certificate types except root
func IsValidCertType(certType string) bool {
	for _, c := range GetSupportedCerts() {
		if c != CaCertTypesRootCa.String() && c == certType {
			return true
		}
	}
	return false
}