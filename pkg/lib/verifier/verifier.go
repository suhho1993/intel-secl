/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package verifier

//
// Contains 'public' structures, inerfaces and factory methods available to external
// packages.
//

import (
	"crypto/x509"
	"github.com/intel-secl/intel-secl/v3/pkg/lib/host-connector/types"
)

type VerifierCertificates struct {
	PrivacyCaCertificates    *x509.CertPool
	AssetTagCaCertificate    *x509.Certificate
	FlavorSigningCertificate *x509.Certificate
	FlavorCaCertificate      *x509.Certificate
}

type Verifier interface {
	Verify(hostManifest *types.HostManifest, signedFlavor *SignedFlavor, skipFlavorSignatureVerification bool) (*TrustReport, error)
}

func NewVerifier(verifierCertificates VerifierCertificates) (Verifier, error) {
	// TODO: validate certificates
	return &verifierImpl{verifierCertificates: verifierCertificates}, nil
}
