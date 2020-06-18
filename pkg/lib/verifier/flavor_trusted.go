/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package verifier

import (
	"crypto/rsa"
	"crypto/x509"
	"fmt"
	"github.com/google/uuid"
	"github.com/intel-secl/intel-secl/v3/pkg/lib/host-connector/types"
	"github.com/intel-secl/intel-secl/v3/pkg/model/hvs"
	"github.com/intel-secl/intel-secl/v3/pkg/lib/flavor/common"
)

func newFlavorTrusted(signedFlavor *hvs.SignedFlavor, flavorSigningCertificate *x509.Certificate, flavorCaCertificates *x509.CertPool, marker common.FlavorPart) (rule, error) {

	return &flavorTrusted {
		signedFlavor: signedFlavor,
		flavorId: signedFlavor.Flavor.Meta.ID,
		flavorSigningCertificate: flavorSigningCertificate,
		flavorCaCertificates: flavorCaCertificates,
		marker: marker,
	}, nil
}

type flavorTrusted struct {
	signedFlavor             *hvs.SignedFlavor
	flavorId                 uuid.UUID		// KWT: remove after flavors are updated to use uuids
	flavorSigningCertificate *x509.Certificate
	flavorCaCertificates     *x509.CertPool
	marker                   common.FlavorPart
}

// - If the flavor does not have a signature create a FaultFlavorSignatureMissing
// - If the flavor's signature does not verify with the signing certificate and CAs, create a 
//   FaultFlavorSignatureNotTrusted
// - If any errors occur during verification, create FaultFlavorSignatureVerificationFailed
func (rule *flavorTrusted) Apply(hostManifest *types.HostManifest) (*RuleResult, error) {

	result := RuleResult{}
	result.Trusted = true
	result.Rule.Name = "com.intel.mtwilson.core.verifier.policy.rule.FlavorTrusted"
	result.Rule.Markers = append(result.Rule.Markers, rule.marker)
	
	if len(rule.signedFlavor.Signature) == 0 {
		fault := Fault {
			Name: FaultFlavorSignatureMissing,
			Description: fmt.Sprintf("Signature is missing for flavor with id %s", rule.flavorId),
		}

		result.Faults = append(result.Faults, fault)
	} else if rule.flavorSigningCertificate == nil {
		log.Error("FlavorSignatureVerificationFailed fault: The flavor signing certificate was not provided")
		result.Faults = append(result.Faults, newFlavorSignatureVerificationFailed(rule.flavorId))
	} else if rule.flavorCaCertificates == nil {
		log.Error("FlavorSignatureVerificationFailed fault: The flavor signing CA certificates were not provided")
		result.Faults = append(result.Faults, newFlavorSignatureVerificationFailed(rule.flavorId))
	} else {

		// verify the cert and ca...
		opts := x509.VerifyOptions {
			Roots: rule.flavorCaCertificates,
		}

		_, err := rule.flavorSigningCertificate.Verify(opts)
		if err != nil {
			log.Error("FlavorSignatureVerificationFailed fault: The flavor signing certificate did not validate against the CAs")
			result.Faults = append(result.Faults, newFlavorSignatureVerificationFailed(rule.flavorId))
			return &result, nil
		}

		// get the public key for verifying the signed flavor
		var ok bool
		var publicKey *rsa.PublicKey
		if publicKey, ok = rule.flavorSigningCertificate.PublicKey.(*rsa.PublicKey); !ok {
			log.Error("FlavorSignatureVerificationFailed fault: Could not get the flavor signing certificate's public key")
			result.Faults = append(result.Faults, newFlavorSignatureVerificationFailed(rule.flavorId))
			return &result, nil
		}

		err = rule.signedFlavor.Verify(publicKey)
		if err != nil {
			fault := Fault {
				Name: FaultFlavorSignatureNotTrusted,
				Description: fmt.Sprintf("Signature is not trusted for flavor with id %s", rule.flavorId),
			}
	
			result.Faults = append(result.Faults, fault)		
		}
	}

	return &result, nil	
}
