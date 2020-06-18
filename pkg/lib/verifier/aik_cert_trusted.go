/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package verifier

//
// Rule that validates the host manifest's aik.
//

import (
	"crypto/x509"
	"fmt"
	"time"
	"github.com/pkg/errors"
	"github.com/intel-secl/intel-secl/v3/pkg/lib/host-connector/types"
	"github.com/intel-secl/intel-secl/v3/pkg/lib/flavor/common"
)

func newAikCertificateTrusted(privacyCACertificates *x509.CertPool, marker common.FlavorPart) (rule, error) {

	if privacyCACertificates == nil {
		return nil, errors.New("The privacy CAs cannot be nil")
	}

	rule := aikCertTrusted{
		privacyCACertificates: privacyCACertificates,
		marker: marker,
	}
	return &rule, nil
}

type aikCertTrusted struct {
	privacyCACertificates *x509.CertPool
	marker                common.FlavorPart
}

// - if the aik is not present in the manifest, raise 'aik missing' fault
// - if the host cert is not valid, raise 'aik expired' or 'aik not yet valid' faults
// - check the host's aik against the trustedAuthority certs and raise 'not trusted' fault
//   if none are valid
func (rule *aikCertTrusted) Apply(hostManifest *types.HostManifest) (*RuleResult, error) {

	var fault *Fault
	result := RuleResult{}
	result.Trusted = true // default to true, set to false when fault encountered
	result.Rule.Name = "com.intel.mtwilson.core.verifier.policy.rule.AikCertificateTrusted"
	result.Rule.Markers = append(result.Rule.Markers, rule.marker)

	if len(hostManifest.AIKCertificate) == 0 {
		fault = &Fault{
			Name:        FaultAikCertificateMissing,
			Description: "Host report does not include an AIK certificate",
		}
	} else {

		aik, err := hostManifest.GetAIKCertificate()
		if err != nil {
			return nil, errors.Wrap(err, "Could not retrive the HostManifest's AIK to validate rule AikCertificateTrusted")
		}

		if time.Now().After(aik.NotAfter) {
			fault = &Fault{
				Name:        FaultAikCertificateExpired,
				Description: fmt.Sprintf("AIK certificate not valid after '%s'", aik.NotAfter),
			}
		} else if time.Now().Before(aik.NotBefore) {
			fault = &Fault{
				Name:        FaultAikCertificateNotYetValid,
				Description: fmt.Sprintf("AIK certificate not valid before '%s'", aik.NotBefore),
			}
		} else {
			opts := x509.VerifyOptions{
				Roots: rule.privacyCACertificates,
			}

			_, err := aik.Verify(opts)
			if err != nil {
				fault = &Fault{
					Name:        FaultAikCertificateNotTrusted,
					Description: "AIK certificate is not signed by any trusted CA",
				}
			}
		}
	}

	if fault != nil {
		result.Faults = append(result.Faults, *fault)
	}

	return &result, nil
}
