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
)

type aikCertTrusted struct {
	trustedAuthorityCerts *x509.CertPool
	result                RuleResult
	marker                string
}

const (
	FaultAikCertificateMissing = "com.intel.mtwilson.core.verifier.policy.rule.AikCertificateMissing"
	FaultAikCertificateExpired = "com.intel.mtwilson.core.verifier.policy.fault.AikCertificateExpired"
	FaultAikCertificateNotYetValid = "com.intel.mtwilson.core.verifier.policy.fault.AikCertificateNotYetValid"
	FaultAikCertificateNotTrusted = "com.intel.mtwilson.core.verifier.policy.fault.AikCertificateNotTrusted"
)

func newAikCertificateTrusted(trustedAuthorityCerts *x509.CertPool, marker string) (rule, error) {
	// TODO: make sure at least one cert is profiled in the pool...

	if len(marker) == 0 {
		return nil, errors.New("The rule 'marker' must be provided")
	}

	rule := aikCertTrusted{
		trustedAuthorityCerts: trustedAuthorityCerts,
		marker: marker,
	}
	return &rule, nil
}

// - if the aik is not present in the manifest, raise 'aik missing' fault
// - if the host cert is not valid, raise 'aik expired' or 'aik not yet valid' faults
// - check the host's aik against the trustedAuthority certs and raise 'not trusted' fault
//   if none are valid
func (rule *aikCertTrusted) Apply(hostManifest *types.HostManifest) (*RuleResult, error) {

	var fault *Fault
	rule.result.Trusted = true // default to true, set to false when fault encountered
	rule.result.Rule.Name = "com.intel.mtwilson.core.verifier.policy.rule.AikCertificateTrusted"
	rule.result.Rule.Markers = append(rule.result.Rule.Markers, rule.marker)

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
				Roots: rule.trustedAuthorityCerts,
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
		rule.result.Faults = append(rule.result.Faults, *fault)
		rule.result.Trusted = false
	}

	return &rule.result, nil
}
