/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package rules

import (
	"crypto/x509"
	"fmt"
	"time"
	"github.com/pkg/errors"
	"github.com/intel-secl/intel-secl/v3/pkg/lib/host-connector/types"
	"github.com/intel-secl/intel-secl/v3/pkg/lib/flavor/model"
	"github.com/intel-secl/intel-secl/v3/pkg/lib/flavor/constants"
	"github.com/intel-secl/intel-secl/v3/pkg/lib/flavor/common"
	"github.com/intel-secl/intel-secl/v3/pkg/model/hvs"
)

func NewTagCertificateTrusted(trustedAuthorityCerts *x509.CertPool, attributeCertificate *model.X509AttributeCertificate) (Rule, error) {
	if trustedAuthorityCerts == nil {
		return nil, errors.New("The tag certificates cannot be nil")
	}

	rule := tagCertificateTrusted {
		trustedAuthorityCerts: trustedAuthorityCerts,
		attributeCertificate: attributeCertificate,
	}

	return &rule, nil
}

type tagCertificateTrusted struct {
	trustedAuthorityCerts *x509.CertPool
	attributeCertificate  *model.X509AttributeCertificate
}

// - If the X509AttributeCertificate is null, raise TagCertificateMissing fault.
// - Otherwise, verify the the attributeCert agains the list of CAs.
// - If the attributeCertificate is valid but has a 'NotBefore' value before 'today,
//   raise a TagCertificateNotYetValid fault.
// - If the attributeCertificate is valid but has a 'NotAfter' value after 'today,
//   raise a TagCertificateNotYetExpired fault.
func (rule *tagCertificateTrusted) Apply(hostManifest *types.HostManifest) (*hvs.RuleResult, error) {

	var fault *hvs.Fault
	result := hvs.RuleResult{}
	result.Trusted = true
	result.Rule.Name = "com.intel.mtwilson.core.verifier.policy.rule.TagCertificateTrusted"
	result.Rule.Markers = append(result.Rule.Markers, common.FlavorPartAssetTag)

	if rule.attributeCertificate == nil {
		fault = &hvs.Fault {
			Name: FaultTagCertificateMissing,
			Description: "Host trust policy requires tag validation but the tag certificate was not found",
		}
	} else {

		tagCertificate, err := x509.ParseCertificate(rule.attributeCertificate.Encoded)
		if err != nil {
			return nil, errors.Wrap(err, "Could not parse attribute certificate")
		}

		opts := x509.VerifyOptions{
			Roots: rule.trustedAuthorityCerts,
		}

		_, err = tagCertificate.Verify(opts)
		if err != nil {
			fault = &hvs.Fault{
				Name:        FaultTagCertificateNotTrusted,
				Description: "Tag certificate is not signed by any trusted CA",
			}
		} else {
			// check to see if the attribute certificate's 'not before' is before today...
			notBefore, err := time.Parse(constants.FlavorTimestampFormat, rule.attributeCertificate.NotBefore)
			if err != nil {
				return nil, errors.Wrapf(err, "Could not parse NotBefore from value '%s'", rule.attributeCertificate.NotBefore)
			}

			if time.Now().Before(notBefore) {
				fault = &hvs.Fault{
					Name:        FaultTagCertificateNotYetValid,
					Description: fmt.Sprintf("Tag certificate not valid before %s", rule.attributeCertificate.NotBefore),
				}
			}
			
			// check to see if teh attributes certificate's 'not after' is after today...
			notAfter, err := time.Parse(constants.FlavorTimestampFormat, rule.attributeCertificate.NotAfter)
			if err != nil {
				return nil, errors.Wrapf(err, "Could not parse NotAfter from value '%s'", rule.attributeCertificate.NotAfter)
			}

			if time.Now().After(notAfter) {
				fault = &hvs.Fault{
					Name:        FaultTagCertificateExpired,
					Description: fmt.Sprintf("Tag certificate not valid after %s", rule.attributeCertificate.NotAfter),
				}
			}

		}
	}

	if fault != nil {
		result.Faults = append(result.Faults, *fault)
	}

	return &result, nil
}