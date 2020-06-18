/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package verifier

//
// Implements 'Verifier' interface.
//

import (
	"github.com/intel-secl/intel-secl/v3/pkg/lib/host-connector/types"
	"github.com/intel-secl/intel-secl/v3/pkg/model/hvs"
	"github.com/intel-secl/intel-secl/v3/pkg/lib/flavor/common"
	"github.com/pkg/errors"
)

type verifierImpl struct {
	signedFlavor         *hvs.SignedFlavor
	verifierCertificates VerifierCertificates
	overallTrust         bool
}

func (v *verifierImpl) Verify(hostManifest *types.HostManifest, signedFlavor *hvs.SignedFlavor, skipSignedFlavorVerification bool) (*TrustReport, error) {

	var err error

	if hostManifest == nil {
		return nil, errors.New("The host manifest cannot be nil")
	}

	if signedFlavor == nil {
		return nil, errors.New("The signed flavor cannot be nil")
	}

	v.signedFlavor = signedFlavor

	// default overall trust to true, change to falsed during rule evaluation
	v.overallTrust = true

	builder, err := getPolicyBuilder(v.verifierCertificates, hostManifest, v.signedFlavor)
	if err != nil {
		return nil, err
	}

	trustReport, err := v.applyPolicy(builder, hostManifest, skipSignedFlavorVerification)
	if err != nil {
		return nil, err
	}

	return trustReport, nil
}

func (v *verifierImpl) applyPolicy(builder policyBuilder, hostManifest *types.HostManifest, skipSignedFlavorVerification bool) (*TrustReport, error) {

	rules, err := builder.GetTrustRules()
	if err != nil {
		return nil, err
	}

	// if flavor signing verification is enabled, add the FlavorTrusted rule
	if !skipSignedFlavorVerification {

		var flavorPart common.FlavorPart
		err := (&flavorPart).Parse(v.signedFlavor.Flavor.Meta.Description.FlavorPart)
		if err != nil {
			return nil, errors.Wrap(err, "Could not retrieve flavor part name")
		}
	
		flavorTrusted, err := newFlavorTrusted(v.signedFlavor,
		                                       v.verifierCertificates.FlavorSigningCertificate, 
		                                       v.verifierCertificates.FlavorCACertificates,
		                                       flavorPart)

		if err != nil {
			return nil, err
		}

		rules = append(rules, flavorTrusted)
	}

	results, err := v.applyTrustRules(hostManifest, rules)
	if err != nil {
		return nil, err
	}

	trustReport := TrustReport{
		PolicyName: builder.GetName(),
		Results:    results,
		Trusted:    v.overallTrust,
	}

	return &trustReport, nil
}

func (v *verifierImpl) applyTrustRules(hostManifest *types.HostManifest, rules []rule) ([]RuleResult, error) {
	var results []RuleResult

	for _, rule := range rules {

		log.Debugf("Applying verifier rule %T", rule)
		result, err := rule.Apply(hostManifest)
		if err != nil {
			return nil, errors.Wrapf(err, "Error ocrurred applying rule type '%T'", rule)
		}

		// if 'Apply' returned a result with any faults, then the 
		// rule is not trusted
		if len(result.Faults) > 0 {
			result.Trusted = false
			v.overallTrust = false
		}

		// assign the flavor id to all rules
		result.FlavorId = v.signedFlavor.Flavor.Meta.ID

		results = append(results, *result)
	}

	return results, nil
}
