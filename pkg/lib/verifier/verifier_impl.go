/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package verifier

//
// Implements 'Verifier' interface.
//

import (
	"intel-secl/v3/pkg/lib/host-connector/types"
	"github.com/pkg/errors"
)

type verifierImpl struct {
	certificates VerifierCertificates
	overallTrust bool
}

func (v *verifierImpl) Verify(hostManifest *types.HostManifest, signedFlavor *SignedFlavor, skipSignedFlavorVerification bool) (*TrustReport, error) {

	// default overall trust to true, change to falsed during rule evaluation
	v.overallTrust = true

	builder, err := getPolicyBuilder(hostManifest, signedFlavor)
	if err != nil {
		return nil, err
	}

	trustReport, err := v.applyPolicy(builder, hostManifest)
	if err != nil {
		return nil, err
	}

	return trustReport, nil
}

func (v *verifierImpl) applyPolicy(builder policyBuilder, hostManifest *types.HostManifest) (*TrustReport, error) {

	rules, err := builder.GetTrustRules()
	if err != nil {
		return nil, err
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

	for i, rule := range rules {
		result, err := rule.Apply(hostManifest)
		if err != nil {
			return nil, errors.Wrapf(err, "Error evaluating rule at index '%d", i)
		}

		if result.Trusted == false {
			v.overallTrust = false
		}

		results = append(results, *result)
	}

	return results, nil
}
