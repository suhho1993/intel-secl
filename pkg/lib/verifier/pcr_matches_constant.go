/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package verifier

//
// Rule that compares the 'expected' PCR with the value stored in the host manifest.
//

import (
	"github.com/pkg/errors"
	"github.com/intel-secl/intel-secl/v3/pkg/lib/host-connector/types"
)

type pcrMatchesConstant struct {
	expectedPcr *types.Pcr
}

func newPcrMatchesConstant(expectedPcr *types.Pcr) (rule, error) {
	if expectedPcr == nil {
		return nil, errors.New("The expected PCR cannot be nil")
	}

	if len(expectedPcr.Value) == 0 {
		return nil, errors.New("The expected PCR cannot have an empty value")
	}

	rule := pcrMatchesConstant{expectedPcr: expectedPcr}
	return &rule, nil
}

func (rule *pcrMatchesConstant) Apply(hostManifest *types.HostManifest) (*RuleResult, error) {

	var fault *Fault
	result := RuleResult{}
	result.Trusted = true // default to true, set to false in fault logic
	result.Rule.Name = "com.intel.mtwilson.core.verifier.policy.rule.PcrMatchesConstant"
	result.Rule.ExpectedPcr = rule.expectedPcr
	result.Rule.Markers = []string{"PLATFORM"} // KWT???

	// KWT: TBD -- this is a structure in the host manifest and is always present, suggest
	// we change it to an optional pointer in host-connector
	// if hostManifest.PcrManifest == nil {
	//     fault = newPcrManifestMissing() 	
	// } else  {

	actualPcr, err := hostManifest.PcrManifest.GetPcrValue(rule.expectedPcr.PcrBank, rule.expectedPcr.Index)
	if err != nil {
		return nil, err
	}

	if actualPcr == nil {
		fault = newPcrValueMissingFault(rule.expectedPcr.PcrBank, rule.expectedPcr.Index)
	} else if rule.expectedPcr.Value != actualPcr.Value {
		fault = newPcrValueMismatchFault(rule.expectedPcr.Index, rule.expectedPcr, actualPcr)
	}

	if fault != nil {
		result.Faults = append(result.Faults, *fault)
		result.Trusted = false
	}

	return &result, nil
}
