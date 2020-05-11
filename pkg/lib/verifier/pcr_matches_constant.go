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

	ruleResult := RuleResult{}
	ruleResult.Trusted = true // default to true, set to false in fault logic
	ruleResult.Rule.Name = "PCR Matches Constant"
	ruleResult.Rule.ExpectedPcr = rule.expectedPcr
	ruleResult.Rule.Markers = []string{"PLATFORM"}

	// TODO: is the host manifest optional (what about 'missing manifest fault'?)
	// if hostManifest.PcrManifest == nil {
	// }

	actualPcr, err := hostManifest.PcrManifest.GetPcrValue(rule.expectedPcr.PcrBank, rule.expectedPcr.Index)
	if err != nil {
		return nil, err
	}

	if actualPcr == nil {
		ruleResult.addPcrValueMissingFault(rule.expectedPcr.PcrBank, rule.expectedPcr.Index)
	} else if rule.expectedPcr.Value != actualPcr.Value {
		ruleResult.addPcrValueMismatchFault(rule.expectedPcr.Index, rule.expectedPcr, actualPcr)
	}

	return &ruleResult, nil
}
