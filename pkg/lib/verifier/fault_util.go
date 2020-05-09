/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package verifier

//
// This file contains utility functions that support a 'rules' ability to add 'faults'
// to a 'RuleResult'.
//

import (
	"fmt"
	"intel-secl/v3/pkg/lib/host-connector/types"
)

func (result *RuleResult) addPcrValueMissingFault(bank types.SHAAlgorithm, pcrIndex types.PcrIndex) error {
	fault := Fault{
		Name:        "com.intel.mtwilson.core.verifier.policy.fault.PcrValueMissing",
		Description: fmt.Sprintf("Host report does not include required PCR %d, bank %s", pcrIndex, bank),
		PcrIndex:    &pcrIndex,
	}

	result.Faults = append(result.Faults, fault)
	result.Trusted = false

	return nil
}

func (result *RuleResult) addPcrValueMismatchFault(pcrIndex types.PcrIndex, expectedPcr *types.Pcr, actualPcr *types.Pcr) error {
	expectedValue := string(expectedPcr.Value)
	actualValue := string(actualPcr.Value)

	fault := Fault{
		Name:             "com.intel.mtwilson.core.verifier.policy.fault.PcrValueMismatch" + string(actualPcr.PcrBank),
		Description:      fmt.Sprintf("Host PCR %d with value '%s' does not match expected value '%s'", pcrIndex, actualValue, expectedValue),
		PcrIndex:         &pcrIndex,
		ExpectedPcrValue: &expectedValue,
		ActualPcrValue:   &actualValue,
	}

	result.Faults = append(result.Faults, fault)
	result.Trusted = false

	return nil
}
