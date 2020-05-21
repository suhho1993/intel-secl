/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package verifier

import (
	"fmt"
	"github.com/pkg/errors"
	"github.com/intel-secl/intel-secl/v3/pkg/lib/host-connector/types"
)

const (
	FaultPcrEventLogInvalid = "com.intel.mtwilson.core.verifier.policy.fault.PcrEventLogInvalid"
)

func newPcrEventLogIntegrity(expectedPcr *types.Pcr) (rule, error) {
	if expectedPcr == nil {
		return nil, errors.New("The expected pcr cannot be nil")
	}

	rule := pcrEventLogIntegrity{expectedPcr: expectedPcr}
	return &rule, nil
}

type pcrEventLogIntegrity struct {
	expectedPcr *types.Pcr
}

// - If the hostmanifest's PcrManifest is not present, create PcrManifestMissing fault.
// - If the hostmanifest does not contain a pcr at 'expected' bank/index, create a PcrValueMissing fault.
// - If the hostmanifest does not have an event log at 'expected' bank/index, create a 
//   PcrEventLogMissing fault.
// - Otherwise, replay the hostmanifest's event log at 'expected' bank/index and verify the 
//   the cumulative hash matches the 'expected' pcr's 'value'.  If not, crete a PcrEventLogInvalid fault.
func (rule *pcrEventLogIntegrity) Apply(hostManifest *types.HostManifest) (*RuleResult, error) {

	var fault *Fault
	result := RuleResult{}
	result.Trusted = true
	result.Rule.Name = "com.intel.mtwilson.core.verifier.policy.rule.PcrEventLogIntegrity"

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
	} else {
		actualEventLog, err := hostManifest.PcrManifest.PcrEventLogMap.GetEventLog(rule.expectedPcr.PcrBank, rule.expectedPcr.Index)
		if err != nil {
			return nil, err
		}
	
		if actualEventLog == nil {
			fault = newPcrEventLogMissingFault(rule.expectedPcr.Index)
		} else {
			calculatedValue, err := actualEventLog.Replay()
			if err != nil {
				return nil, err
			}

			if calculatedValue != rule.expectedPcr.Value {
				fault = &Fault{
					Name:        FaultPcrEventLogInvalid,
					Description: fmt.Sprintf("PCR %d Event Log is invalid", rule.expectedPcr.Index),
					PcrIndex: &rule.expectedPcr.Index,
				}
			}
		}
	}

	if fault != nil {
		result.Faults = append(result.Faults, *fault)
		result.Trusted = false
	}

	return &result, nil
}