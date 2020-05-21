/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package verifier

import (
	"github.com/pkg/errors"
	"github.com/intel-secl/intel-secl/v3/pkg/lib/host-connector/types"
)

func newPcrEventLogIncludes(expectedEventLogEntry *types.EventLogEntry) (rule, error) {
	if expectedEventLogEntry == nil {
		return nil, errors.New("The expected event log cannot be nil")
	}

	rule := pcrEventLogIncludes{expectedEventLogEntry: expectedEventLogEntry}
	return &rule, nil
}

type pcrEventLogIncludes struct {
	expectedEventLogEntry *types.EventLogEntry
}

// - if the host manifest does not have any log entries, or it doesn't have any value
//   at the bank/index 'expected', raise "PcrEventLogMissing".
// - if the log at bank/index does not have the same events as 'expected', raise
//   "PcrEventLogMissingExpectedEntries".
func (rule *pcrEventLogIncludes) Apply(hostManifest *types.HostManifest) (*RuleResult, error) {

	var fault *Fault
	result := RuleResult{}
	result.Trusted = true
	result.Rule.Name = "com.intel.mtwilson.core.verifier.policy.rule.PcrEventLogIncludes"

	// TODO: Check presence of PcrManifest

	actualEventLog, err := hostManifest.PcrManifest.PcrEventLogMap.GetEventLog(rule.expectedEventLogEntry.PcrBank, rule.expectedEventLogEntry.PcrIndex)
	if err != nil {
		return nil, err
	}

	if actualEventLog == nil {
		fault = newPcrEventLogMissingFault(rule.expectedEventLogEntry.PcrIndex)
	} else {
		// subtract the 'actual' event log measurements from 'expected'.
		// if there are any left in 'expected', then 'actual' did not include all entries

		missingEvents, err := rule.expectedEventLogEntry.Subtract(actualEventLog)
		if err != nil {
			return nil, errors.Wrap(err, "Error subtracting event logs in pcr eventlog includes rule.")
		}

		if len(missingEvents.EventLogs) > 0 {
			fault = newPcrEventLogMissingExpectedEntries(missingEvents)
		}
	}

	if fault != nil {
		result.Faults = append(result.Faults, *fault)
		result.Trusted = false
	}

	return &result, nil
}