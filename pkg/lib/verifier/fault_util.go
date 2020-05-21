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
	"github.com/intel-secl/intel-secl/v3/pkg/lib/host-connector/types"
)

const (
	FaultPcrValueMissing                      = "com.intel.mtwilson.core.verifier.policy.fault.PcrValueMissing"
	FaultPcrValueMismatch                     = "com.intel.mtwilson.core.verifier.policy.fault.PcrValueMismatch"
	FaultPcrValueMismatchSHA1                 = FaultPcrValueMismatch + "SHA1"
	FaultPcrValueMismatchSHA256               = FaultPcrValueMismatch + "SHA256"
	FaultPcrEventLogMissingExpectedEntries    = "com.intel.mtwilson.core.verifier.policy.fault.PcrEventLogMissingExpectedEntries"
	FaultPcrEventLogMissing                   = "com.intel.mtwilson.core.verifier.policy.rule.PcrEventLogMissing"
	FaultPcrEventLogContainsUnexpectedEntries =  "com.intel.mtwilson.core.verifier.policy.fault.PcrEventLogContainsUnexpectedEntries"
)

func newPcrValueMissingFault(bank types.SHAAlgorithm, pcrIndex types.PcrIndex) *Fault {
	fault := Fault{
		Name:        FaultPcrValueMissing,
		Description: fmt.Sprintf("Host report does not include required PCR %d, bank %s", pcrIndex, bank),
		PcrIndex:    &pcrIndex,
	}

	return &fault
}

func newPcrValueMismatchFault(pcrIndex types.PcrIndex, expectedPcr *types.Pcr, actualPcr *types.Pcr) *Fault {

	fault := Fault{
		Name:             FaultPcrValueMismatch + string(actualPcr.PcrBank),
		Description:      fmt.Sprintf("Host PCR %d with value '%s' does not match expected value '%s'", pcrIndex, actualPcr.Value, expectedPcr.Value),
		PcrIndex:         &pcrIndex,
		ExpectedPcrValue: &expectedPcr.Value,
		ActualPcrValue:   &actualPcr.Value,
	}

	return &fault
}

func newPcrEventLogMissingExpectedEntries(eventLogEntry *types.EventLogEntry) *Fault {
	fault := Fault {
		Name: FaultPcrEventLogMissingExpectedEntries,
		Description: fmt.Sprintf("Module manifest for PCR %d missing %d expected entries", eventLogEntry.PcrIndex, len(eventLogEntry.EventLogs)),
		PcrIndex: &eventLogEntry.PcrIndex,
		MissingEntries: eventLogEntry.EventLogs,
	}

	return &fault
}

func newPcrEventLogMissingFault(pcrIndex types.PcrIndex) *Fault {
	return &Fault{
		Name:        FaultPcrEventLogMissing,
		Description: fmt.Sprintf("Host report does not include a PCR Event Log for PCR %d", pcrIndex),
		PcrIndex:    &pcrIndex,
	}
}

func newPcrEventLogContainsUnexpectedEntries(eventLogEntry *types.EventLogEntry) *Fault {
	fault := Fault {
		Name: FaultPcrEventLogContainsUnexpectedEntries,
		Description: fmt.Sprintf("Module manifest for PCR %d contains %d unexpected entries", eventLogEntry.PcrIndex, len(eventLogEntry.EventLogs)),
		PcrIndex: &eventLogEntry.PcrIndex,
		UnexpectedEntries: eventLogEntry.EventLogs,
	}

	return &fault
}