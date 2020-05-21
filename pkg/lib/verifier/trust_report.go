/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package verifier

//
// TrustReport model returned by verifier.Verify()
//

import (
	"github.com/google/uuid"
	"github.com/intel-secl/intel-secl/v3/pkg/lib/host-connector/types"
)

type TrustReport struct {
	PolicyName string       `json:"policy_name"`
	Results    []RuleResult `json:"rules"`
	Trusted    bool         `json:"trusted"`
}

type RuleResult struct {
	Rule     RuleInfo   `json:"rule"`
	FlavorId *uuid.UUID `json:"flavor_id,omitempty"`
	Faults   []Fault    `json:"faults"`
	Trusted  bool       `json:"trusted"`
}

type RuleInfo struct {
	Name        string     `json:"rule_name"`
	Markers     []string   `json:"markers"`
	ExpectedPcr *types.Pcr `json:"expected_pcr,omitempty"`
}

type Fault struct {
	Name              string           `json:"fault_name"`
	Description       string           `json:"description"`
	PcrIndex          *types.PcrIndex  `json:"pcr_index,omitempty"`
	ExpectedPcrValue  *string          `json:"expected_value,omitempty"`
	ActualPcrValue    *string          `json:"actual_value,omitempty"`
	MissingEntries    []types.EventLog `json:"missing_entries,omitempty"`
	UnexpectedEntries []types.EventLog `json:"unexpected_entries,omitempty"`
}
