/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package hvs

//
// TrustReport model returned by verifier.Verify()
//

import (
	"github.com/google/uuid"
	"github.com/intel-secl/intel-secl/v3/pkg/lib/host-connector/types"
	"github.com/intel-secl/intel-secl/v3/pkg/lib/flavor/common"
	ta "github.com/intel-secl/intel-secl/v3/pkg/model/ta"
)

type TrustReport struct {
	PolicyName string       `json:"policy_name"`
	Results    []RuleResult `json:"rules"`
	Trusted    bool         `json:"trust"`
}

type RuleResult struct {
	Rule     RuleInfo   `json:"rule"`
	FlavorId uuid.UUID  `json:"flavor_id,omitempty"`
	Faults   []Fault    `json:"faults,omitempty"`
	Trusted  bool       `json:"trusted"`
}

type RuleInfo struct {
	Name                  string                   `json:"rule_name"`
	Markers               []common.FlavorPart      `json:"markers,omitempty"`
	ExpectedPcr           *types.Pcr               `json:"expected_pcr,omitempty"`
	FlavorID              *uuid.UUID               `json:"flavor_id,omitempty"`
	FlavorName            *string                  `json:"flavor_name,omitempty"`
	ExpectedValue         *string                  `json:"expected_value,omitempty"`
	ExpectedMeasurements  []ta.FlavorMeasurement   `json:"expected_measurements,omitempty"`
	ExpectedEventLogs     []types.EventLog         `json:"expected,omitempty"`
	ExpectedEventLogEntry *types.EventLogEntry     `json:"expected,omitempty"`
}

type Fault struct {
	Name                   string                   `json:"fault_name"`
	Description            string                   `json:"description"`
	PcrIndex               *types.PcrIndex          `json:"pcr_index,omitempty"`
	ExpectedPcrValue       *string                  `json:"expected_value,omitempty"`
	ActualPcrValue         *string                  `json:"actual_value,omitempty"`
	MissingEntries         []types.EventLog         `json:"missing_entries,omitempty"`
	UnexpectedEntries      []types.EventLog         `json:"unexpected_entries,omitempty"`
	FlavorId               *uuid.UUID               `json:"flavor_id,omitempty"`
	UnexpectedMeasurements []ta.FlavorMeasurement   `json:"unexpected_entries,omitempty"`
	MissingMeasurements    []ta.FlavorMeasurement   `json:"missing_entries,omitempty"`
	MismatchMeasurements   []ta.FlavorMeasurement   `json:"unexpected_entries,omitempty"`
	ExpectedValue          *string                  `json:"expected_value,omitempty"`   
	ActualValue            *string                  `json:"actual_value,omitempty"`
	MeasurementId          *string                  `json:"measurement_id,omitempty"`
	FlavorDigestAlg        *string                  `json:"flavor_digest_alg,omitempty"`
	MeasurementDigestAlg   *string                  `json:"measurement_digest_alg,omitempty"`
}