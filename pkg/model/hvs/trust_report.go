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
	"github.com/intel-secl/intel-secl/v3/pkg/lib/flavor/common"
	"github.com/intel-secl/intel-secl/v3/pkg/lib/host-connector/types"
	ta "github.com/intel-secl/intel-secl/v3/pkg/model/ta"
)

type TrustReport struct {
	PolicyName string               `json:"policy_name"`
	Results    []RuleResult         `json:"results"`
	Trusted    bool                 `json:"trusted"`
	HostManifest types.HostManifest `json:"host_manifest"`
}

type RuleResult struct {
	Rule     RuleInfo  `json:"rule"`
	FlavorId uuid.UUID `json:"flavor_id,omitempty"`
	Faults   []Fault   `json:"faults,omitempty"`
	Trusted  bool      `json:"trusted"`
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

func NewTrustReport(report TrustReport) *TrustReport {
	return &TrustReport{PolicyName: report.PolicyName, Results: report.Results, Trusted: report.Trusted}
}

func (t *TrustReport) IsTrusted() bool {
	return t.isTrustedForResults(t.Results)
}

func (t *TrustReport) IsTrustedForMarker(marker string) bool {
	return t.isTrustedForResults(t.GetResultsForMarker(marker))
}
func (t *TrustReport) isTrustedForResults(ruleResults []RuleResult) bool {
	if len(ruleResults) == 0 {
		return false // empty policy is not trusted;  like RequireAllEmptySet fault.
	}

	trusted := true

	for _, result := range ruleResults{
		trusted = trusted && result.Trusted
	}

	return trusted
}


func (t *TrustReport) GetResultsForMarker(marker string) []RuleResult {
	var ruleResults []RuleResult
	for _, result := range t.Results{
		markers := result.Rule.Markers
		if markers != nil{
			if find(markers, marker){
				ruleResults = append(ruleResults, result)
			}
		}
	}
	return ruleResults
}

func find(slice []common.FlavorPart, val string) bool {
	for _, item := range slice {
		if item.String() == val {
			return true
		}
	}
	return false
}