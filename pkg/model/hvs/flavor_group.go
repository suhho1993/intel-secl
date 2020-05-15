/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */

package hvs

type FlavorgroupCollection struct {
	Flavorgroups []FlavorGroup `json:"flavorgroups" xml:"flavorgroup"`
}

type FlavorGroup struct {
	Id                          string                      `json:"id,omitempty"`
	Name                        string                      `json:"name,omitempty"`
	FlavorIds                   []string                    `json:"flavorIds,omitempty"`
	Flavors                     []string                    `json:"flavors,omitempty"` //TODO: Update type on flavor library merge
	FlavorMatchPolicyCollection *FlavorMatchPolicyCollection `json:"flavor_match_policy_collection,omitempty"`
}

type FlavorMatchPolicyCollection struct {
	FlavorMatchPolicies []FlavorMatchPolicy `json:"flavor_match_policies,omitempty"`
}

type FlavorMatchPolicy struct {
	FlavorPart  FlavorPart  `json:"flavor_part,omitempty"`
	MatchPolicy MatchPolicy `json:"match_policy,omitempty"`
}

type MatchPolicy struct {
	MatchType MatchType `json:"match_type,omitempty"`
	Required  Required  `json:"required,omitempty"`
}

type MatchType string
const (
	ANY_OF MatchType = "ANY_OF"
	ALL_OF           = "ALL_OF"
	LATEST           = "LATEST"
)
func (mt MatchType) String() string {
	return mt.String()
}

type Required string
const (
	REQUIRED Required     = "REQUIRED"
	REQUIRED_IF_DEFINED   = "REQUIRED_IF_DEFINED"
)
func (req Required) String() string {
	return req.String()
}
