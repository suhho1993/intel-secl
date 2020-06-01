/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */

package hvs

import (
	"github.com/google/uuid"
	cf "github.com/intel-secl/intel-secl/v3/pkg/lib/flavor/common"
)

type FlavorgroupCollection struct {
	Flavorgroups []*FlavorGroup `json:"flavorgroups" xml:"flavorgroup"`
}

type FlavorGroup struct {
	ID                          uuid.UUID                    `json:"id,omitempty"`
	Name                        string                       `json:"name,omitempty"`
	FlavorIds                   []string                     `json:"flavorIds,omitempty"`
	Flavors                     []Flavor                     `json:"flavors,omitempty"`
	FlavorMatchPolicyCollection *FlavorMatchPolicyCollection `json:"flavor_match_policy_collection,omitempty"`
}

type FlavorMatchPolicyCollection struct {
	FlavorMatchPolicies []FlavorMatchPolicy `json:"flavor_match_policies,omitempty"`
}

type FlavorMatchPolicy struct {
	FlavorPart  cf.FlavorPart  `json:"flavor_part,omitempty"`
	MatchPolicy MatchPolicy `json:"match_policy,omitempty"`
}

type MatchPolicy struct {
	MatchType MatchType      `json:"match_type,omitempty"`
	Required  PolicyRequired `json:"required,omitempty"`
}

type MatchType string

const (
	AnyOf  MatchType = "ANY_OF"
	AllOf  MatchType = "ALL_OF"
	Latest MatchType = "LATEST"
)
func (mt MatchType) String() string {
	return mt.String()
}

type PolicyRequired string

const (
	Required            PolicyRequired = "REQUIRED"
	RequiredIfDefined   PolicyRequired = "REQUIRED_IF_DEFINED"
)
func (req PolicyRequired) String() string {
	return req.String()
}
