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
	ID                          uuid.UUID                   `json:"id,omitempty"`
	Name                        string                      `json:"name,omitempty"`
	FlavorIds                   []string                    `json:"flavorIds,omitempty"`
	Flavors                     []Flavor                    `json:"flavors,omitempty"`
	FlavorMatchPolicyCollection FlavorMatchPolicyCollection `json:"flavor_match_policy_collection,omitempty"`
}

type FlavorMatchPolicyCollection struct {
	FlavorMatchPolicies []FlavorMatchPolicy `json:"flavor_match_policies,omitempty"`
}

type FlavorMatchPolicy struct {
	FlavorPart  cf.FlavorPart `json:"flavor_part,omitempty"`
	MatchPolicy MatchPolicy   `json:"match_policy,omitempty"`
}

type MatchPolicy struct {
	MatchType MatchType            `json:"match_type,omitempty"`
	Required  FlavorRequiredPolicy `json:"required,omitempty"`
}

type MatchType string

const (
	MatchTypeAnyOf  MatchType = "ANY_OF"
	MatchTypeAllOf  MatchType = "ALL_OF"
	MatchTypeLatest MatchType = "LATEST"
)

func (mt MatchType) String() string {
	return string(mt)
}

type FlavorRequiredPolicy string

const (
	FlavorRequired          FlavorRequiredPolicy = "REQUIRED"
	FlavorRequiredIfDefined FlavorRequiredPolicy = "REQUIRED_IF_DEFINED"
)

func (req FlavorRequiredPolicy) String() string {
	return string(req)
}

func NewFlavorMatchPolicy(fp cf.FlavorPart, mp MatchPolicy) FlavorMatchPolicy {
	return FlavorMatchPolicy{
		FlavorPart:  fp,
		MatchPolicy: mp,
	}
}

func NewMatchPolicy(mt MatchType, rp FlavorRequiredPolicy) MatchPolicy {
	return MatchPolicy{
		MatchType: mt,
		Required:  rp,
	}
}
