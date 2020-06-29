/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */

package hvs

import (
	"encoding/json"
	"github.com/google/uuid"
	cf "github.com/intel-secl/intel-secl/v3/pkg/lib/flavor/common"
)

type FlavorgroupCollection struct {
	Flavorgroups []*FlavorGroup `json:"flavorgroups" xml:"flavorgroup"`
}

type FlavorMatchPolicies []FlavorMatchPolicy

type FlavorMatchPolicyCollection struct {
	FlavorMatchPolicies `json:"flavor_match_policies,omitempty"`
}

type FlavorGroup struct {
	ID            uuid.UUID           `json:"id,omitempty"`
	Name          string              `json:"name,omitempty"`
	FlavorIds     []string            `json:"flavorIds,omitempty"`
	Flavors       []Flavor            `json:"flavors,omitempty"`
	MatchPolicies FlavorMatchPolicies `json:"flavor_match_policies,omitempty"`
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

func (r FlavorGroup) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		ID                          uuid.UUID                   `json:"id,omitempty"`
		Name                        string                      `json:"name,omitempty"`
		FlavorIds                   []string                    `json:"flavorIds,omitempty"`
		Flavors                     []Flavor                    `json:"flavors,omitempty"`
		FlavorMatchPolicyCollection FlavorMatchPolicyCollection `json:"flavor_match_policy_collection,omitempty"`
	}{
		ID:                          r.ID,
		Name:                        r.Name,
		FlavorIds:                   r.FlavorIds,
		Flavors:                     r.Flavors,
		FlavorMatchPolicyCollection: FlavorMatchPolicyCollection{r.MatchPolicies},
	})
}

func (r *FlavorGroup) UnmarshalJSON(b []byte) error {
	decoded := new(struct {
		ID                          uuid.UUID                   `json:"id,omitempty"`
		Name                        string                      `json:"name,omitempty"`
		FlavorIds                   []string                    `json:"flavorIds,omitempty"`
		Flavors                     []Flavor                    `json:"flavors,omitempty"`
		FlavorMatchPolicyCollection FlavorMatchPolicyCollection `json:"flavor_match_policy_collection,omitempty"`
	})
	err := json.Unmarshal(b, decoded)
	if err == nil {
		r.ID = decoded.ID
		r.Name = decoded.Name
		r.FlavorIds = decoded.FlavorIds
		r.Flavors = decoded.Flavors
		r.MatchPolicies = decoded.FlavorMatchPolicyCollection.FlavorMatchPolicies
	}
	return err
}
