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

// Function returns 3 maps. The reason for this is that we do not have to keep iterating over per part policy
// over and over again trying to look for information. Everything is gathered in one fell swoop
func (r *FlavorGroup) GetMatchPolicyMaps() (

	// Map to determine what is the match policy for each individual flavor part
	// eg : map["SOFTWARE"] = MatchPolicy{MatchType: "ANY_OF", Required: "Required_if_defined"}
	map[cf.FlavorPart]MatchPolicy,

	// TODO: maybe the value of the following two maps do not need to be another map... just a slice would suffice
	// Have a mapping of all the flavor parts with a particular match type
	// eg : map["ALL_OF"] = map with entries {Platform, Software}. The reason the value of the map is another
	// map is that we can immediately determine if a particular flavorpart is contained in the match type map
	map[MatchType]map[cf.FlavorPart]bool,
	// Have a mapping of all the flavor parts with a particular Required Policy
	// eg : map["Required_if_defined"] = map with entries {Platform, Software}. The reason the value of the map is another
	// map is that we can immediately determine if a particular flavorpart is contained in the required policy map
	map[FlavorRequiredPolicy]map[cf.FlavorPart]bool) {

	fpMap := map[cf.FlavorPart]MatchPolicy{}
	mtMap := map[MatchType]map[cf.FlavorPart]bool{}
	plcyMap := map[FlavorRequiredPolicy]map[cf.FlavorPart]bool{}

	for _, plcy := range r.MatchPolicies {
		fpMap[plcy.FlavorPart] = plcy.MatchPolicy

		mtMap[plcy.MatchPolicy.MatchType][plcy.FlavorPart] = true
		plcyMap[plcy.MatchPolicy.Required][plcy.FlavorPart] = true
	}
	return fpMap, mtMap, plcyMap

}
