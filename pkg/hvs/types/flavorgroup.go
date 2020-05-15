/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package types

import (
	"encoding/json"
	"github.com/intel-secl/intel-secl/v3/pkg/model/hvs"
	"github.com/jinzhu/gorm/dialects/postgres"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
)

type FlavorGroup struct {
	Id                    string         `json:"id,omitempty" gorm:"primary_key;type:uuid"`
	Name                  string         `json:"name"`
	FlavorTypeMatchPolicy postgres.Jsonb `json:"flavor_type_match_policy" gorm:"type:json"`
}

func (dbFlavorGroup *FlavorGroup) Unmarshal() (*hvs.FlavorGroup, error) {
	log.Trace("mw_flavorgroup:unmarshal() Entering")
	defer log.Trace("mw_flavorgroup:unmarshal() Leaving")

	flavorGroup := hvs.FlavorGroup{}
	if dbFlavorGroup == nil {
		return &flavorGroup, nil
	}
	// ignore error since we validate it on callbacks
	var matchPolicyCollection hvs.FlavorMatchPolicyCollection
	err := json.Unmarshal(dbFlavorGroup.FlavorTypeMatchPolicy.RawMessage, &matchPolicyCollection)
	if err != nil {
		return &flavorGroup, errors.Wrap(err, "mw_flavorgroup:unmarshal() Error in unmarshalling the FlavorTypeMatchPolicy")
	}

	flavorGroup.Id = dbFlavorGroup.Id
	flavorGroup.Name = dbFlavorGroup.Name
	if &matchPolicyCollection != nil && len(matchPolicyCollection.FlavorMatchPolicies) > 0 {
		flavorGroup.FlavorMatchPolicyCollection = &matchPolicyCollection
	}
	return &flavorGroup, nil
}

type DefaultFlavorGroups string

const (
	AUTOMATIC         DefaultFlavorGroups = "automatic"
	HOST_UNIQUE                           = "host_unique"
	PLATFORM_SOFTWARE                     = "platform_software"
	WORKLOAD_SOFTWARE                     = "workload_software"
)

func (dfg DefaultFlavorGroups) String() string {
	return dfg.String()
}
