/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package util

import (
	"github.com/intel-secl/intel-secl/v3/pkg/lib/common/log"
	cf "github.com/intel-secl/intel-secl/v3/pkg/lib/flavor/common"
	"github.com/intel-secl/intel-secl/v3/pkg/model/hvs"
)

var defaultLog = log.GetDefaultLogger()

func CreateFlavorGroupByName(flavorgroupName string) hvs.FlavorGroup {
	defaultLog.Trace("util/flavor_group:CreateFlavorGroupByName() Entering")
	defer defaultLog.Trace("util/flavor_group:CreateFlavorGroupByName() Leaving")

	var collection hvs.FlavorMatchPolicyCollection
	collection.FlavorMatchPolicies = GetAutomaticFlavorMatchPolicy()

	var flavorgroup hvs.FlavorGroup
	flavorgroup.Name = flavorgroupName
	flavorgroup.FlavorMatchPolicyCollection = collection

	return flavorgroup
}

func GetAutomaticFlavorMatchPolicy() []hvs.FlavorMatchPolicy {
	defaultLog.Trace("util/flavor_group:GetAutomaticFlavorMatchPolicy() Entering")
	defer defaultLog.Trace("util/flavor_group:GetAutomaticFlavorMatchPolicy() Leaving")

	var policies []hvs.FlavorMatchPolicy
	policies = append(policies, hvs.NewFlavorMatchPolicy(cf.FlavorPartPlatform, hvs.NewMatchPolicy(hvs.MatchTypeAnyOf, hvs.FlavorRequired)))
	policies = append(policies, hvs.NewFlavorMatchPolicy(cf.FlavorPartOs, hvs.NewMatchPolicy(hvs.MatchTypeAnyOf, hvs.FlavorRequired)))
	policies = append(policies, hvs.NewFlavorMatchPolicy(cf.FlavorPartSoftware, hvs.NewMatchPolicy(hvs.MatchTypeAllOf, hvs.FlavorRequiredIfDefined)))
	policies = append(policies, hvs.NewFlavorMatchPolicy(cf.FlavorPartAssetTag, hvs.NewMatchPolicy(hvs.MatchTypeLatest, hvs.FlavorRequiredIfDefined)))
	policies = append(policies, hvs.NewFlavorMatchPolicy(cf.FlavorPartHostUnique, hvs.NewMatchPolicy(hvs.MatchTypeLatest, hvs.FlavorRequiredIfDefined)))

	return policies
}
