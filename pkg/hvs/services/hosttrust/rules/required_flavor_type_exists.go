/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */

package rules

import (
	"fmt"
	"github.com/intel-secl/intel-secl/v3/pkg/hvs/constants/verifier-rules-and-faults"
	cf "github.com/intel-secl/intel-secl/v3/pkg/lib/flavor/common"
	"github.com/intel-secl/intel-secl/v3/pkg/model/hvs"
	"reflect"
)

//TODO move to verifier
type RequiredFlavorTypeExists struct {
	FlavorPart cf.FlavorPart
}

func NewRequiredFlavorTypeExists(flavorPart cf.FlavorPart) *RequiredFlavorTypeExists {
	return &RequiredFlavorTypeExists{
		FlavorPart: flavorPart,
	}
}

func (r *RequiredFlavorTypeExists) Apply(trustReport hvs.TrustReport) *hvs.TrustReport{

	var ruleResult hvs.RuleResult
 	if r.isFlavorPartMissing(trustReport){
 		fault := hvs.Fault{
			Name:        constants.FaultRequiredFlavorTypeMissing,
			Description: fmt.Sprintf("Required flavor type missing: %s", r.FlavorPart.String()),
		}
		defaultLog.Debugf("Defined and required flavor part [%s] is missing", r.FlavorPart.String())
		ruleResult.Faults = append(ruleResult.Faults, fault)
	}
	if !reflect.DeepEqual(ruleResult, hvs.RuleResult{}){
		trustReport.AddResult(ruleResult)
	}
	return &trustReport
}

func (r *RequiredFlavorTypeExists) isFlavorPartMissing(trustReport hvs.TrustReport) bool{
	if trustReport.GetResultsForMarker(r.FlavorPart.String()) != nil && len(trustReport.GetResultsForMarker(r.FlavorPart.String())) != 0{
		return false
	}
	return true
}