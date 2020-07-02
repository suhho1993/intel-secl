/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */

package rules

import (
	commLog "github.com/intel-secl/intel-secl/v3/pkg/lib/common/log"
	"github.com/intel-secl/intel-secl/v3/pkg/lib/flavor/common"
	"github.com/intel-secl/intel-secl/v3/pkg/lib/flavor/model"
	flavorVerifier "github.com/intel-secl/intel-secl/v3/pkg/lib/verifier"
	"github.com/intel-secl/intel-secl/v3/pkg/lib/verifier/rules"
	"github.com/intel-secl/intel-secl/v3/pkg/model/hvs"
	"github.com/pkg/errors"
)

type AllOfFlavors struct {
	AllOfFlavors []*model.SignedFlavor
	Result       *hvs.RuleResult
	Markers      []common.FlavorPart
}

var defaultLog = commLog.GetDefaultLogger()
var secLog = commLog.GetSecurityLogger()

func (aof *AllOfFlavors) AddFaults(report *hvs.TrustReport) (*hvs.TrustReport, error) {

	if report == nil {
		return nil, nil
	}
	hostManifest := &report.HostManifest
	for _, flavor := range aof.AllOfFlavors {
		if flavor == nil {
			continue
		}
		trustPolicyManager := flavorVerifier.NewHostTrustPolicyManager(flavor.Flavor, hostManifest)
		for _, policyRule := range trustPolicyManager.GetVendorTrustPolicyReader().Rules() {
			result, err := policyRule.Apply(hostManifest)
			if err != nil {
				return report, errors.Wrap(err, "Failed to apply rule \""+report.PolicyName+"\" to host manifest of "+report.HostManifest.HostInfo.HostName)
			}
			if result != nil &&
				!report.CheckResultExists(*result) {
				flvPart := flavor.Flavor.Meta.Description.FlavorPart
				// TODO:
				// assign RuleInfo? FlavorID?
				// Trusted is be default empty since Fault is not empty
				// ref: lib-verifier: RuleResult.java
				report.Results = append(report.Results, hvs.RuleResult{
					Faults: []hvs.Fault{
						{
							Name :       rules.FaultAllofFlavorsMissing,
							Description: "All of Flavor Types Missing : " + flvPart,
						},
					},
				})
			}
		}
	}
	return report, nil
}

// RuleAllOfFlavors.java: 81
// checkAllOfFlavorsExist(TrustReport trustReport)
// this function does the same apply operations as addFaults
// and the flow in code seems to utilize it before calling addFaults
// for optimizing reason...probably better get rid of it
func (aof *AllOfFlavors) CheckAllOfFlavorsExist(report *hvs.TrustReport) bool {

	if report == nil ||
		aof.AllOfFlavors == nil {
		return false
	}
	hostManifest := &report.HostManifest
	for _, flavor := range aof.AllOfFlavors {
		if flavor == nil {
			continue
		}
		trustPolicyManager := flavorVerifier.NewHostTrustPolicyManager(flavor.Flavor, hostManifest)
		for _, policyRule := range trustPolicyManager.GetVendorTrustPolicyReader().Rules() {
			result, err := policyRule.Apply(hostManifest)
			if err != nil {
				defaultLog.WithError(err).Debug("hosttrust/all_of_flavors:checkAllOfFlavorsExist() Error applying vendor trust policy rule")
				return false
			}
			if result != nil && !report.CheckResultExists(*result) {
				return false
			}
		}
	}
	return true
}