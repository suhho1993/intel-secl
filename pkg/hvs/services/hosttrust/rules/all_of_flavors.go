/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */

package rules

import (
	"github.com/intel-secl/intel-secl/v3/pkg/hvs/constants/verifier-rules-and-faults"
	commLog "github.com/intel-secl/intel-secl/v3/pkg/lib/common/log"
	"github.com/intel-secl/intel-secl/v3/pkg/lib/flavor/common"
	"github.com/intel-secl/intel-secl/v3/pkg/lib/flavor/model"
	flavorVerifier "github.com/intel-secl/intel-secl/v3/pkg/lib/verifier"
	"github.com/intel-secl/intel-secl/v3/pkg/model/hvs"
	"github.com/pkg/errors"
)

type AllOfFlavors struct {
	AllOfFlavors []*model.SignedFlavor
	Result       *hvs.RuleResult
	Markers      []common.FlavorPart
	SkipFlavorSignatureVerification bool
}

func NewAllOfFlavors(flavors []*model.SignedFlavor, markers []common.FlavorPart, skipFlavorSignatureVerification bool) AllOfFlavors {
	return AllOfFlavors{
		AllOfFlavors:                    flavors,
		Markers:                         markers,
		SkipFlavorSignatureVerification: skipFlavorSignatureVerification,
	}
}
var defaultLog = commLog.GetDefaultLogger()
var secLog = commLog.GetSecurityLogger()

func (aof *AllOfFlavors) AddFaults(verifierCerts flavorVerifier.VerifierCertificates, report *hvs.TrustReport) (*hvs.TrustReport, error) {

	if report == nil {
		return nil, nil
	}
	hostManifest := &report.HostManifest
	for _, flavor := range aof.AllOfFlavors {
		if flavor == nil {
			continue
		}
		ruleFactory := flavorVerifier.NewRuleFactory(verifierCerts, hostManifest, flavor, aof.SkipFlavorSignatureVerification)
		policyRules, _, err := ruleFactory.GetVerificationRules()
		if err != nil{
			return nil, err
		}
		for _, policyRule := range policyRules {
			result, err := policyRule.Apply(hostManifest)
			if err != nil {
				return report, errors.Wrap(err, "Failed to apply rule \""+report.PolicyName+"\" to host manifest of "+report.HostManifest.HostInfo.HostName)
			}
			if result != nil && !report.CheckResultExists(*result){
				// TODO:
				// assign RuleInfo? FlavorID?
				// Trusted is be default empty since Fault is not empty
				// ref: lib-verifier: RuleResult.java
				ruleResult := hvs.RuleResult{
					//FlavorVerify.java 585
					Rule: hvs.RuleInfo{Markers: aof.Markers},
					Faults: []hvs.Fault{
						{
							Name :       constants.FaultAllofFlavorsMissing,
							Description: "All of Flavor Types Missing : " + flavor.Flavor.Meta.Description.FlavorPart,
						},
					},
				}
				report.AddResult(ruleResult)
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