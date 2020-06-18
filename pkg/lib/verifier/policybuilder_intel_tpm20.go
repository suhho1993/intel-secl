/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package verifier

//
// Builds rules for "intel" vendor and TPM 2.0.
//

import (
	"github.com/pkg/errors"
	"github.com/intel-secl/intel-secl/v3/pkg/lib/host-connector/types"
	"github.com/intel-secl/intel-secl/v3/pkg/lib/flavor/common"
	"github.com/intel-secl/intel-secl/v3/pkg/model/hvs"
	ta "github.com/intel-secl/intel-secl/v3/pkg/model/ta"
)

type policyBuilderIntelTpm20 struct {
	verifierCertificates VerifierCertificates
	hostManifest         *types.HostManifest
	signedFlavor         *hvs.SignedFlavor
	rules                []rule
}

func newPolicyBuilderIntelTpm20(verifierCertificates VerifierCertificates, hostManifest *types.HostManifest, signedFlavor *hvs.SignedFlavor) (policyBuilder, error) {
	builder := policyBuilderIntelTpm20{
		verifierCertificates: verifierCertificates,
		hostManifest: hostManifest,
		signedFlavor: signedFlavor,
	}

	return &builder, nil
}

func (builder *policyBuilderIntelTpm20) GetTrustRules() ([]rule, error) {

	var flavorPart common.FlavorPart
	var rules []rule

	if builder.signedFlavor.Flavor.Meta.Description == nil {
		return nil, errors.New("The flavor's description cannot be nil")
	}

	err := (&flavorPart).Parse(builder.signedFlavor.Flavor.Meta.Description.FlavorPart)
	if err != nil {
		return nil, errors.Wrap(err, "Could not retrieve flavor part name")
	}

	switch(flavorPart) {
	case common.FlavorPartPlatform:
		rules, err = builder.loadPlatformRules()
	case common.FlavorPartAssetTag:
		rules, err = builder.loadAssetTagRules()
	case common.FlavorPartOs:
		rules, err = builder.loadOsRules()
	case common.FlavorPartHostUnique:
		rules, err = builder.loadHostUniqueRules()
	case common.FlavorPartSoftware: 
		rules, err = builder.loadSoftwareRules()
	default:
		return nil, errors.Errorf("Cannot build rules for unknown flavor part %s", flavorPart)
	}

	if err != nil {
		return nil, errors.Wrapf(err, "Error creating trust rules for flavor '%s'", builder.signedFlavor.Flavor.Meta.ID)
	}

	return rules, nil
}

func (builder *policyBuilderIntelTpm20) GetName() string {
	return "Intel Host Trust Policy"
}

// From 'design' repo at isecl/libraries/verifier/verifier.md...
// AikCertificateTrusted  
// PcrMatchesConstant depend on HW features present in flavor  
// PcrEventLogEqualsExcluding rule for PCR 17, 18  
// PcrEventLogIntegrity rule for PCR 17,18 (if tboot is installed)
// FlavorTrusted (added in verifierimpl)
func (builder *policyBuilderIntelTpm20) loadPlatformRules() ([]rule, error) {

	var rules []rule

	//
	// Add 'AikCertificateTrusted' rule...
	// 
	aikCertificateTrusted, err := newAikCertificateTrusted(builder.verifierCertificates.PrivacyCACertificates, common.FlavorPartPlatform)
	if err != nil {
		return nil, err
	}

	rules = append(rules, aikCertificateTrusted)

	//
	// Add 'PcrMatchesConstant' rules...
	//
	pcrs, err := builder.getPlatformPcrsFromHardwareMeta()
	if err != nil {
		return nil, err
	}

	pcrMatchesContantsRules, err := getPcrMatchesConstantRules(pcrs, &builder.signedFlavor.Flavor, common.FlavorPartPlatform)
	if err != nil {
		return nil, err
	}

	rules = append(rules, pcrMatchesContantsRules...)

	//
	// Add 'PcrEventLogEqualsExcluding' rules...
	//
	pcrs = []types.PcrIndex{types.PCR17, types.PCR18}
	pcrEventLogEqualsExcludingRules, err := getPcrEventLogEqualsExcludingRules(pcrs, &builder.signedFlavor.Flavor, common.FlavorPartPlatform)
	if err != nil {
		return nil, err
	}

	rules = append(rules, pcrEventLogEqualsExcludingRules...)

	//
	// Add 'PcrEventLogIntegrity' rules...
	//  
	if builder.hostManifest.HostInfo.TbootInstalled {
		pcrs = []types.PcrIndex{types.PCR17, types.PCR18}
		pcrEventLogIntegrityRules, err := getPcrEventLogIntegrityRules(pcrs, &builder.signedFlavor.Flavor, common.FlavorPartPlatform)
		if err != nil {
			return nil, err
		}		
	
		rules = append(rules, pcrEventLogIntegrityRules...)
	}

	
	return rules, nil
}

// From 'design' repo at isecl/libraries/verifier/verifier.md...
// TagCertificateTrusted
// AssetTagMatches  
// FlavorTrusted (added in verifierimpl)
func (builder *policyBuilderIntelTpm20) loadAssetTagRules() ([]rule, error) {
	
	var rules []rule

	//
	// TagCertificateTrusted
	//
	tagCertificateTrusted, err := getTagCertificateTrustedRule(builder.verifierCertificates.PrivacyCACertificates, &builder.signedFlavor.Flavor)
	if err != nil {
		return nil, err
	}

	rules = append(rules, tagCertificateTrusted)

	//
	// AssetTagMatches
	//
	assetTagMatches, err := getAssetTagMatchesRule(&builder.signedFlavor.Flavor)
	if err != nil {
		return nil, err
	}

	rules = append(rules, assetTagMatches)

	return rules, nil
}

// From 'design' repo at isecl/libraries/verifier/verifier.md...
// AikCertificateTrusted  
// PcrEventLogIntegrity rule for PCR 17 (if tboot is installed)
// PcrEventLogIncludes rule for PCR 17
// FlavorTrusted (added in verifierimpl)
func (builder *policyBuilderIntelTpm20) loadOsRules() ([]rule, error) {

	var rules []rule
	pcr17 := []types.PcrIndex{types.PCR17}

	//
	// Add 'AikCertificateTrusted' rule...
	// 
	aikCertificateTrusted, err := newAikCertificateTrusted(builder.verifierCertificates.PrivacyCACertificates, common.FlavorPartOs)
	if err != nil {
		return nil, err
	}

	rules = append(rules, aikCertificateTrusted)

	//
	// Add 'PcrEventLogIntegrity' rules...
	//  
	if builder.hostManifest.HostInfo.TbootInstalled {
		pcrEventLogIntegrityRules, err := getPcrEventLogIntegrityRules(pcr17, &builder.signedFlavor.Flavor, common.FlavorPartOs)
		if err != nil {
			return nil, err
		}

		rules = append(rules, pcrEventLogIntegrityRules...)
	}

	//
	// Add 'PcrEventLogIncludes' rules...
	//  
	pcrEventLogIncludesRules, err := getPcrEventLogIncludesRules(pcr17, &builder.signedFlavor.Flavor, common.FlavorPartOs)
	if err != nil {
		return nil, err
	}

	rules = append(rules, pcrEventLogIncludesRules...)

	return rules, nil
}

// From 'design' repo at isecl/libraries/verifier/verifier.md...
// AikCertificateTrusted
// PcrEventLogIncludes rule for PCR 17, 18  
// PcrEventLogIntegrity rule for PCR 17, 18 (if tboot is installed)
// FlavorTrusted (added in verifierimpl)
func (builder *policyBuilderIntelTpm20) loadHostUniqueRules() ([]rule, error) {

	var rules []rule
	pcr17and18 := []types.PcrIndex{types.PCR17, types.PCR18}

	//
	// Add 'AikCertificateTrusted' rule...
	// 
	aikCertificateTrusted, err := newAikCertificateTrusted(builder.verifierCertificates.PrivacyCACertificates, common.FlavorPartHostUnique)
	if err != nil {
		return nil, err
	}

	rules = append(rules, aikCertificateTrusted)

	//
	// Add 'PcrEventLogIntegrity' rules...
	//  
	if builder.hostManifest.HostInfo.TbootInstalled {
		pcrEventLogIntegrityRules, err := getPcrEventLogIntegrityRules(pcr17and18, &builder.signedFlavor.Flavor, common.FlavorPartHostUnique)
		if err != nil {
			return nil, err
		}

		rules = append(rules, pcrEventLogIntegrityRules...)
	}

	//
	// Add 'PcrEventLogIncludes' rules...
	//  
	pcrEventLogIncludesRules, err := getPcrEventLogIncludesRules(pcr17and18, &builder.signedFlavor.Flavor, common.FlavorPartHostUnique)
	if err != nil {
		return nil, err
	}

	rules = append(rules, pcrEventLogIncludesRules...)

	return rules, nil
}

// From 'design' repo at isecl/libraries/verifier/verifier.md...
// XmlMeasurementsDigestEquals
// PcrEventLogIntegrity rule for PCR 15  
// XmlMeasurementLogIntegrity  
// XmlMeasurementLogEquals
// FlavorTrusted (added in verifierimpl)
func (builder *policyBuilderIntelTpm20) loadSoftwareRules() ([]rule, error) {

	var rules []rule

	//
	// Add 'XmlEventLogDigestEquals' rule...
	//  
	meta := builder.signedFlavor.Flavor.Meta
	if meta == nil {
		return nil, errors.New("'Meta' was not present in the flavor")
	}

	if meta.Description == nil {
		return nil, errors.New("'Description' was not present in the flavor")
	}

	xmlMeasurementLogDigestEqualsRule, err := newXmlMeasurementLogDigestEquals(meta.Description.DigestAlgorithm, meta.ID)
	if err != nil {
		return nil, err
	}

	rules = append(rules, xmlMeasurementLogDigestEqualsRule)

	//
	// Add 'PcrEventLogIntegrity' rules...
	//  
	pcr15 := []types.PcrIndex{types.PCR15}
	pcrEventLogIntegrityRules, err := getPcrEventLogIntegrityRules(pcr15, &builder.signedFlavor.Flavor, common.FlavorPartSoftware)
	if err != nil {
		return nil, err
	}

	rules = append(rules, pcrEventLogIntegrityRules...)

	//
	// Add 'XmlMeasurementLogIntegrity' rule... 
	//
	if builder.signedFlavor.Flavor.Software == nil {
		return nil, errors.New("'Software' was not present in the flavor")
	}

	xmlMeasurementLogIntegrityRule, err := newXmlMeasurementLogIntegrity(meta.ID, meta.Description.Label, builder.signedFlavor.Flavor.Software.CumulativeHash)
	rules = append(rules, xmlMeasurementLogIntegrityRule)	

	//
	// Add 'XmlMeasurementLogEquals' rule...
	//
	var measurements []ta.FlavorMeasurement
	for _, measurement := range(builder.signedFlavor.Flavor.Software.Measurements) {
		measurements = append(measurements, measurement)
	}

	xmlMeasurementLogEqualsRule, err := newXmlMeasurementLogEquals(&builder.signedFlavor.Flavor)
	if err != nil {
		// KT LOG: failed to create rule from measurement 'name'
		return nil, err
	}

	rules = append(rules, xmlMeasurementLogEqualsRule)

	return rules, nil
}

// Based on the manifest's hardware metadata, return the correct PCRs...
//   - Always match on PCR0
//   - If CBNT is enabled and profile 5: Add PCR7
//   - If SUEFI is enabled: add PCR0-PCR7
func (builder *policyBuilderIntelTpm20) getPlatformPcrsFromHardwareMeta() ([]types.PcrIndex, error) {

	var pcrs []types.PcrIndex

	pcrs = append(pcrs, types.PCR0)

	if builder.hostManifest.HostInfo.HardwareFeatures.CBNT != nil {
		if builder.hostManifest.HostInfo.HardwareFeatures.CBNT.Enabled {
			if builder.hostManifest.HostInfo.HardwareFeatures.CBNT.Meta.Profile == "BTGP5" {
				pcrs = append(pcrs, types.PCR7)
			}
		}
	}

	if builder.hostManifest.HostInfo.HardwareFeatures.SUEFI != nil {
		if builder.hostManifest.HostInfo.HardwareFeatures.SUEFI.Enabled {
			suefiPcrs := []types.PcrIndex {
				types.PCR1, 
				types.PCR2, 
				types.PCR3, 
				types.PCR4, 
				types.PCR5, 
				types.PCR6, 
				types.PCR7,
			
			}

			pcrs = append(pcrs, suefiPcrs...)
		}
	}
	
	return pcrs, nil
}