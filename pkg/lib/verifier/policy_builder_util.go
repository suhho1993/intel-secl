/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package verifier

import (
	"crypto/x509"
	"github.com/intel-secl/intel-secl/v3/pkg/lib/host-connector/types"
	"github.com/intel-secl/intel-secl/v3/pkg/model/hvs"
	"github.com/intel-secl/intel-secl/v3/pkg/lib/flavor/common"
	"github.com/pkg/errors"
)

func getPcrMatchesConstantRules(pcrs []types.PcrIndex, flavor *hvs.Flavor, marker common.FlavorPart) ([]rule, error) {

	var rules []rule

	// iterate over the banks, collecting the values for each supplied index
	// and create PcrMatchesConstant rules.
	for bank, pcrMap := range(flavor.Pcrs) {
		for _, index := range(pcrs) {
			if expectedPcrEx, ok := pcrMap[index.String()]; ok {
				expectedPcr, _ := flavorPcr2ManifestPcr(&expectedPcrEx, types.SHAAlgorithm(bank), index)

				rule, err := newPcrMatchesConstant(expectedPcr, marker)
				if err != nil {
					return nil, errors.Wrapf(err, "An error occurred creating a PcrMatchesConstant rule for bank '%s', index '%s'", bank, index)
				}
					
				rules = append(rules, rule)
			}
		}
	}

	return rules, nil
}

func getPcrEventLogEqualsExcludingRules(pcrs []types.PcrIndex, flavor *hvs.Flavor, marker common.FlavorPart) ([]rule, error) {
	
	var rules []rule

	// iterate over the banks, collecting the values for each supplied index
	// and create PcrEventLogEqualsExcluding rules (when present).
	for bank, pcrMap := range(flavor.Pcrs) {
		for _, index := range(pcrs) {
			if expectedPcrEx, ok := pcrMap[index.String()]; ok {

				expectedEventLogEntry := types.EventLogEntry {
					PcrIndex: index,
					PcrBank: types.SHAAlgorithm(bank),
					EventLogs: expectedPcrEx.Event,
				}

				rule, err := newPcrEventLogEqualsExcluding(&expectedEventLogEntry, flavor.Meta.ID, marker)
				if err != nil {
					return nil, errors.Wrapf(err, "An error occurred creating a PcrEventLogEqualsExcluding rule for bank '%s', index '%s'", bank, index)
				}
	
				rules = append(rules, rule)
			}
		}
	}

	return rules, nil
}

func getPcrEventLogIntegrityRules(pcrs []types.PcrIndex, flavor *hvs.Flavor, marker common.FlavorPart) ([]rule, error) {

	var rules []rule

	// iterate over the banks, collecting the values for each supplied index
	// and create PcrEventLogIntegrity rules (when present).
	for bank, pcrMap := range(flavor.Pcrs) {
		for _, index := range(pcrs) {
			if expectedPcrEx, ok := pcrMap[index.String()]; ok {
				expectedPcr, _ := flavorPcr2ManifestPcr(&expectedPcrEx, types.SHAAlgorithm(bank), index)

				rule, err := newPcrEventLogIntegrity(expectedPcr, marker)
				if err != nil {
					return nil, errors.Wrapf(err, "An error occurred creating a PcrEventLogIntegrity rule for bank '%s', index '%s'", bank, index)
				}

				rules = append(rules, rule)
			}
		}
	}

	return rules, nil
}

func getAssetTagMatchesRule(flavor *hvs.Flavor) (rule, error) {

	var rule rule
	var err error

	// if the flavor has a valid asset tag certificate, add the AssetTagMatches rule...
	if flavor.External == nil {
		return nil, errors.New("'External' was not present in the flavor")
	}

	rule, err = newAssetTagMatches(flavor.External.AssetTag.TagCertificate.Encoded)
	if err != nil {
		return nil, err
	}

	return rule, nil
}	

func getTagCertificateTrustedRule(privacyCACertificates *x509.CertPool, flavor *hvs.Flavor) (rule, error) {

	var rule rule 
	var err error

	// if the flavor has a valid asset tag certificate, add the TagCertificateTrusted rule...
	if flavor.External == nil {
		return nil, errors.New("'External' was not present in the flavor")
	}

	rule, err = newTagCertificateTrusted(privacyCACertificates, &flavor.External.AssetTag.TagCertificate)
	if err != nil {
		return nil, err
	}

	return rule, nil
}

func getPcrEventLogIncludesRules(pcrs []types.PcrIndex, flavor *hvs.Flavor, marker common.FlavorPart) ([]rule, error) {

	var rules []rule

	for bank, pcrMap := range(flavor.Pcrs) {
		for _, index := range(pcrs) {
			if expectedPcrEx, ok := pcrMap[index.String()]; ok {

				expectedEventLogEntry := types.EventLogEntry {
					PcrIndex: index,
					PcrBank: types.SHAAlgorithm(bank),
					EventLogs: expectedPcrEx.Event,
				}

				rule, err := newPcrEventLogIncludes(&expectedEventLogEntry, marker)
				if err != nil {
					return nil, errors.Wrapf(err, "An error occurred creating a PcrEventLogIncludes rule for bank '%s', index '%s'", bank, index)
				}
	
				rules = append(rules, rule)
			}
		}
	}

	return rules, nil
}