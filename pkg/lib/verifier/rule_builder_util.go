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
	"github.com/intel-secl/intel-secl/v3/pkg/lib/verifier/rules"
	"github.com/pkg/errors"
)

func getPcrMatchesConstantRules(pcrs []types.PcrIndex, flavor *hvs.Flavor, marker common.FlavorPart) ([]rules.Rule, error) {

	var results []rules.Rule

	// iterate over the banks, collecting the values for each supplied index
	// and create PcrMatchesConstant rules.
	for bank, pcrMap := range(flavor.Pcrs) {
		for _, index := range(pcrs) {
			if expectedPcrEx, ok := pcrMap[index.String()]; ok {
				expectedPcr, _ := rules.FlavorPcr2ManifestPcr(&expectedPcrEx, types.SHAAlgorithm(bank), index)

				rule, err := rules.NewPcrMatchesConstant(expectedPcr, marker)
				if err != nil {
					return nil, errors.Wrapf(err, "An error occurred creating a PcrMatchesConstant rule for bank '%s', index '%s'", bank, index)
				}
					
				results = append(results, rule)
			}
		}
	}

	return results, nil
}

func getPcrEventLogEqualsExcludingRules(pcrs []types.PcrIndex, flavor *hvs.Flavor, marker common.FlavorPart) ([]rules.Rule, error) {
	
	var results []rules.Rule

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

				rule, err := rules.NewPcrEventLogEqualsExcluding(&expectedEventLogEntry, flavor.Meta.ID, marker)
				if err != nil {
					return nil, errors.Wrapf(err, "An error occurred creating a PcrEventLogEqualsExcluding rule for bank '%s', index '%s'", bank, index)
				}
	
				results = append(results, rule)
			}
		}
	}

	return results, nil
}

func getPcrEventLogEqualsRules(pcrs []types.PcrIndex, flavor *hvs.Flavor, marker common.FlavorPart) ([]rules.Rule, error) {
	
	var results []rules.Rule

	// iterate over the banks, collecting the values for each supplied index
	// and create PcrEventLogEquals rules (when present).
	for bank, pcrMap := range(flavor.Pcrs) {
		for _, index := range(pcrs) {
			if expectedPcrEx, ok := pcrMap[index.String()]; ok {

				expectedEventLogEntry := types.EventLogEntry {
					PcrIndex: index,
					PcrBank: types.SHAAlgorithm(bank),
					EventLogs: expectedPcrEx.Event,
				}

				rule, err := rules.NewPcrEventLogEquals(&expectedEventLogEntry, flavor.Meta.ID, marker)
				if err != nil {
					return nil, errors.Wrapf(err, "An error occurred creating a PcrEventLogEqualsExcluding rule for bank '%s', index '%s'", bank, index)
				}
	
				results = append(results, rule)
			}
		}
	}

	return results, nil
}

func getPcrEventLogIntegrityRules(pcrs []types.PcrIndex, flavor *hvs.Flavor, marker common.FlavorPart) ([]rules.Rule, error) {

	var results []rules.Rule

	// iterate over the banks, collecting the values for each supplied index
	// and create PcrEventLogIntegrity rules (when present).
	for bank, pcrMap := range(flavor.Pcrs) {
		for _, index := range(pcrs) {
			if expectedPcrEx, ok := pcrMap[index.String()]; ok {
				expectedPcr, _ := rules.FlavorPcr2ManifestPcr(&expectedPcrEx, types.SHAAlgorithm(bank), index)

				rule, err := rules.NewPcrEventLogIntegrity(expectedPcr, marker)
				if err != nil {
					return nil, errors.Wrapf(err, "An error occurred creating a PcrEventLogIntegrity rule for bank '%s', index '%s'", bank, index)
				}

				results = append(results, rule)
			}
		}
	}

	return results, nil
}

func getAssetTagMatchesRule(flavor *hvs.Flavor) (rules.Rule, error) {

	var rule rules.Rule
	var err error

	// if the flavor has a valid asset tag certificate, add the AssetTagMatches rule...
	if flavor.External == nil {
		return nil, errors.New("'External' was not present in the flavor")
	}

	rule, err = rules.NewAssetTagMatches(flavor.External.AssetTag.TagCertificate.Encoded)
	if err != nil {
		return nil, err
	}

	return rule, nil
}	

func getTagCertificateTrustedRule(privacyCACertificates *x509.CertPool, flavor *hvs.Flavor) (rules.Rule, error) {

	var rule rules.Rule
	var err error

	// if the flavor has a valid asset tag certificate, add the TagCertificateTrusted rule...
	if flavor.External == nil {
		return nil, errors.New("'External' was not present in the flavor")
	}

	rule, err = rules.NewTagCertificateTrusted(privacyCACertificates, &flavor.External.AssetTag.TagCertificate)
	if err != nil {
		return nil, err
	}

	return rule, nil
}

func getPcrEventLogIncludesRules(pcrs []types.PcrIndex, flavor *hvs.Flavor, marker common.FlavorPart) ([]rules.Rule, error) {

	var results []rules.Rule

	for bank, pcrMap := range(flavor.Pcrs) {
		for _, index := range(pcrs) {
			if expectedPcrEx, ok := pcrMap[index.String()]; ok {

				expectedEventLogEntry := types.EventLogEntry {
					PcrIndex: index,
					PcrBank: types.SHAAlgorithm(bank),
					EventLogs: expectedPcrEx.Event,
				}

				rule, err := rules.NewPcrEventLogIncludes(&expectedEventLogEntry, marker)
				if err != nil {
					return nil, errors.Wrapf(err, "An error occurred creating a PcrEventLogEqualsExcluding rule for bank '%s', index '%s'", bank, index)
				}
	
				results = append(results, rule)
			}
		}
	}

	return results, nil
}