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
)

type policyBuilderIntelTpm20 struct {
	verifierCertificates VerifierCertificates
	hostManifest         *types.HostManifest
	signedFlavor         *SignedFlavor
	rules                []rule
}

func newPolicyBuilderIntelTpm20(verifierCertificates VerifierCertificates, hostManifest *types.HostManifest, signedFlavor *SignedFlavor) (policyBuilder, error) {
	builder := policyBuilderIntelTpm20{
		verifierCertificates: verifierCertificates,
		hostManifest: hostManifest,
		signedFlavor: signedFlavor,
	}

	return &builder, nil
}

func (builder *policyBuilderIntelTpm20) GetTrustRules() ([]rule, error) {

	// TODO:  Get rules based on the flavor type

	err := builder.loadPlatformRules()
	if err != nil {
		return nil, err
	}

	err = builder.loadAssetTagRules()
	if err != nil {
		return nil, err
	}

	return builder.rules, nil
}

func (builder *policyBuilderIntelTpm20) GetName() string {
	return "Intel Host Trust Policy"
}

func (builder *policyBuilderIntelTpm20) loadPlatformRules() error {

	aikCertificateTrusted, err := newAikCertificateTrusted(builder.verifierCertificates.PrivacyCaCertificates, "PLATFORM")
	if err != nil {
		return err
	}

	builder.rules = append(builder.rules, aikCertificateTrusted)


	expectedPcr, err := builder.signedFlavor.Flavor.PcrManifest.GetRequiredPcrValue(types.SHA256, types.PCR0)
	if err != nil {
		return errors.Errorf("The flavor's manifest did not contain PCR bank %s, index %d", types.SHA256, types.PCR0)
	}

	pcrMatchesConstant, err := newPcrMatchesConstant(expectedPcr)
	if err != nil {
		return err
	}

	builder.rules = append(builder.rules, pcrMatchesConstant)

	return nil
}

func (builder *policyBuilderIntelTpm20) loadAssetTagRules() error {
	
	// if the flavor has a valid asset tag certificate, add the AssetTagMatches rule...
	if builder.signedFlavor.Flavor.External != nil {
		assetTagCertificate := builder.signedFlavor.Flavor.External.AssetTag.TagCertificate.Encoded;
		if len(assetTagCertificate) > 0 {
			assetTagMatches, err := newAssetTagMatches(assetTagCertificate)
			if err != nil {
				return err
			}
		
			builder.rules = append(builder.rules, assetTagMatches)
		}
	}

	return nil
}
