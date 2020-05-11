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
	hostManifest *types.HostManifest
	signedFlavor *SignedFlavor
	rules        []rule
}

func newPolicyBuilderIntelTpm20(hostManifest *types.HostManifest, signedFlavor *SignedFlavor) (policyBuilder, error) {
	builder := policyBuilderIntelTpm20{
		hostManifest: hostManifest,
		signedFlavor: signedFlavor,
	}

	return &builder, nil
}

func (builder *policyBuilderIntelTpm20) GetTrustRules() ([]rule, error) {
	err := builder.loadPlatformRules()
	if err != nil {
		return nil, err
	}

	return builder.rules, nil
}

func (builder *policyBuilderIntelTpm20) GetName() string {
	return "Intel Host Trust Policy"
}

func (builder *policyBuilderIntelTpm20) loadPlatformRules() error {

	expectedPcr, err := builder.signedFlavor.PcrManifest.GetRequiredPcrValue(types.SHA256, types.PCR0)
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
