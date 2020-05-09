/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package verifier

import (
	"intel-secl/v3/pkg/lib/host-connector/types"
)

type rule interface {
	Apply(hostManifest *types.HostManifest) (*RuleResult, error)
}

type policyBuilder interface {
	GetTrustRules() ([]rule, error)
	GetName() string
}

func getPolicyBuilder(hostManifest *types.HostManifest, signedFlavor *SignedFlavor) (policyBuilder, error) {

	// TODO: Add logic that uses the vendor/tpm version from flavor/manifest to determine the
	// policy builder.  For now, just return intel/tpm2.
	builder, err := newPolicyBuilderIntelTpm20(hostManifest, signedFlavor)
	if err != nil {
		return nil, err
	}

	return builder, nil
}
