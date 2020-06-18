/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package verifier

//
// Rule that validates that the host manifests matches what was supplied
// in the flavor.
//

import (
	"bytes"
	"encoding/base64"
	"github.com/pkg/errors"
	"github.com/intel-secl/intel-secl/v3/pkg/lib/host-connector/types"
	"github.com/intel-secl/intel-secl/v3/pkg/lib/flavor/common"
)

func newAssetTagMatches(expectedAssetTagDigest []byte) (rule, error) {

	assetTagMatches := assetTagMatches {
		expectedAssetTagDigest: expectedAssetTagDigest,
	}

	return &assetTagMatches, nil
}

type assetTagMatches struct {
	expectedAssetTagDigest []byte
}

func (rule *assetTagMatches) Apply(hostManifest *types.HostManifest) (*RuleResult, error) {
	var fault *Fault
	result := RuleResult{}
	result.Trusted = true 
	result.Rule.Name = "com.intel.mtwilson.core.verifier.policy.rule.AssetTagMatches"
	result.Rule.Markers = append(result.Rule.Markers, common.FlavorPartAssetTag)

	if len(hostManifest.AssetTagDigest) == 0 {
		fault = &Fault{
			Name:        FaultAssetTagMissing,
			Description: "AssetTag Reported is null",
		}
	} else if rule.expectedAssetTagDigest == nil {
		fault = &Fault{
			Name:        FaultAssetTagNotProvisioned,
			Description: "AssetTag is not in provisioned by the management",
		}
	} else {
		actualAssetTagDigest, err := base64.StdEncoding.DecodeString(hostManifest.AssetTagDigest)
		if err != nil {
			return nil, errors.Wrap(err, "Could not decode AssetTagDigest")
		}

		if bytes.Compare(actualAssetTagDigest, rule.expectedAssetTagDigest) != 0 {
			fault = &Fault{
				Name:        FaultAssetTagMismatch,
				Description: "Asset tag provisioned does not match asset tag reported",
			}	
		}
	}

	if fault != nil {
		result.Faults = append(result.Faults, *fault)
	}

	return &result, nil
}
