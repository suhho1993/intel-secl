/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package verifier

import (
	"testing"
	"github.com/intel-secl/intel-secl/v3/pkg/lib/host-connector/types"
	"github.com/stretchr/testify/assert"
)

var (
	validAssetTagBytes = []byte{'b', 'e', 'e', 'f'}
	invalidAssetTagBytes = []byte{'d', 'e', 'a', 'd'}
	validAssetTagString = "YmVlZg=="
	invalidAssetTagString = "ZGVhZA==" 
)

func TestAssetTagMatchesNotProvisionedFault(t *testing.T) {

	hostManifest := types.HostManifest{
		AssetTagDigest : validAssetTagString,	// valid tag in host
	}
	
	// provide a nil certificate value to the rule
	rule, err := newAssetTagMatches(nil)
	assert.NoError(t, err)

	// no faults should be returned...
	result, err := rule.Apply(&hostManifest)
	assert.NoError(t, err)
	assert.NotNil(t, result)
	assert.Equal(t, 1, len(result.Faults))
	assert.Equal(t, FaultAssetTagNotProvisioned, result.Faults[0].Name)
	t.Logf("Fault description: %s", result.Faults[0].Description)
}

func TestAssetTagMissingFromManifest(t *testing.T) {

	hostManifest := types.HostManifest{
		AssetTagDigest : "",	// not in host manifest
	}
	
	// simulate adding valid asset tag bytes from the flavor...
	rule, err := newAssetTagMatches(validAssetTagBytes)
	assert.NoError(t, err)

	// we should get a "missing asset tag" fault...
	result, err := rule.Apply(&hostManifest)
	assert.NoError(t, err)
	assert.NotNil(t, result)
	assert.Equal(t, 1, len(result.Faults))
	assert.Equal(t, FaultAssetTagMissing, result.Faults[0].Name)
	t.Logf("Fault description: %s", result.Faults[0].Description)
}

func TestAssetTagMismatch(t *testing.T) {

	hostManifest := types.HostManifest{
		AssetTagDigest : invalidAssetTagString,	// in valid from the host
	}
	
	// simulate adding valid asset tag bytes from the flavor...
	rule, err := newAssetTagMatches(validAssetTagBytes)
	assert.NoError(t, err)

	// we should get a "asset tag mismatch" fault...
	result, err := rule.Apply(&hostManifest)
	assert.NoError(t, err)
	assert.NotNil(t, result)
	assert.Equal(t, 1, len(result.Faults))
	assert.Equal(t, FaultAssetTagMismatch, result.Faults[0].Name)
	t.Logf("Fault description: %s", result.Faults[0].Description)
}

func TestAssetTagMatches(t *testing.T) {

	hostManifest := types.HostManifest{
		AssetTagDigest : validAssetTagString,	// valid tag in host
	}
	
	// simulate adding valid asset tag bytes from the flavor...
	rule, err := newAssetTagMatches(validAssetTagBytes)
	assert.NoError(t, err)

	// no faults should be returned...
	result, err := rule.Apply(&hostManifest)
	assert.NoError(t, err)
	assert.NotNil(t, result)
	assert.Equal(t, 0, len(result.Faults))
}