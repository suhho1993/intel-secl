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

func TestPcrMatchesConstantMismatchFault(t *testing.T) {

	expectedPcr := types.Pcr {
		Index: 0,
		Value: PCR_VALID_256,
		PcrBank:  types.SHA256,
	}

	// host manifest with 'invalid' value for pcr0
	hostManifest := types.HostManifest{
		PcrManifest: types.PcrManifest{
			Sha256Pcrs : []types.Pcr {
				{
					Index: 0,
					Value: PCR_INVALID_256,
					PcrBank:  types.SHA256,
				},
			},
		},
	}

	rule, err := newPcrMatchesConstant(&expectedPcr)
	assert.NoError(t, err)

	result, err := rule.Apply(&hostManifest)
	assert.NoError(t, err)
	assert.NotNil(t, result)
	assert.Equal(t, len(result.Faults), 1)
	assert.Equal(t, result.Faults[0].Name, FaultPcrValueMismatchSHA256)
	t.Logf("Fault description: %s", result.Faults[0].Description)
	assert.False(t, result.Trusted)
}

func TestPcrMatchesConstantMissingFault(t *testing.T) {

	// empty manifest will result in 'missing' fault
	hostManifest := types.HostManifest{
		PcrManifest: types.PcrManifest{
		},
	}

	expectedPcr := types.Pcr {
		Index: 0,
		Value: PCR_VALID_256,
		PcrBank:  types.SHA256,
	}

	rule, err := newPcrMatchesConstant(&expectedPcr)
	assert.NoError(t, err)

	result, err := rule.Apply(&hostManifest)
	assert.NoError(t, err)
	assert.NotNil(t, result)
	assert.Equal(t, len(result.Faults), 1)
	assert.Equal(t, result.Faults[0].Name, FaultPcrValueMissing)
	t.Logf("Fault description: %s", result.Faults[0].Description)
	assert.False(t, result.Trusted)
}

func TestPcrMatchesConstantNoFault(t *testing.T) {

	expectedPcr := types.Pcr {
		Index: 0,
		Value: PCR_VALID_256,
		PcrBank:  types.SHA256,
	}

	hostManifest := types.HostManifest{
		PcrManifest: types.PcrManifest{
			Sha256Pcrs : []types.Pcr {
				{
					Index: 0,
					Value: PCR_VALID_256,
					PcrBank:  types.SHA256,
				},
			},
		},
	}

	rule, err := newPcrMatchesConstant(&expectedPcr)
	assert.NoError(t, err)

	result, err := rule.Apply(&hostManifest)
	assert.NoError(t, err)
	assert.NotNil(t, result)
	assert.Equal(t, len(result.Faults), 0)
	assert.True(t, result.Trusted)
}
