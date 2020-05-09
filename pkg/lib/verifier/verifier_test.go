/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package verifier

import (
	"encoding/json"
	"testing"

	"intel-secl/v3/pkg/lib/host-connector/types"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

const (
	PCR_VALID_256   = "00000000000000000000"
	PCR_INVALID_256 = "deadbeefdeadbeefdead"
)

func TestMockExample(t *testing.T) {

	hostManifest := types.HostManifest{}
	signedFlavor := SignedFlavor{}
	certficates := VerifierCertificates{}
	trustReport := TrustReport{}

	v, err := NewMockVerifier(certficates)
	assert.NoError(t, err)

	v.On("Verify", &hostManifest, &signedFlavor, mock.Anything).Return(&trustReport, nil)

	report, err := v.Verify(&hostManifest, &signedFlavor, true)
	assert.NoError(t, err)
	assert.NotNil(t, report)
}

func TestPcrMatchesConstantMismatch(t *testing.T) {

	hostManifest := types.HostManifest{
		PcrManifest: types.PcrManifest{
			Sha256Pcrs : []types.Pcr {
				{
					Index: 0,
					Value: PCR_INVALID_256, // host pcr is invalid
					PcrBank:  types.SHA256,
				},
			},
		},
	}

	signedFlavor := SignedFlavor{
		PcrManifest: &types.PcrManifest{
			Sha256Pcrs : []types.Pcr {
				{
					Index: 0,
					Value: PCR_VALID_256, // flavor pcr is valid
					PcrBank:  types.SHA256,
				},
			},
		},
	}

	v, err := NewVerifier(VerifierCertificates{})
	assert.NoError(t, err)

	trustReport, err := v.Verify(&hostManifest, &signedFlavor, true)
	assert.NoError(t, err)
	assert.NotNil(t, trustReport)
	assert.False(t, trustReport.Trusted)

	json, err := json.Marshal(trustReport)
	assert.NoErrot(t, err)
	t.Log(string(json))
}

//-------------------------------------------------------------------------------------------------
// M O C K   V E R I F I E R
//-------------------------------------------------------------------------------------------------

type MockVerifier struct {
	mock.Mock
	certificates VerifierCertificates
}

func NewMockVerifier(certificates VerifierCertificates) (*MockVerifier, error) {
	return &MockVerifier{certificates: certificates}, nil
}

func (v *MockVerifier) Verify(hostManifest *types.HostManifest, signedFlavor *SignedFlavor, skipFlavorSignatureVerification bool) (*TrustReport, error) {
	args := v.Called(hostManifest, signedFlavor, skipFlavorSignatureVerification)
	return args.Get(0).(*TrustReport), args.Error(1)
}
