/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package verifier

//
// Run unit tests: go test github.com/intel-secl/intel-secl/v3/pkg/lib/verifier
//
// coverage report...
// go test github.com/intel-secl/intel-secl/v3/pkg/lib/verifier -v -coverpkg=github.com/intel-secl/intel-secl/v3/pkg/lib/verifier -coverprofile cover.out
// go tool cover -func cover.out

import (
	"encoding/json"
	"testing"
	"github.com/intel-secl/intel-secl/v3/pkg/lib/host-connector/types"
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

// WIP
func TestVerifierIntegration(t *testing.T) {

	// simulate host manifest...
	hostManifest := types.HostManifest{
		AssetTagDigest: invalidAssetTagString,
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

	// Simulate flavor...
	signedFlavor := SignedFlavor{
		Flavor: Flavor {
			PcrManifest: &types.PcrManifest{
				Sha256Pcrs : []types.Pcr {
					{
						Index: 0,
						Value: PCR_VALID_256,
						PcrBank:  types.SHA256,
					},
				},
			},
			External: &External {
				AssetTag: AssetTag {
					TagCertificate: TagCertificate {
						Encoded: validAssetTagBytes,
					},
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
	assert.NoError(t, err)
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
