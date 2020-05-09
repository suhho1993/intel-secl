/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package ta

//
// This is a temporary mock until we potentialy switch to gomock (requires a module name change to "intel-sec/v3")
//
// FOR MOCKGENT TO WORK WE WILL NEED TO CHANGE OUR MODULE NAME TO CONATAIN A "DOT".  Ex...
// module intel.com/secl/v3
// Otherwise we get: malformed module path "intel-secl/v3/pkg/lib/clients/ta": missing dot in first path element
// From what I can tell -- a dot is required in the first section of module names
//go:generate mockgen -destination=mock_taclient.go -package=ta intel-secl/v3/pkg/lib/clients/ta TAClient

import (
	"github.com/stretchr/testify/mock"
	taModel "intel-secl/v3/pkg/model/ta"
	"net/url"
)

type MockTAClient struct {
	mock.Mock
}

func NewMockTAClient() (*MockTAClient, error) {
	mockTAClient := MockTAClient{}
	return &mockTAClient, nil
}

func (ta *MockTAClient) GetHostInfo() (taModel.HostInfo, error) {
	args := ta.Called()
	return args.Get(0).(taModel.HostInfo), args.Error(1)
}

func (ta *MockTAClient) GetTPMQuote(nonce string, pcrList []int, pcrBankList []string) (taModel.TpmQuoteResponse, error) {
	args := ta.Called(nonce, pcrList, pcrBankList)
	return args.Get(0).(taModel.TpmQuoteResponse), args.Error(1)
}

func (ta *MockTAClient) GetAIK() ([]byte, error) {
	args := ta.Called()
	return args.Get(0).([]byte), args.Error(1)
}

func (ta *MockTAClient) GetBindingKeyCertificate() ([]byte, error) {
	args := ta.Called()
	return args.Get(0).([]byte), args.Error(1)
}

func (ta *MockTAClient) DeployAssetTag(hardwareUUID, tag string) error {
	args := ta.Called(hardwareUUID, tag)
	return args.Error(0)
}

func (ta *MockTAClient) DeploySoftwareManifest(manifest taModel.Manifest) error {
	args := ta.Called(manifest)
	return args.Error(0)
}

func (ta *MockTAClient) GetMeasurementFromManifest(manifest taModel.Manifest) (taModel.Measurement, error) {
	args := ta.Called(manifest)
	return args.Get(0).(taModel.Measurement), args.Error(1)
}

func (ta *MockTAClient) GetBaseURL() (*url.URL) {
	args := ta.Called()
	return args.Get(0).(*url.URL)
}
