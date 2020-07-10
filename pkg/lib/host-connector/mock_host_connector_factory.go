/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package host_connector

import (
	"crypto/x509"
	"encoding/json"
	"github.com/intel-secl/intel-secl/v3/pkg/clients/vmware"
	"github.com/intel-secl/intel-secl/v3/pkg/lib/host-connector/constants"
	"github.com/intel-secl/intel-secl/v3/pkg/lib/host-connector/types"
	"github.com/intel-secl/intel-secl/v3/pkg/lib/host-connector/util"
	taModel "github.com/intel-secl/intel-secl/v3/pkg/model/ta"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/mock"
	"io/ioutil"
	"os"
)

// MockHostConnectorFactory is required for mocking the HostConnector dependency in flows involving HostConnector
// using MockedHostConnector in its place
type MockHostConnectorFactory struct{}

// NewHostConnector returns a mocked instance of VendorConnector passing in a MockedTAClient or a MockVMwareClient as required
func (htcFactory MockHostConnectorFactory) NewHostConnector(connectionString string) (HostConnector, error) {
	vendorConnector, _ := util.GetConnectorDetails(connectionString)
	var connectorFactory VendorHostConnectorFactory
	switch vendorConnector.Vendor {
	case constants.INTEL, constants.MICROSOFT:
		connectorFactory = &MockIntelConnectorFactory{}
	case constants.VMWARE:
		connectorFactory = &MockVmwareConnectorFactory{}
	default:
		return nil, errors.New("mock_host_connector_factory:NewHostConnector() Vendor not supported yet: " + vendorConnector.Vendor)
	}
	return connectorFactory.GetHostConnector(vendorConnector, "", nil)
}

// MockIntelConnectorFactory implements the VendorConnectorFactory interface
type MockIntelConnectorFactory struct{}

// GetHostConnector returns an instance of IntelConnector passing in a MockedTAClient
func (micf MockIntelConnectorFactory) GetHostConnector(vendorConnector types.VendorConnector, aasApiUrl string, trustedCaCerts []x509.Certificate) (HostConnector, error) {
	mhc := MockIntelConnector{}

	// AnythingOfType allows us to wildcard the digest hash since this will be computed at runtime
	mhc.On("DeployAssetTag", "7a569dad-2d82-49e4-9156-069b0065b262", mock.AnythingOfType("string")).Return(nil)
	mhc.On("DeployAssetTag", "00e4d709-8d72-44c3-89ae-c5edc395d6fe", mock.AnythingOfType("string")).Return(errors.New("Error deploying tag"))

	// Mock GetHostDetails
	var hostInfo taModel.HostInfo
	hostInfoJson, _ := os.Open("../../lib/host-connector/test/sample_platform_info.json")
	hostInfoBytes, _ := ioutil.ReadAll(hostInfoJson)
	_ = json.Unmarshal(hostInfoBytes, &hostInfo)
	mhc.On("GetHostDetails").Return(hostInfo, nil)

	// Mock GetHostManifest
	var hm types.HostManifest
	hmBytes, _ := ioutil.ReadFile("../../lib/host-connector/test/sample_host_manifest.json")
	_ = json.Unmarshal(hmBytes, &hm)
	mhc.On("GetHostManifest").Return(hm, nil)

	return &mhc, nil
}

// MockVmwareConnectorFactory implements the VendorConnectorFactory interface
type MockVmwareConnectorFactory struct{}

// GetHostConnector returns an instance of VmwareConnector passing in a MockVMwareClient
func (micf MockVmwareConnectorFactory) GetHostConnector(vendorConnector types.VendorConnector, aasApiUrl string, trustedCaCerts []x509.Certificate) (HostConnector, error) {
	return &VmwareConnector{&vmware.MockVMWareClient{}}, nil
}
