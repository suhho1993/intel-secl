/*
 *  Copyright (C) 2020 Intel Corporation
 *  SPDX-License-Identifier: BSD-3-Clause
 */

package host_connector

import (
	"encoding/json"
	"encoding/xml"
	"github.com/stretchr/testify/assert"
	"github.com/intel-secl/intel-secl/v3/pkg/lib/host-connector/types"
	"github.com/intel-secl/intel-secl/v3/pkg/clients/ta"
	taModel "github.com/intel-secl/intel-secl/v3/pkg/model/ta"
	"github.com/stretchr/testify/mock"
	"io/ioutil"
	"testing"
	"net/url"
)

func TestHostManifestParsing(t *testing.T) {
	log.Trace("resource/flavors_test:TestHostManifestParsing() Entering")
	defer log.Trace("resource/flavors_test:TestHostManifestParsing() Leaving")

	var hostManifest types.HostManifest
	readBytes, err := ioutil.ReadFile("./test/sample_host_manifest.txt")
	assert.Equal(t, err, nil)
	err = json.Unmarshal(readBytes, &hostManifest)
	assert.Equal(t, err, nil)
	log.Info("Host Manifest : ", hostManifest)
}

func TestCreateHostManifestFromSampleData(t *testing.T) {

	// create a mock ta client that will return dummy data to host-connector
	mockTAClient, err := ta.NewMockTAClient()

	// read sample tpm quote that will be returned by the mock client
	var tpmQuoteResponse taModel.TpmQuoteResponse
	b, err := ioutil.ReadFile("./test/sample_tpm_quote.xml")
	assert.NoError(t, err)
	err = xml.Unmarshal(b, &tpmQuoteResponse)
	assert.NoError(t, err)
	mockTAClient.On("GetTPMQuote", mock.Anything, mock.Anything, mock.Anything).Return(tpmQuoteResponse, nil)

	// read sample platform-info that will be returned my the mock client
	var hostInfo taModel.HostInfo
	b, err = ioutil.ReadFile("./test/sample_platform_info.json")
	assert.NoError(t, err)
	err = json.Unmarshal(b, &hostInfo)
	assert.NoError(t, err)
	mockTAClient.On("GetHostInfo").Return(hostInfo, nil)
	
	// read the aik that will be returned by the mock
	aik, err := ioutil.ReadFile("./test/aik.der")
	assert.NoError(t, err)
	mockTAClient.On("GetAIK").Return(aik, nil)

	// the sample data in ./test was collected from 168.63 -- this is needed
	// for the nonce to verify...
	baseUrl, err := url.Parse("http://10.105.168.63:1443/")
	assert.NoError(t, err)
	mockTAClient.On("GetBaseURL").Return(baseUrl, nil)

	// binding key is only applicable to workload-agent (skip for now)
	mockTAClient.On("GetBindingKeyCertificate").Return([]byte{}, nil)

	// create an intel host connector and collect the manifest
	intelConnector := IntelConnector {
		client : mockTAClient,
	}

	// the sample data in ./test used this nonce which needs to be provided to GetHostManifest...
	nonce := "3FvsK0fpHg5qtYuZHn1MriTMOxc="

	hostManifest, err := intelConnector.GetHostManifest(nonce, []int {0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23}, []string {"SHA1", "SHA256"})
	assert.NoError(t, err)

	json, err := json.Marshal(hostManifest)
	assert.NoError(t, err)
	t.Log(string(json))
}
