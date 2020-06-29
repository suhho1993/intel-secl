/*
 *  Copyright (C) 2020 Intel Corporation
 *  SPDX-License-Identifier: BSD-3-Clause
 */

package host_connector

import (
	"crypto/x509"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestNewHostConnector(t *testing.T) {

	sampleUrl1 := "intel:https://ta.ip.com:1443;u=admin;p=password"
	aasurl := "https://aas.url.com:8444/aas"
	var caCertMap []x509.Certificate
	hostConnector, err := NewHostConnector(sampleUrl1, aasurl, caCertMap)
	assert.NoError(t, err, nil)
	assert.NotEqual(t, hostConnector, nil)

	invalidURL := "intel:https:// ta.ip.com:1443;u=admin;p=password"
	hostConnector, err = NewHostConnector(invalidURL, aasurl, caCertMap)
	assert.Error(t, err)
	assert.Equal(t, hostConnector, nil)

	unknownVendorURL := "xyz:https://ta.ip.com:1443;u=admin;p=password"
	hostConnector, err = NewHostConnector(unknownVendorURL, aasurl, caCertMap)
	assert.Error(t, err)
	assert.Equal(t, hostConnector, nil)
}