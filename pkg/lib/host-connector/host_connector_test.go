/*
 *  Copyright (C) 2020 Intel Corporation
 *  SPDX-License-Identifier: BSD-3-Clause
 */

package host_connector

import (
	"encoding/json"
	"github.com/stretchr/testify/assert"
	"intel-secl/v3/pkg/lib/host-connector/types"
	"io/ioutil"
	"testing"
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
