/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package flavor

import (
	"encoding/json"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestImageFlavorCreationWithEncryption(t *testing.T) {
	flavorInput, err := GetImageFlavor("Cirros-Enc-Label", true,
		"http://kbs.server.com:20080/v1/keys/73755fda-c910-46be-821f-e8ddeab189e9/transfer",
		"261209df1789073192285e4e408addadb35068421ef4890a5d4d434")
	assert.NoError(t, err)
	flavor, err := json.Marshal(flavorInput)
	assert.NoError(t, err)
	assert.NotNil(t, flavor)
}

func TestImageFlavorWithoutEncryption(t *testing.T) {
	flavorInput, err := GetImageFlavor("Cirros-Label", false, "", "")
	assert.NoError(t, err)
	flavor, err := json.Marshal(flavorInput)
	assert.NoError(t, err)
	assert.NotNil(t, flavor)
}
