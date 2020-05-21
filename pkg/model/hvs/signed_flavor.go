/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package hvs

import (
	"encoding/json"
	"github.com/pkg/errors"
)

/**
 *
 * @author mullas
 */

// SignedFlavor combines the Flavor along with the cryptographically signed hash that authenticates its source
type SignedFlavor struct {
	Flavor    Flavor `json:"flavor"`
	Signature string `json:"signature"`
}

// NewSignedFlavorFromJSON returns an instance of SignedFlavor from an JSON string
func NewSignedFlavorFromJSON(sfstring string) (*SignedFlavor, error) {
	var sf SignedFlavor
	err := json.Unmarshal([]byte(sfstring), &sf)
	if err != nil {
		err = errors.Wrapf(err, "Error unmarshaling SignedFlavor JSON: %s", err.Error())
		return nil, err
	}
	return &sf, nil
}
