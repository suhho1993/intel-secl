/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package hvs

import (
	"encoding/json"
	"github.com/intel-secl/intel-secl/v3/pkg/lib/common/crypt"
	"github.com/intel-secl/intel-secl/v3/pkg/lib/flavor/model"
	"github.com/intel-secl/intel-secl/v3/pkg/lib/host-connector/types"
	"github.com/pkg/errors"
)

/**
 *
 * @author mullas
 */

// Flavor struct
type Flavor struct {
	Meta     *model.Meta                       `json:"meta"`
	Validity *model.Validity                   `json:"validity,omitempty"`
	Bios     *model.Bios                       `json:"bios,omitempty"`
	Hardware *model.Hardware                   `json:"hardware,omitempty"`
	Pcrs     map[string]map[string]model.PcrEx `json:"pcrs,omitempty"`
	External *model.External                   `json:"external,omitempty"`
	Software *model.Software                   `json:"software,omitempty"`
}

// NewFlavor returns a new instance of Flavor
func NewFlavor(meta *model.Meta, bios *model.Bios, hardware *model.Hardware, pcrs map[crypt.DigestAlgorithm]map[types.PcrIndex]model.PcrEx, external *model.External, software *model.Software) *Flavor {
	// Since maps are hard to marshal as JSON, let's try to convert the DigestAlgorithm and PcrIndex to strings
	pcrx := make(map[string]map[string]model.PcrEx)
	for dA, shaBank := range pcrs {
		pcrx[dA.String()] = make(map[string]model.PcrEx)
		for pI, pE := range shaBank {
			pcrx[dA.String()][pI.String()] = pE
		}
	}
	return &Flavor{
		Meta:     meta,
		Bios:     bios,
		Hardware: hardware,
		Pcrs:     pcrx,
		External: external,
		Software: software,
	}

}

// NewFlavorToJson is a convenience method that returns a new instance of Flavor in JSON format ready for export
func NewFlavorToJson(meta *model.Meta, bios *model.Bios, hardware *model.Hardware, pcrs map[crypt.DigestAlgorithm]map[types.PcrIndex]model.PcrEx, external *model.External, software *model.Software, errorMsg string) (string, error) {
	// Assemble the Flavor
	var flavor = NewFlavor(meta, bios, hardware, pcrs, external, software)
	// serialize it
	fj, err := json.Marshal(flavor)
	if err != nil {
		err = errors.Wrapf(err, "%s - JSON marshal failure", errorMsg)
		return "", err
	}
	// return JSON
	return string(fj), nil
}
