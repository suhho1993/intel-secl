/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package hvs

import (
	"crypto/sha512"
	"encoding/json"
	"github.com/pkg/errors"
	"github.com/intel-secl/intel-secl/v3/pkg/lib/common/crypt"
	"github.com/intel-secl/intel-secl/v3/pkg/lib/flavor/model"
	"github.com/intel-secl/intel-secl/v3/pkg/lib/host-connector/types"
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
	flavorDigest []byte 						// internal variable that stores the orignating flavor json digest used in 'SignedFlavor.Verify()'
}

type FlavorCollection struct {
	Flavors []*Flavor `json:"flavors" xml:"flavors"`
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
func NewFlavorToJson(meta *model.Meta, bios *model.Bios, hardware *model.Hardware, pcrs map[crypt.DigestAlgorithm]map[types.PcrIndex]model.PcrEx, external *model.External, software *model.Software) (string, error) {
	// Assemble the Flavor
	var flavor = NewFlavor(meta, bios, hardware, pcrs, external, software)
	// serialize it
	fj, err := json.Marshal(flavor)
	if err != nil {
		return "", err
	}
	// return JSON
	return string(fj), nil
}

// UnmarshalJSON performs the standard json unmarshalling but
// also calculates the flavor digest while json bytes are present
// to avoid redundant marshalling. 
func (flavor *Flavor) UnmarshalJSON(flavorJSON []byte) error {

	// avoid recursion by declaring and unmarhalling to a private
	// copy of the Flavor type.
	type flavorCopy Flavor
	err := json.Unmarshal(flavorJSON, (*flavorCopy)(flavor))
	if err != nil {
		return errors.Wrap(err, "Failed to unmarshal flavor json")
	}

	// now calculate the digest and store it in 'Flavor.flavorDigest'
	// so that it can be used in SignedFlavor.Verify()
	err = flavor.calculateFlavorDigest(flavorJSON) 
	if err != nil {
		return err
	}

	return nil
}


// Utility function for retreiving the PcrEx value at 'bank', 'index'.  Returns
// an error if the pcr cannot be found.
func (flavor *Flavor) GetPcrValue(bank types.SHAAlgorithm, index types.PcrIndex) (*model.PcrEx, error) {

	if indexMap, ok := flavor.Pcrs[string(bank)]; ok {
		if pcrValue, ok := indexMap[index.String()]; ok {
			return &pcrValue, nil
		} else {
			return nil, errors.Errorf("The flavor does not contain a pcr values for bank '%s', index %d", bank, index)
		}
	} else {
		return nil, errors.Errorf("The flavor does not contain any pcr values for bank '%s'", bank)
	}
}

// GetFlavorDigest Calculates the SHA384 hash of the Flavor's json data for use when 
// signing/verifying signed flavors.
func (flavor *Flavor) getFlavorDigest() ([]byte, error) {

	// if the digest has previously set, return that value.  This avoids
	// having to marshal to json and calculate the digest in the scenario
	// that the Flavor was loaded from JSON (the digest was caluated in
	// UnmarshalJSON).
	if flavor.flavorDigest != nil {
		return flavor.flavorDigest, nil
	}

	flavorJSON, err := json.Marshal(flavor)
	if err != nil {
		return nil, errors.Wrap(err, "An error occurred attempting to convert the flavor to json")
	}

	err = flavor.calculateFlavorDigest(flavorJSON)
	if err != nil {
		return nil, errors.Wrap(err, "An error occurred attempting to calculate the flavor digest")
	}

	return flavor.flavorDigest, nil
}

func (flavor *Flavor) calculateFlavorDigest(flavorJSON []byte) error {
	if flavorJSON == nil || len(flavorJSON) == 0 {
		return errors.New("The flavor json was not provided")
	}

	hashEntity := sha512.New384()
	hashEntity.Write(flavorJSON)
	flavor.flavorDigest = hashEntity.Sum(nil)

	return nil
}