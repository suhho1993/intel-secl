/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package verifier

import (
//	"github.com/pkg/errors"
	"github.com/intel-secl/intel-secl/v3/pkg/lib/host-connector/types"
)

//
// These are temporary models used to support development.
//

// type HostManifest struct {
// 	PcrManifest PcrManifest `json:"pcrs,omitempty"`
// }

type SignedFlavor struct {
	PcrManifest *types.PcrManifest `json:"pcrs,omitempty"`
}

// type PcrManifest map[SHAAlgorithm]PcrBank

// func (pcrManifest PcrManifest) GetPcrValue(bank SHAAlgorithm, index PcrIndex) (*PcrValue, error) {
// 	var pcrValue *PcrValue

// 	if pcrBank, ok := pcrManifest[bank]; ok {
// 		if pcr, ok := pcrBank[index]; ok {
// 			pcrValue = &pcr
// 		}
// 	}

// 	return pcrValue, nil
// }

// func (pcrManifest *PcrManifest) GetRequiredPcrValue(bank SHAAlgorithm, index PcrIndex) (*PcrValue, error) {
// 	pcrValue, err := pcrManifest.GetPcrValue(bank, index)
// 	if err != nil {
// 		return nil, err
// 	}

// 	if pcrValue == nil {
// 		return nil, errors.Errorf("Could not retrive PCR at bank '%s', index '%s'", bank, index)
// 	}

// 	return pcrValue, nil
// }

// type PcrBank map[PcrIndex]PcrValue

// type PcrValue struct {
// 	Index PcrIndex     `json:"index"`
// 	Bank  SHAAlgorithm `json:"pcr_bank"`
// 	Value []byte       `json:"value"` // TODO: bytes in go get serialized to base64, we want hex
// 	// TODO:  Not 'digest type' (java class name)
// }

// type PcrIndex string

// const (
// 	PCR0  PcrIndex = "pcr_0"
// 	PCR1           = "pcr_1"
// 	PCR2           = "pcr_2"
// 	PCR3           = "pcr_4"
// 	PCR4           = "pcr_5"
// 	PCR5           = "pcr_6"
// 	PCR6           = "pcr_7"
// 	PCR7           = "pcr_8"
// 	PCR8           = "pcr_9"
// 	PCR9           = "pcr_9"
// 	PCR10          = "pcr_10"
// 	PCR11          = "pcr_11"
// 	PCR12          = "pcr_12"
// 	PCR13          = "pcr_13"
// 	PCR14          = "pcr_14"
// 	PCR15          = "pcr_15"
// 	PCR16          = "pcr_16"
// 	PCR17          = "pcr_17"
// 	PCR18          = "pcr_18"
// 	PCR19          = "pcr_19"
// 	PCR20          = "pcr_20"
// 	PCR21          = "pcr_21"
// 	PCR22          = "pcr_22"
// 	PCR23          = "pcr_23"
// )

// type SHAAlgorithm string

// const (
// 	SHA1   SHAAlgorithm = "SHA1"
// 	SHA256              = "SHA256"
// 	SHA384              = "SHA384"
// 	SHA512              = "SHA512"
// )
