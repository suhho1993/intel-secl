/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */

package hvs

import "github.com/google/uuid"

// TpmEndorsement struct
type TpmEndorsement struct {
	ID           uuid.UUID `json:"id,omitempty"`
	HardwareUUID uuid.UUID `json:"hardware_uuid"`
	Issuer       string    `json:"issuer,omitempty"`
	Revoked      bool      `json:"revoked,omitempty"`
	Certificate  string    `json:"certificate"`
	Comment      string    `json:"comment,omitempty"`
}

type TpmEndorsementCollection struct {
	TpmEndorsement []*TpmEndorsement `json:"tpmendorsements"`
}
