/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package models

import (
	"github.com/google/uuid"
)

// KeyAttributes - Contains all possible key attributes.
type KeyAttributes struct {
	ID         uuid.UUID `json:"id"`
	Algorithm  string    `json:"algorithm"`
	KeyLength  int       `json:"key_length,omitempty"`
	KeyData    string    `json:"key,omitempty"`
	CurveType  string    `json:"curve_type,omitempty"`
	PublicKey  string    `json:"public_key,omitempty"`
	PrivateKey string    `json:"private_key,omitempty"`
	KmipKeyID  string    `json:"kmip_key_id,omitempty"`
}
