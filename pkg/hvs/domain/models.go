/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package domain

import "github.com/google/uuid"

type (
	TlsPolicy struct {
		Id           uuid.UUID `json:"id,omitempty" gorm:"primary_key;type:uuid"`
		Name         string    `json:"name"`
		Comment      string    `json:"comment"`
		PrivateScope bool      `json:"private"`
		ContentType  string    `json:"content_type"`
		Content      []byte    `json:"content"`
	}

	// Define all struct types independent of DataStore here
)
