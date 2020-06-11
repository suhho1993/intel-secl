/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package domain

import "github.com/google/uuid"

type (
	Host struct {
		Id               uuid.UUID `json:"id,omitempty" gorm:"primary_key;type:uuid;index:idx_host_hostname"`
		Name             string    `gorm:"type:varchar(255);not null"`
		Description      string
		ConnectionString string    `gorm:"not null"`
		HardwareUuid     uuid.UUID `gorm:"type:uuid;index:idx_host_hardware_uuid"`
	}

	// Define all struct types independent of DataStore here
)
