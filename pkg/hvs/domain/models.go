/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package domain

import (
	"github.com/jinzhu/gorm/dialects/postgres"
)

type (
	FlavorGroup struct {
		ID                    string         `json:"id,omitempty" gorm:"primary_key;type:uuid"`
		Name                  string         `json:"name"`
		FlavorTypeMatchPolicy *postgres.Jsonb `json:"flavor_type_match_policy" gorm:"type:json"`
	}
	// Define all struct types here
)
