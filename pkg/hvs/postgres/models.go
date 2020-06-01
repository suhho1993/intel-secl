/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package postgres

import (
	"github.com/google/uuid"
	"github.com/jinzhu/gorm/dialects/postgres"
)

type (
	flavorGroup struct {
		ID                    uuid.UUID       `json:"id" gorm:"primary_key;type:uuid"`
		Name                  string          `json:"name"`
		FlavorTypeMatchPolicy *postgres.Jsonb `json:"flavor_type_match_policy" gorm:"type:json"`
	}
	// Define all struct types here
)
