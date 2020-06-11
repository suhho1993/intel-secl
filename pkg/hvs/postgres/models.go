/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package postgres

import (
	"encoding/json"
	"github.com/intel-secl/intel-secl/v3/pkg/model/hvs"
	"time"

	"database/sql/driver"
	"github.com/google/uuid"
	"github.com/intel-secl/intel-secl/v3/pkg/hvs/domain/models"
	"github.com/pkg/errors"
)

type (
	PGJsonStrMap map[string]interface{}
	PGFlavorMatchPolicies hvs.FlavorMatchPolicyCollection

	flavorGroup struct {
		ID                    uuid.UUID             `json:"id" gorm:"primary_key;type:uuid"`
		Name                  string                `json:"name"`
		FlavorTypeMatchPolicy PGFlavorMatchPolicies `json:"flavor_type_match_policy,omitempty" sql:"type:JSONB"`
	}
	// Define all struct types here

	queue struct {
		Id        uuid.UUID         `json:"id,omitempty" gorm:"primary_key; unique;type:uuid"`
		Action    string            `json:"action"`
		Params    PGJsonStrMap      `json:"-" sql:"type:JSONB NOT NULL DEFAULT '{}'::JSONB"`
		CreatedAt time.Time         `json:"created" `
		UpdatedAt time.Time         `json:"updated"`
		State     models.QueueState `json:"state"`
		Message   string            `json:"message,omitempty"`
	}
)

// no trace comments here as it is a high frequency function.
func (qp PGJsonStrMap) Value() (driver.Value, error) {
	return json.Marshal(qp)
}

func (qp *PGJsonStrMap) Scan(value interface{}) error {
	// no trace comments here as it is a high frequency function.
	b, ok := value.([]byte)
	if !ok {
		return errors.New("postgres/queue_store:PGJsonStrMap_Scan() - type assertion to []byte failed")
	}

	return json.Unmarshal(b, &qp)
}

func (fmp PGFlavorMatchPolicies) Value() (driver.Value, error) {
	return json.Marshal(fmp)
}

func (fmp *PGFlavorMatchPolicies) Scan(value interface{}) error {
	b, ok := value.([]byte)
	if !ok {
		return errors.New("postgres/queue_store:PGFlavorMatchPolicies_Scan() - type assertion to []byte failed")
	}
	return json.Unmarshal(b, &fmp)
}