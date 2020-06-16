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
	"github.com/intel-secl/intel-secl/v3/pkg/lib/host-connector/types"
	"github.com/pkg/errors"
)

// Define all struct types here
type (
	PGJsonStrMap          map[string]interface{}
	PGFlavorMatchPolicies hvs.FlavorMatchPolicyCollection

	flavorGroup struct {
		ID                    uuid.UUID             `json:"id" gorm:"primary_key;type:uuid"`
		Name                  string                `json:"name"`
		FlavorTypeMatchPolicy PGFlavorMatchPolicies `json:"flavor_type_match_policy,omitempty" sql:"type:JSONB"`
	}

	host struct {
		Id               uuid.UUID `gorm:"primary_key;type:uuid;index:idx_host_hostname"`
		Name             string    `gorm:"type:varchar(255);not null"`
		Description      string
		ConnectionString string    `gorm:"not null"`
		HardwareUuid     uuid.UUID `gorm:"type:uuid;index:idx_host_hardware_uuid"`
	}

	PGHostManifest          types.HostManifest
	PGHostStatusInformation hvs.HostStatusInformation

	// hostStatus holds all the hostStatus records for VS-attested hosts
	hostStatus struct {
		// TODO: do we need to associate with Host table using foreign_key?
		ID         uuid.UUID               `gorm:"primary_key;type:uuid"`
		HostID     uuid.UUID               `gorm:"type:uuid;not null"`
		Status     PGHostStatusInformation `gorm:"column:status" sql:"type:JSONB"`
		HostReport PGHostManifest          `gorm:"column:host_report" sql:"type:JSONB"`
		CreatedAt  time.Time               `gorm:"column:created;not null"`
	}

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

func (phm PGHostManifest) Value() (driver.Value, error) {
	return json.Marshal(phm)
}

func (phm *PGHostManifest) Scan(value interface{}) error {
	// no trace comments here as it is a high frequency function.
	b, ok := value.([]byte)
	if !ok {
		return errors.New("postgres/models:PGHostManifest_Scan() - type assertion to []byte failed")
	}

	return json.Unmarshal(b, &phm)
}

func (hm PGHostStatusInformation) Value() (driver.Value, error) {
	return json.Marshal(hm)
}

func (hm *PGHostStatusInformation) Scan(value interface{}) error {
	// no trace comments here as it is a high frequency function.
	b, ok := value.([]byte)
	if !ok {
		return errors.New("postgres/queue_store:PGHostStatusInformation_Scan() - type assertion to []byte failed")
	}

	return json.Unmarshal(b, &hm)
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
