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
	PGJsonStrMap            map[string]interface{}
	PGFlavorMatchPolicies   hvs.FlavorMatchPolicies
	PGHostManifest          types.HostManifest
	PGHostStatusInformation hvs.HostStatusInformation
	PGFlavorContent         hvs.Flavor

	flavorGroup struct {
		ID                    uuid.UUID             `json:"id" gorm:"primary_key;type:uuid"`
		Name                  string                `json:"name"`
		FlavorTypeMatchPolicy PGFlavorMatchPolicies `json:"flavor_type_match_policy,omitempty" sql:"type:JSONB"`
	}

	flavor struct {
		ID         uuid.UUID       `json:"id" gorm:"primary_key;type:uuid"`
		Content    PGFlavorContent `json:"flavor" sql:"type:JSONB"`
		CreatedAt  time.Time       `json:"created"`
		Label      string          `gorm:"unique;not null"`
		FlavorPart string          `json:"flavor_part"`
		Signature  string          `json:"signature"`
	}

	host struct {
		Id               uuid.UUID `gorm:"primary_key;type:uuid"`
		Name             string    `gorm:"type:varchar(255);not null;index:idx_host_hostname"`
		Description      string
		ConnectionString string    `gorm:"not null"`
		HardwareUuid     uuid.UUID `gorm:"type:uuid;index:idx_host_hardware_uuid"`
	}

	flavorgroupFlavors struct {
		FlavorgroupId uuid.UUID   `gorm:"primary_key;not null"`
		FlavorId      uuid.UUID   `gorm:"primary_key;not null"`
	}

	trustCache struct {
		FlavorId uuid.UUID `gorm:"primary_key;not null"`
		HostId   uuid.UUID `gorm:"primary_key;not null"`
	}

	hostCredential struct {
		Id           uuid.UUID `gorm:"primary_key;type:uuid"`
		HostId       uuid.UUID `gorm:"type:uuid;index:idx_host_credential_host_id"`
		HostName     string    `gorm:"type:varchar(255);index:idx_host_credential_hostname"`
		HardwareUuid uuid.UUID `gorm:"type:uuid;index:idx_host_credential_hardware_uuid"`
		Credential   string
		CreatedTs    time.Time
	}

	// hostStatus holds all the hostStatus records for VS-attested hosts
	hostStatus struct {
		ID         uuid.UUID               `gorm:"primary_key;type:uuid"`
		HostID     uuid.UUID               `sql:"type:uuid REFERENCES hosts(Id)"`
		Status     PGHostStatusInformation `gorm:"column:status" sql:"type:JSONB"`
		HostReport PGHostManifest          `gorm:"column:host_report" sql:"type:JSONB"`
		CreatedAt  time.Time               `gorm:"column:created;not null"`
	}

	esxiCluster struct {
		Id               uuid.UUID `gorm:"primary_key;type:uuid"`
		ConnectionString string    `gorm:"column:connection_string;not null"`
		ClusterName      string    `gorm:"column:cluster_name;type:varchar(255);not null"`
	}

	queue struct {
		Id        uuid.UUID         `json:"id,omitempty" gorm:"primary_key; unique;type:uuid"`
		Action    string            `json:"action"`
		Params    PGJsonStrMap      `json:"-" sql:"type:JSONB NOT NULL DEFAULT '{}'::JSONB"`
		CreatedAt time.Time         `json:"created"`
		UpdatedAt time.Time         `json:"updated"`
		State     models.QueueState `json:"state"`
		Message   string            `json:"message,omitempty"`
	}

	PGTrustReport         hvs.TrustReport
	report struct {
		ID          uuid.UUID     `gorm:"id,omitempty" gorm:"primary_key;"`
		HostID      uuid.UUID     `gorm:"host_id" gorm:"unique;type:uuid;not null;index:idx_report_host_id"`
		TrustReport PGTrustReport `gorm:"column:trust_report; not null" sql:"type:JSONB"`
		CreatedAt   time.Time     `gorm:"column:created;not null"`
		Expiration  time.Time     `gorm:"column:expiration;not null"`
		Saml        string        `gorm:"column:saml;not null"`
	}

	tpmEndorsement struct {
		ID           uuid.UUID `gorm:"id,omitempty" gorm:"primary_key;type:uuid"`
		HardwareUUID uuid.UUID `gorm:"hardware_uuid;not null"`
		Issuer       string    `gorm:"issuer;not null"`
		Revoked      bool      `gorm:"revoked,omitempty" `
		Certificate  string    `gorm:"certificate;not null"`
		Comment      string    `gorm:"comment,omitempty"`
	}

	tagCertificate struct {
		ID uuid.UUID `gorm:"primary_key; type:uuid"`
		// TODO: Do we need to link this to Host.Hardware_UUID?
		HardwareUUID uuid.UUID `gorm:"not null; type:uuid; column:hardware_uuid"`
		Certificate  []byte    `gorm:"not null; type:bytea"`
		Subject      string    `gorm:"not null"`
		Issuer       string    `gorm:"not null"`
		NotBefore    time.Time `gorm:"not null; column:notbefore"`
		NotAfter     time.Time `gorm:"not null; column:notafter"`
	}
)

func (trustCache) TableName() string {
	return "trust_cache"
}

func (qp PGJsonStrMap) Value() (driver.Value, error) {
	return json.Marshal(qp)
}

func (qp *PGJsonStrMap) Scan(value interface{}) error {
	// no trace comments here as it is a high frequency function.
	b, ok := value.([]byte)
	if !ok {
		return errors.New("postgres/models:PGJsonStrMap_Scan() - type assertion to []byte failed")
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
		return errors.New("postgres/models:PGHostStatusInformation_Scan() - type assertion to []byte failed")
	}

	return json.Unmarshal(b, &hm)
}

func (fmp PGFlavorMatchPolicies) Value() (driver.Value, error) {
	return json.Marshal(fmp)
}

func (fmp *PGFlavorMatchPolicies) Scan(value interface{}) error {
	b, ok := value.([]byte)
	if !ok {
		return errors.New("postgres/models:PGFlavorMatchPolicies_Scan() - type assertion to []byte failed")
	}
	return json.Unmarshal(b, &fmp)
}

func (trp PGTrustReport) Value() (driver.Value, error) {
	return json.Marshal(trp)
}

func (trp *PGTrustReport) Scan(value interface{}) error {
	b, ok := value.([]byte)
	if !ok {
		return errors.New("postgres/models:PGTrustReport_Scan() - type assertion to []byte failed")
	}
	return json.Unmarshal(b, &trp)
}

func (fl PGFlavorContent) Value() (driver.Value, error) {
	return json.Marshal(fl)
}

func (fl *PGFlavorContent) Scan(value interface{}) error {
	b, ok := value.([]byte)
	if !ok {
		return errors.New("postgres/models:PGFlavorContent_Scan() - type assertion to []byte failed")
	}
	return json.Unmarshal(b, &fl)
}
