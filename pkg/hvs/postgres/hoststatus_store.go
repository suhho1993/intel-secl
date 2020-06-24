/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package postgres

import (
	"github.com/google/uuid"
	"github.com/intel-secl/intel-secl/v3/pkg/hvs/domain/models"
	"github.com/intel-secl/intel-secl/v3/pkg/model/hvs"
	"github.com/jinzhu/gorm"
	"github.com/pkg/errors"
	"strings"
	"time"
)

type HostStatusStore struct {
	Store *DataStore
}

func NewHostStatusStore(store *DataStore) *HostStatusStore {
	return &HostStatusStore{store}
}

// Create creates a HostStatus record in the DB
func (hss *HostStatusStore) Create(hs *hvs.HostStatus) (*hvs.HostStatus, error) {
	defaultLog.Trace("postgres/hoststatus_store:Create() Entering")
	defer defaultLog.Trace("postgres/hoststatus_store:Create() Leaving")

	dbHostStatus := hostStatus{
		ID:         uuid.New(),
		HostID:     hs.HostID,
		Status:     PGHostStatusInformation(hs.HostStatusInformation),
		HostReport: PGHostManifest(hs.HostManifest),
		CreatedAt:  time.Now(),
	}

	if err := hss.Store.Db.Create(&dbHostStatus).Error; err != nil {
		return nil, errors.Wrap(err, "postgres/hoststatus_store:Create() failed to create hostStatus")
	}

	return hs, nil
}

// Retrieve retrieves a single HostStatus record matching a provided hostStatusId
func (hss *HostStatusStore) Retrieve(hostStatusId uuid.UUID) (*hvs.HostStatus, error) {
	defaultLog.Trace("postgres/hoststatus_store:Retrieve() Entering")
	defer defaultLog.Trace("postgres/hoststatus_store:Retrieve() Leaving")

	dbHostStatus := hostStatus{
		ID: hostStatusId,
	}

	row := hss.Store.Db.Model(&dbHostStatus).Where(&dbHostStatus).Row()
	result := hvs.HostStatus{}
	if err := row.Scan(&result.ID, &result.HostID, (*PGHostStatusInformation)(&result.HostStatusInformation), &result.Created, (*PGHostManifest)(&result.HostManifest)); err != nil {
		return nil, errors.Wrap(err, "postgres/hoststatus_store:Retrieve() failed to retrieve hostStatus")
	}

	return &result, nil
}

// Search retrieves a HostStatusCollection pertaining to a user-provided HostStatusFilterCriteria
func (hss *HostStatusStore) Search(hsFilter *models.HostStatusFilterCriteria) (*hvs.HostStatusCollection, error) {
	defaultLog.Trace("postgres/hoststatus_store:Search() Entering")
	defer defaultLog.Trace("postgres/hoststatus_store:Search() Leaving")

	tx := buildHostStatusSearchQuery(hss.Store.Db, hsFilter)

	if tx == nil {
		return nil, errors.New("postgres/hoststatus_store:Search() Unexpected Error. Could not build" +
			" a gorm query object in HostStatus Search function.")
	}

	rows, err := tx.Rows()
	if err != nil {
		return nil, errors.Wrap(err, "postgres/hoststatus_store:Search() failed to retrieve records from db")
	}
	defer rows.Close()

	hsCollection := hvs.HostStatusCollection{}
	hsCollection.HostStatuses = []hvs.HostStatus{}

	for rows.Next() {
		result := hvs.HostStatus{}

		if err := rows.Scan(&result.ID, &result.HostID, (*PGHostStatusInformation)(&result.HostStatusInformation), (*PGHostManifest)(&result.HostManifest), &result.Created); err != nil {
			return nil, errors.Wrap(err, "postgres/hoststatus_store:Search() failed to scan record")
		}
		hsCollection.HostStatuses = append(hsCollection.HostStatuses, result)
	}
	return &hsCollection, nil
}

func (hss *HostStatusStore) Update(hs *hvs.HostStatus) error {
	defaultLog.Trace("postgres/hoststatus_store:Update() Entering")
	defer defaultLog.Trace("postgres/hoststatus_store:Update() Leaving")

	if hs.ID == uuid.Nil {
		return errors.New("postgres/hoststatus_store:Update() - ID is invalid")
	}

	dbHostStatus := hostStatus{
		ID:         hs.ID,
		HostID:     hs.HostID,
		Status:     PGHostStatusInformation(hs.HostStatusInformation),
		HostReport: PGHostManifest(hs.HostManifest),
	}

	if db := hss.Store.Db.Model(&dbHostStatus).Updates(&dbHostStatus); db.Error != nil || db.RowsAffected != 1 {
		if db.Error != nil {
			return errors.Wrap(db.Error, "postgres/hoststatus_store:Update() failed to update HostStatus  "+hs.ID.String())
		} else {
			return errors.New("postgres/hoststatus_store:Update() - no rows affected - Record not found = id :  " + hs.ID.String())
		}

	}
	return nil
}

func (hss *HostStatusStore) Delete(hostStatusId uuid.UUID) error {
	defaultLog.Trace("postgres/hoststatus_store:Delete() Entering")
	defer defaultLog.Trace("postgres/hoststatus_store:Delete() Leaving")

	dbHostStatus := hostStatus{
		ID: hostStatusId,
	}
	if err := hss.Store.Db.Delete(&dbHostStatus).Error; err != nil {
		return errors.Wrap(err, "postgres/hoststatus_store:Delete() failed to delete HostStatus")
	}
	return nil
}

// buildHostStatusSearchQuery is a helper function to build the query object for a hostStatus search.
func buildHostStatusSearchQuery(tx *gorm.DB, hsFilter *models.HostStatusFilterCriteria) *gorm.DB {
	defaultLog.Trace("postgres/hoststatus_store:buildHostStatusSearchQuery() Entering")
	defer defaultLog.Trace("postgres/hoststatus_store:buildHostStatusSearchQuery() Leaving")

	// handle nil condition
	if tx == nil {
		return nil
	}

	tx = tx.Model(&hostStatus{})

	// TODO: and ensure latest HostStatus is returned per host - by default true
	// TODO: AuditTable and Host Table joins
	// latestPerHost := true

	// no criteria are specified
	if hsFilter == nil {
		defaultLog.Info("postgres/hoststatus_store:buildHostStatusSearchQuery() No criteria specified in search query" +
			". Returning all rows.")
		return tx
	}

	// Host Status ID
	if hsFilter.Id != uuid.Nil {
		tx = tx.Where("id = ?", hsFilter.Id)
	}

	// Host UUID
	if hsFilter.HostId != uuid.Nil {
		tx = tx.Where("host_id = ?", hsFilter.HostId)
	}

	// HWUUID
	if hsFilter.HostHardwareId != uuid.Nil {
		tx = tx.Where(`host_report @> '{"host_info": {"hardware_uuid": "` + hsFilter.HostHardwareId.String() + `"}}'`)
	}

	// AIK Cert
	if hsFilter.AikCertificate != "" {
		tx = tx.Where(`host_report @> '{"aik_certificate": "` + hsFilter.AikCertificate + `"}'`)

	}

	// HostName
	if hsFilter.HostName != "" {
		tx = tx.Where(`host_report @> '{"host_info": {"host_name": "` + hsFilter.HostName + `"}}'`)
	}

	// Host Connection Status
	if hsFilter.HostStatus != "" {
		tx = tx.Where(`status @> '{"host_state": "` + strings.ToUpper(hsFilter.HostStatus) + `"}'`)
	}

	// Number of days and Date Filters are mutually exclusive
	if hsFilter.NumberOfDays != 0 {
		// first parse numDays
		curTime := time.Now()
		prevTime := curTime.AddDate(0, 0, -hsFilter.NumberOfDays)
		tx = tx.Where("created >= ?", prevTime)
	} else if !hsFilter.FromDate.IsZero() || !hsFilter.ToDate.IsZero() {
		// determine what dates params are set - try all combinations till one matches up
		if !hsFilter.FromDate.IsZero() && hsFilter.ToDate.IsZero() {
			tx = tx.Where("created >= ?", hsFilter.FromDate)
		} else if hsFilter.FromDate.IsZero() && !hsFilter.ToDate.IsZero() {
			tx = tx.Where("created <= ? ", hsFilter.ToDate)
		} else if !hsFilter.FromDate.IsZero() && !hsFilter.ToDate.IsZero() {
			tx = tx.Where("created >= ? AND created <= ? ", hsFilter.FromDate, hsFilter.ToDate)
		}
	}

	// apply result limits
	tx = tx.Limit(hsFilter.Limit)

	return tx
}