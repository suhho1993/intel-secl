/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package postgres

import (
	"github.com/google/uuid"
	"github.com/intel-secl/intel-secl/v3/pkg/hvs/domain"
	"github.com/intel-secl/intel-secl/v3/pkg/model/hvs"
	"github.com/jinzhu/gorm"
	"github.com/pkg/errors"
)

type HostStore struct {
	Store *DataStore
}

func NewHostStore(store *DataStore) *HostStore {
	return &HostStore{store}
}

func (t *HostStore) Create(host *hvs.Host) (*hvs.Host, error) {
	defaultLog.Trace("postgres/host_store:Create() Entering")
	defer defaultLog.Trace("postgres/host_store:Create() Leaving")

	dbHost := domain.Host{
		Id:               uuid.New(),
		Name:             host.HostName,
		Description:      host.Description,
		ConnectionString: host.ConnectionString,
		HardwareUuid:     host.HardwareUuid,
	}

	if err := t.Store.Db.Create(&dbHost).Error; err != nil {
		return host, errors.Wrap(err, "postgres/host_store:Create() failed to create Host")
	}
	return host, nil
}

func (t *HostStore) Retrieve(id uuid.UUID) (*hvs.Host, error) {
	defaultLog.Trace("postgres/host_store:Retrieve() Entering")
	defer defaultLog.Trace("postgres/host_store:Retrieve() Leaving")

	host := hvs.Host{}
	row := t.Store.Db.Model(&domain.Host{}).Where(&domain.Host{Id: id}).Row()
	if err := row.Scan(&host.Id, &host.HostName, &host.Description, &host.ConnectionString, &host.HardwareUuid); err != nil {
		return nil, errors.Wrap(err, "postgres/host_store:Retrieve() failed to scan record")
	}
	return &host, nil
}

func (t *HostStore) Update(host *hvs.Host) (*hvs.Host, error) {
	defaultLog.Trace("postgres/host_store:Update() Entering")
	defer defaultLog.Trace("postgres/host_store:Update() Leaving")

	dbHost := domain.Host{
		Id:               host.Id,
		Name:             host.HostName,
		Description:      host.Description,
		ConnectionString: host.ConnectionString,
		HardwareUuid:     host.HardwareUuid,
	}

	if err := t.Store.Db.Save(&dbHost).Error; err != nil {
		return host, errors.Wrap(err, "postgres/host_store:Update() failed to update Host")
	}
	return host, nil
}

func (t *HostStore) Delete(id uuid.UUID) error {
	defaultLog.Trace("postgres/host_store:Delete() Entering")
	defer defaultLog.Trace("postgres/host_store:Delete() Leaving")

	if err := t.Store.Db.Delete(&domain.Host{Id: id}).Error; err != nil {
		return errors.Wrap(err, "postgres/host_store:Delete() failed to delete Host")
	}
	return nil
}

func (t *HostStore) Search(tpFilter *hvs.HostFilterCriteria) (*hvs.HostCollection, error) {
	defaultLog.Trace("postgres/host_store:Search() Entering")
	defer defaultLog.Trace("postgres/host_store:Search() Leaving")

	tx := buildHostSearchQuery(t.Store.Db, tpFilter)
	if tx == nil {
		return nil, errors.New("postgres/host_store:Search() Unexpected Error. Could not build" +
			" a gorm query object.")
	}

	rows, err := tx.Rows()
	if err != nil {
		return nil, errors.Wrap(err, "postgres/host_store:Search() failed to retrieve records from db")
	}
	defer rows.Close()

	hostCollection := hvs.HostCollection{}
	for rows.Next() {
		host := hvs.Host{}
		if err := rows.Scan(&host.Id, &host.HostName, &host.Description, &host.ConnectionString, &host.HardwareUuid); err != nil {
			return nil, errors.Wrap(err, "postgres/host_store:Search() failed to scan record")
		}
		hostCollection.Hosts = append(hostCollection.Hosts, &host)
	}
	return &hostCollection, nil
}

// helper function to build the query object for a Host search.
func buildHostSearchQuery(tx *gorm.DB, criteria *hvs.HostFilterCriteria) *gorm.DB {
	defaultLog.Trace("postgres/host_store:buildHostSearchQuery() Entering")
	defer defaultLog.Trace("postgres/host_store:buildHostSearchQuery() Leaving")

	if tx == nil {
		return nil
	}

	tx = tx.Model(&domain.Host{})
	if criteria == nil {
		return tx
	}

	if criteria.Id != "" {
		tx = tx.Where("id = ?", criteria.Id)
	} else if criteria.NameEqualTo != "" {
		tx = tx.Where("name = ?", criteria.NameEqualTo)
	} else if criteria.NameContains != "" {
		tx = tx.Where("name like ? ", "%"+criteria.NameContains+"%")
	} else if criteria.HostHardwareId != "" {
		tx = tx.Where("hardware_uuid = ?", criteria.HostHardwareId)
	} else if criteria.Key != "" && criteria.Value != "" {
		//TODO: fetch host ids from host_status table
	}

	return tx
}
