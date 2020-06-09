/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package postgres

import (
	"encoding/json"
	"github.com/google/uuid"
	"github.com/intel-secl/intel-secl/v3/pkg/hvs/domain"
	"github.com/intel-secl/intel-secl/v3/pkg/model/hvs"
	"github.com/jinzhu/gorm"
	"github.com/pkg/errors"
	"strconv"
)

type TlsPolicyStore struct {
	Store *DataStore
}

func NewTlsPolicyStore(store *DataStore) *TlsPolicyStore {
	return &TlsPolicyStore{store}
}

func (t *TlsPolicyStore) Create(tlsPolicy *hvs.TlsPolicy) (*hvs.TlsPolicy, error) {
	defaultLog.Trace("postgres/tlspolicy_store:Create() Entering")
	defer defaultLog.Trace("postgres/tlspolicy_store:Create() Leaving")

	content, err := json.Marshal(tlsPolicy.Descriptor)
	if err != nil {
		return nil, errors.Wrap(err, "postgres/tlspolicy_store:Create() failed to marshal TlsPolicyDescriptor to bytes")
	}

	dbTlsPolicy := domain.TlsPolicy{
		Id:           uuid.New(),
		Name:         tlsPolicy.Name,
		Comment:      tlsPolicy.Comment,
		PrivateScope: tlsPolicy.PrivateScope,
		ContentType:  "application/json",
		Content:      content,
	}

	if err := t.Store.Db.Create(&dbTlsPolicy).Error; err != nil {
		return tlsPolicy, errors.Wrap(err, "postgres/tlspolicy_store:Create() failed to create TlsPolicy")
	}
	return tlsPolicy, nil
}

func (t *TlsPolicyStore) Retrieve(id uuid.UUID) (*hvs.TlsPolicy, error) {
	defaultLog.Trace("postgres/tlspolicy_store:Retrieve() Entering")
	defer defaultLog.Trace("postgres/tlspolicy_store:Retrieve() Leaving")

	var content []byte
	var contentType string
	tlsPolicy := hvs.TlsPolicy{}
	row := t.Store.Db.Model(&domain.TlsPolicy{}).Where(&domain.TlsPolicy{Id: id}).Row()
	if err := row.Scan(&tlsPolicy.Id, &tlsPolicy.Name, &tlsPolicy.Comment, &tlsPolicy.PrivateScope, &contentType, &content); err != nil {
		return nil, errors.Wrap(err, "postgres/tlspolicy_store:Retrieve() failed to scan record")
	}

	if len(content) != 0 {
		var policyDescriptor hvs.TlsPolicyDescriptor
		err := json.Unmarshal(content, &policyDescriptor)
		if err != nil {
			return nil, errors.Wrap(err, "postgres/tlspolicy_store:Retrieve() failed to unmarshal bytes to TlsPolicyDescriptor")
		}
		tlsPolicy.Descriptor = &policyDescriptor
	}

	return &tlsPolicy, nil
}

func (t *TlsPolicyStore) Update(tlsPolicy *hvs.TlsPolicy) (*hvs.TlsPolicy, error) {
	defaultLog.Trace("postgres/tlspolicy_store:Update() Entering")
	defer defaultLog.Trace("postgres/tlspolicy_store:Update() Leaving")

	content, err := json.Marshal(tlsPolicy.Descriptor)
	if err != nil {
		return nil, errors.Wrap(err, "postgres/tlspolicy_store:Update() failed to marshal TlsPolicyDescriptor to bytes")
	}

	dbTlsPolicy := domain.TlsPolicy{
		Id:           tlsPolicy.Id,
		Name:         tlsPolicy.Name,
		Comment:      tlsPolicy.Comment,
		PrivateScope: tlsPolicy.PrivateScope,
		ContentType:  "application/json",
		Content:      content,
	}

	if err := t.Store.Db.Save(&dbTlsPolicy).Error; err != nil {
		return tlsPolicy, errors.Wrap(err, "postgres/tlspolicy_store:Update() failed to update TlsPolicy")
	}
	return tlsPolicy, nil
}

func (t *TlsPolicyStore) Delete(id uuid.UUID) error {
	defaultLog.Trace("postgres/tlspolicy_store:Delete() Entering")
	defer defaultLog.Trace("postgres/tlspolicy_store:Delete() Leaving")

	if err := t.Store.Db.Delete(&domain.TlsPolicy{Id: id}).Error; err != nil {
		return errors.Wrap(err, "postgres/tlspolicy_store:Delete() failed to delete TlsPolicy")
	}
	return nil
}

func (t *TlsPolicyStore) Search(tpFilter *hvs.TlsPolicyFilterCriteria) (*hvs.TlsPolicyCollection, error) {
	defaultLog.Trace("postgres/tlspolicy_store:Search() Entering")
	defer defaultLog.Trace("postgres/tlspolicy_store:Search() Leaving")

	tx := buildTlsPolicySearchQuery(t.Store.Db, tpFilter)
	if tx == nil {
		return nil, errors.New("postgres/tlspolicy_store:Search() Unexpected Error. Could not build" +
			" a gorm query object.")
	}

	rows, err := tx.Rows()
	if err != nil {
		return nil, errors.Wrap(err, "postgres/tlspolicy_store:Search() failed to retrieve records from db")
	}
	defer rows.Close()
	tlsPolicyCollection := hvs.TlsPolicyCollection{}

	for rows.Next() {
		var content []byte
		var contentType string
		tlsPolicy := hvs.TlsPolicy{}
		if err := rows.Scan(&tlsPolicy.Id, &tlsPolicy.Name, &tlsPolicy.Comment, &tlsPolicy.PrivateScope, &contentType, &content); err != nil {
			return nil, errors.Wrap(err, "postgres/tlspolicy_store:Search() failed to scan record")
		}

		if len(content) != 0 {
			var policyDescriptor hvs.TlsPolicyDescriptor
			err := json.Unmarshal(content, &policyDescriptor)
			if err != nil {
				return nil, errors.Wrap(err, "postgres/tlspolicy_store:Retrieve() failed to unmarshal bytes to TlsPolicyDescriptor")
			}
			tlsPolicy.Descriptor = &policyDescriptor
		}

		tlsPolicyCollection.TlsPolicies = append(tlsPolicyCollection.TlsPolicies, &tlsPolicy)
	}

	return &tlsPolicyCollection, nil
}

// helper function to build the query object for a TlsPolicy search.
func buildTlsPolicySearchQuery(tx *gorm.DB, tpFilter *hvs.TlsPolicyFilterCriteria) *gorm.DB {
	defaultLog.Trace("postgres/tlspolicy_store:buildTlsPolicySearchQuery() Entering")
	defer defaultLog.Trace("postgres/tlspolicy_store:buildTlsPolicySearchQuery() Leaving")

	if tx == nil {
		return nil
	}

	tx = tx.Model(&domain.TlsPolicy{})
	if tpFilter == nil {
		return tx
	}

	if tpFilter.Id != "" {
		tx = tx.Where("id = ?", tpFilter.Id)
	} else if tpFilter.HostId != "" {
		tx = tx.Where("private=true and name = ?", tpFilter.HostId)
	} else if tpFilter.PrivateEqualTo != "" {
		private, _ := strconv.ParseBool(tpFilter.PrivateEqualTo)
		tx = tx.Where("private = ?", private)
	} else if tpFilter.NameEqualTo != "" {
		tx = tx.Where("name = ?", tpFilter.NameEqualTo)
	} else if tpFilter.NameContains != "" {
		tx = tx.Where("name like ? ", "%"+tpFilter.NameContains+"%")
	} else if tpFilter.CommentEqualTo != "" {
		tx = tx.Where("comment = ?", tpFilter.CommentEqualTo)
	} else if tpFilter.CommentContains != "" {
		tx = tx.Where("comment like ? ", "%"+tpFilter.CommentContains+"%")
	}

	return tx
}
