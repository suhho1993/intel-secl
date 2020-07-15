/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package postgres

import (
	"fmt"
	"github.com/google/uuid"
	"github.com/intel-secl/intel-secl/v3/pkg/hvs/domain/models"
	"github.com/intel-secl/intel-secl/v3/pkg/model/hvs"
	"github.com/jinzhu/gorm"
	"github.com/pkg/errors"
	"strings"
)

type FlavorGroupStore struct {
	Store *DataStore
}

func NewFlavorGroupStore(store *DataStore) *FlavorGroupStore {
	return &FlavorGroupStore{store}
}

func (f *FlavorGroupStore) Create(fg *hvs.FlavorGroup) (*hvs.FlavorGroup, error) {
	defaultLog.Trace("postgres/flavorgroup_store:Create() Entering")
	defer defaultLog.Trace("postgres/flavorgroup_store:Create() Leaving")

	fg.ID = uuid.New()
	dbFlavorGroup := &flavorGroup{
		ID:                    fg.ID,
		Name:                  fg.Name,
		FlavorTypeMatchPolicy: PGFlavorMatchPolicies(fg.MatchPolicies),
	}

	if err := f.Store.Db.Create(&dbFlavorGroup).Error; err != nil {
		return nil, errors.Wrap(err, "postgres/flavorgroup_store:Create() failed to create Flavorgroup")
	}
	return fg, nil
}

func (f *FlavorGroupStore) Retrieve(flavorGroupId uuid.UUID) (*hvs.FlavorGroup, error) {
	defaultLog.Trace("postgres/flavorgroup_store:Retrieve() Entering")
	defer defaultLog.Trace("postgres/flavorgroup_store:Retrieve() Leaving")

	fg := hvs.FlavorGroup{}
	row := f.Store.Db.Model(&flavorGroup{}).Where(&flavorGroup{ID: flavorGroupId}).Row()
	if err := row.Scan(&fg.ID, &fg.Name, (*PGFlavorMatchPolicies)(&fg.MatchPolicies)); err != nil {
		return nil, errors.Wrap(err, "postgres/flavorgroup_store:Retrieve() failed to scan record")
	}
	return &fg, nil
}

func (f *FlavorGroupStore) Search(fgFilter *models.FlavorGroupFilterCriteria) (*hvs.FlavorgroupCollection, error) {
	defaultLog.Trace("postgres/flavorgroup_store:Search() Entering")
	defer defaultLog.Trace("postgres/flavorgroup_store:Search() Leaving")

	tx := buildFlavorGroupSearchQuery(f.Store.Db, fgFilter)

	if tx == nil {
		return nil, errors.New("postgres/flavorgroup_store:Search() Unexpected Error. Could not build" +
			" a gorm query object in FlavorGroups Search function.")
	}

	rows, err := tx.Rows()
	if err != nil {
		return nil, errors.Wrap(err, "postgres/flavorgroup_store:Search() failed to retrieve records from db")
	}
	defer rows.Close()

	flavorgroupCollection := hvs.FlavorgroupCollection{Flavorgroups: []*hvs.FlavorGroup{}}
	for rows.Next() {
		fg := hvs.FlavorGroup{}
		if err := rows.Scan(&fg.ID, &fg.Name, (*PGFlavorMatchPolicies)(&fg.MatchPolicies)); err != nil {
			return nil, errors.Wrap(err, "postgres/flavorgroup_store:Search() failed to scan record")
		}
		flavorgroupCollection.Flavorgroups = append(flavorgroupCollection.Flavorgroups, &fg)
	}

	return &flavorgroupCollection, nil
}

func (f *FlavorGroupStore) Delete(flavorGroupId uuid.UUID) error {
	defaultLog.Trace("postgres/flavorgroup_store:Delete() Entering")
	defer defaultLog.Trace("postgres/flavorgroup_store:Delete() Leaving")

	dbFlavorGroup := flavorGroup{
		ID: flavorGroupId,
	}
	if err := f.Store.Db.Delete(&dbFlavorGroup).Error; err != nil {
		return errors.Wrap(err, "postgres/flavorgroup_store:Delete() failed to delete Flavorgroup")
	}
	return nil
}

// helper function to build the query object for a FlavorGroup search.
func buildFlavorGroupSearchQuery(tx *gorm.DB, fgFilter *models.FlavorGroupFilterCriteria) *gorm.DB {
	defaultLog.Trace("postgres/flavorgroup_store:buildFlavorGroupSearchQuery() Entering")
	defer defaultLog.Trace("postgres/flavorgroup_store:buildFlavorGroupSearchQuery() Leaving")

	if tx == nil {
		return nil
	}

	tx = tx.Model(&flavorGroup{})
	if fgFilter == nil {
		return tx
	}

	if fgFilter.Id != "" {
		tx = tx.Where("id = ?", fgFilter.Id)
	} else if fgFilter.NameEqualTo != "" {
		tx = tx.Where("name = ?", fgFilter.NameEqualTo)
	} else if fgFilter.NameContains != "" {
		tx = tx.Where("name like ? ", "%"+fgFilter.NameContains+"%")
	}
	//TODO: Add search for hostId
	return tx
}

// create flavorgroup-flavor association
func (f *FlavorGroupStore) AddFlavors(fgId uuid.UUID, fIds []uuid.UUID) ([]uuid.UUID, error) {
	defaultLog.Trace("postgres/flavorgroup_store:AddFlavors() Entering")
	defer defaultLog.Trace("postgres/flavorgroup_store:AddFlavors() Leaving")
	if len(fIds) <= 0 || fgId == uuid.Nil {
		return nil, errors.New("postgres/flavorgroup_store:AddFlavors()- invalid input : must have flavorId and flavorgroupId to associate flavorgroup with the flavor")
	}

	fgfValues := []string{}
	fgfValueArgs := []interface{}{}
	for _, fId := range fIds {
		fgfValues = append(fgfValues, "(?, ?)")
		fgfValueArgs = append(fgfValueArgs, fgId)
		fgfValueArgs = append(fgfValueArgs, fId)
	}

	insertQuery := fmt.Sprintf("INSERT INTO flavorgroup_flavor VALUES %s", strings.Join(fgfValues, ","))
	err := f.Store.Db.Model(flavorgroupFlavor{}).Exec(insertQuery, fgfValueArgs...).Error
	if err != nil {
		return nil, errors.Wrap(err, "postgres/flavorgroup_store:AddFlavors() failed to create flavorgroup-flavor association")
	}
	return fIds, nil
}

// delete flavorgroup-flavor association
func (f *FlavorGroupStore) RemoveFlavors(fgId uuid.UUID, fIds []uuid.UUID) error {
	defaultLog.Trace("postgres/flavorgroup_store:RemoveFlavors() Entering")
	defer defaultLog.Trace("postgres/flavorgroup_store:RemoveFlavors() Leaving")

	if (fgId == uuid.Nil && len(fIds) <=0) {
		return errors.New("postgres/flavorgroup_store:RemoveFlavors()- invalid input : must have flavorId or flavorgroupId to delete flavorgroup-flavor association")
	}
	tx := f.Store.Db
	if fgId != uuid.Nil {
		tx = tx.Where("flavorgroup_id = ?", fgId)
	}

	if len(fIds) >=1 {
		tx = tx.Where("flavor_id IN (?)", fIds)
	}

	if err := tx.Delete(&flavorgroupFlavor{}).Error ; err != nil {
		return errors.Wrap(err, "postgres/flavorgroup_store:RemoveFlavors() failed to delete flavorgroup-flavor association")
	}
	return nil
}

// search flavorgroup-flavor association
func (f *FlavorGroupStore) SearchFlavors(fgId uuid.UUID) ([]uuid.UUID, error) {
	defaultLog.Trace("postgres/flavorgroup_store:SearchFlavors() Entering")
	defer defaultLog.Trace("postgres/flavorgroup_store:SearchFlavors() Leaving")

	if fgId == uuid.Nil {
		return nil, errors.New("postgres/flavorgroup_store:SearchFlavors() Flavorgroup ID must be set to search through flavorgroup-flavor association")
	}

	dbfgfl := flavorgroupFlavor{
		FlavorgroupId: fgId,
	}

	rows, err := f.Store.Db.Model(&flavorgroupFlavor{}).Select("flavor_id").Where(&dbfgfl).Rows()
	if err != nil {
		return nil, errors.Wrap(err, "postgres/flavorgroup_store:SearchFlavors() failed to retrieve records from db")
	}
	defer rows.Close()

	flavorIds := []uuid.UUID{}

	for rows.Next() {
		flavorId := uuid.UUID{}
		if err := rows.Scan(&flavorId); err != nil {
			return nil, errors.Wrap(err, "postgres/flavorgroup_store:SearchFlavors() failed to scan record")
		}
		flavorIds = append(flavorIds, flavorId)
	}
	return flavorIds, nil
}