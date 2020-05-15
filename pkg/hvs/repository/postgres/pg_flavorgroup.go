/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package postgres

import (
	"encoding/json"
	"github.com/intel-secl/intel-secl/v3/pkg/hvs/types"
	"github.com/intel-secl/intel-secl/v3/pkg/model/hvs"
	"github.com/jinzhu/gorm"
	"github.com/jinzhu/gorm/dialects/postgres"
	"github.com/pkg/errors"
	uuid "github.com/satori/go.uuid"
)

type FlavorGroupRepository struct {
	db *gorm.DB
}

func (f *FlavorGroupRepository) Create(flavorGroup *hvs.FlavorGroup) (*hvs.FlavorGroup, error) {
	defaultLog.Trace("pg_flavorgroup:Create() Entering")
	defer defaultLog.Trace("pg_flavorgroup:Create() Leaving")

	dbFlavorGroup, err := toDbFlavorGroup("", flavorGroup)
	if err != nil {
		return flavorGroup, errors.Wrap(err, "pg_flavorgroup:Create() failed to marshal to dbFlavorgroup")
	}

	newUuid, err := uuid.NewV4()
	if err == nil {
		dbFlavorGroup.Id = newUuid.String()
	} else {
		return flavorGroup, errors.Wrap(err, "pg_flavorgroup:Create() failed to get UUID")
	}
	if err := f.db.Create(&dbFlavorGroup).Error; err != nil {
		return flavorGroup, errors.Wrap(err, "pg_flavorgroup:Create() failed to create Flavorgroup")
	}
	flavorGroup, err = dbFlavorGroup.Unmarshal()
	if err != nil {
		return flavorGroup, errors.Wrap(err, "pg_flavorgroup:Create() failed to unmarshal to Flavorgroup")
	}
	return flavorGroup, nil
}

func (f *FlavorGroupRepository) Retrieve(flavorGroupId string) (*hvs.FlavorGroup, error) {
	defaultLog.Trace("pg_flavorgroup:Retrieve() Entering")
	defer defaultLog.Trace("pg_flavorgroup:Retrieve() Leaving")

	dbFlavorGroup := types.FlavorGroup{
		Id: flavorGroupId,
	}
	err := f.db.Where(&dbFlavorGroup).First(&dbFlavorGroup).Error
	if err != nil {
		return nil, errors.Wrap(err, "pg_flavorgroup:Retrieve() failed to retrieve Flavorgroup")
	}
	return dbFlavorGroup.Unmarshal()
}

func (f *FlavorGroupRepository) RetrieveAll(fgFilter *hvs.FlavorGroupFilterCriteria) (*hvs.FlavorgroupCollection, error) {
	defaultLog.Trace("pg_flavorgroup:RetrieveAll() Entering")
	defer defaultLog.Trace("pg_flavorgroup:RetrieveAll() Leaving")

	var flavorgroups *hvs.FlavorgroupCollection
	tx := buildFlavorGroupSearchQuery(f.db, fgFilter)

	if tx == nil {
		return flavorgroups, errors.New("pg_flavorgroup:RetrieveAll() Unexpected Error. Could not build" +
			" a gorm query object in FlavorGroups RetrieveAll function.")
	}

	var dbFlavorgroups []types.FlavorGroup
	if err := tx.Find(&dbFlavorgroups).Error; err != nil {
		return flavorgroups, errors.Wrap(err, "pg_flavorgroup:RetrieveAll() failed to retrieve all "+
			"Flavorgroups")
	}

	return toFlavorGroups(dbFlavorgroups)
}

func (f *FlavorGroupRepository) Delete(flavorGroupId string) error {
	defaultLog.Trace("pg_flavorgroup:Delete() Entering")
	defer defaultLog.Trace("pg_flavorgroup:Delete() Leaving")

	dbFlavorGroup := types.FlavorGroup{
		Id: flavorGroupId,
	}
	if err := f.db.Delete(&dbFlavorGroup).Error; err != nil {
		return errors.Wrap(err, "pg_flavorgroup:Delete() failed to delete Flavorgroup")
	}
	return nil
}

// helper function to build the query object for a FlavorGroup search.
func buildFlavorGroupSearchQuery(tx *gorm.DB, fgFilter *hvs.FlavorGroupFilterCriteria) *gorm.DB {
	defaultLog.Trace("pg_flavorgroup:buildFlavorGroupSearchQuery() Entering")
	defer defaultLog.Trace("pg_flavorgroup:buildFlavorGroupSearchQuery() Leaving")

	if tx == nil {
		return nil
	}

	if fgFilter == nil {
		return tx.Where(&types.FlavorGroup{})
	}
	if fgFilter.Id != "" {
		tx = tx.Where("id = ?", fgFilter.Id)
	}
	if fgFilter.NameEqualTo != "" {
		tx = tx.Where("name = ?", fgFilter.NameEqualTo)
	}
	if fgFilter.NameContains != "" {
		tx = tx.Where("name like ? ", "%"+fgFilter.NameContains+"%")
	}

	return tx
}

func toDbFlavorGroup(flavorGroupId string, flavorGroup *hvs.FlavorGroup) (*types.FlavorGroup, error) {
	defaultLog.Trace("pg_flavorgroup:toDbFlavorGroup() Entering")
	defer defaultLog.Trace("pg_flavorgroup:toDbFlavorGroup() Leaving")

	var dbFlavorGroup types.FlavorGroup

	if flavorGroup == nil {
		return &dbFlavorGroup, nil
	}

	flavorMatchPolicyCollection, err := json.Marshal(flavorGroup.FlavorMatchPolicyCollection)
	if err != nil {
		return &dbFlavorGroup, errors.Wrap(err, "pg_flavorgroup:toDbFlavorGroup() failed to marshal FlavorMatchPolicyCollection to JSON")
	}
	dbFlavorGroup = types.FlavorGroup{
		Id:                    flavorGroupId,
		Name:                  flavorGroup.Name,
		FlavorTypeMatchPolicy: postgres.Jsonb{RawMessage: flavorMatchPolicyCollection},
	}
	return &dbFlavorGroup, nil
}

func toFlavorGroups(dbFlavorgroups []types.FlavorGroup) (*hvs.FlavorgroupCollection, error) {
	defaultLog.Trace("pg_flavorgroup:toFlavorGroups() Entering")
	defer defaultLog.Trace("pg_flavorgroup:toFlavorGroups() Leaving")

	var flavorgroupCollection hvs.FlavorgroupCollection
	if dbFlavorgroups == nil || len(dbFlavorgroups) == 0 {
		flavorgroupCollection.Flavorgroups = []hvs.FlavorGroup{}
		return &flavorgroupCollection, nil
	}

	for _, dbFlavorGroup := range dbFlavorgroups {
		flavorgroup, err := dbFlavorGroup.Unmarshal()
		if err != nil {
			return &flavorgroupCollection, errors.Wrap(err, "pg_flavorgroup:toDbFlavorGroup() failed to unmarshal dbFlavorGroup")
		}
		flavorgroupCollection.Flavorgroups = append(flavorgroupCollection.Flavorgroups, *flavorgroup)
	}

	return &flavorgroupCollection, nil
}