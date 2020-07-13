/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package postgres

import (
	"github.com/google/uuid"
	"github.com/intel-secl/intel-secl/v3/pkg/hvs/domain/models"
	cf "github.com/intel-secl/intel-secl/v3/pkg/lib/flavor/common"
	hcTypes "github.com/intel-secl/intel-secl/v3/pkg/lib/host-connector/types"
	"github.com/intel-secl/intel-secl/v3/pkg/model/hvs"
	"github.com/jinzhu/gorm"
	"github.com/pkg/errors"
	"reflect"
	"strings"
	"time"
)

type FlavorStore struct {
	Store *DataStore
}

func NewFlavorStore(store *DataStore) *FlavorStore {
	return &FlavorStore{store}
}

// create flavors
func (f *FlavorStore) Create(signedFlavor *hvs.SignedFlavor) (*hvs.SignedFlavor, error) {
	defaultLog.Trace("postgres/flavor_store:Create() Entering")
	defer defaultLog.Trace("postgres/flavor_store:Create() Leaving")
	if signedFlavor == nil || signedFlavor.Signature == "" || signedFlavor.Flavor.Meta.Description.Label == "" {
		return nil, errors.New("postgres/flavor_store:Create()- invalid input : must have content, signature and the label for the flavor")
	}

	fId := uuid.New()
	signedFlavor.Flavor.Meta.ID = fId
	dbf := flavor{
		ID:         fId,
		Content:    PGFlavorContent(signedFlavor.Flavor),
		CreatedAt:  time.Time{},
		Label:      signedFlavor.Flavor.Meta.Description.Label,
		FlavorPart: signedFlavor.Flavor.Meta.Description.FlavorPart,
		Signature:  signedFlavor.Signature,
	}

	if err := f.Store.Db.Create(&dbf).Error; err != nil {
		return nil, errors.Wrap(err, "postgres/flavor_store:Create() failed to create flavor")
	}
	return signedFlavor, nil
}

func (f *FlavorStore) Search(flavorFilter *models.FlavorFilterCriteria) ([]*hvs.SignedFlavor, error) {
	defaultLog.Trace("postgres/flavor_store:Search() Entering")
	defer defaultLog.Trace("postgres/flavor_store:Search() Leaving")

	var tx *gorm.DB

	if (flavorFilter == nil || reflect.DeepEqual(flavorFilter, models.FlavorFilterCriteria{})) {
		tx = f.Store.Db.Model(&flavor{}).Select("content, signature")
	} else if flavorFilter.Id != uuid.Nil {
		tx = f.Store.Db.Model(&flavor{}).Select("content, signature").Where("id = ?", flavorFilter.Id)
	} else if flavorFilter.Key != "" || flavorFilter.Value != "" {
		tx = findFlavorByKeyValue(f.Store.Db, flavorFilter.Key, flavorFilter.Value)
	} else if flavorFilter.FlavorGroupID.String() != "" ||
		len(flavorFilter.FlavorParts) >= 1 || len(flavorFilter.FlavorPartsWithLatest) >= 1 || flavorFilter.HostManifest != nil {
		flavorPartsWithLatestMap := getFlavorPartsWithLatest(flavorFilter.FlavorParts, flavorFilter.FlavorPartsWithLatest)

		// add all flavor parts in list of flavor Parts
		tx = buildMultipleFlavorPartQueryString(tx, flavorFilter.FlavorGroupID, flavorFilter.HostManifest, flavorPartsWithLatestMap)
	} else {
		return nil, errors.New("postgres/flavor_store:Search() invalid flavor filter criteria set")
	}

	if tx == nil {
		return nil, errors.New("postgres/flavor_store:Search() Unexpected Error. Could not build gorm query object in flavor Search function")
	}

	rows, err := tx.Rows()
	if err != nil {
		return nil, errors.Wrap(err, "postgres/flavor_store:Search() failed to retrieve records from db")
	}
	defer rows.Close()

	signedFlavors := []*hvs.SignedFlavor{}

	for rows.Next() {
		sf := hvs.SignedFlavor{}
		if err := rows.Scan((*PGFlavorContent)(&sf.Flavor), &sf.Signature); err != nil {
			return nil, errors.Wrap(err, "postgres/flavor_store:Search() failed to scan record")
		}
		signedFlavors = append(signedFlavors, &sf)
	}
	return signedFlavors, nil
}

func buildMultipleFlavorPartQueryString(tx *gorm.DB, fgId uuid.UUID, hostManifest *hcTypes.HostManifest, flavorPartsWithLatest map[cf.FlavorPart]bool) *gorm.DB {
	// TODO: to be implemented
	return tx
}

// helper function used to create a map of all the flavor parts for which latest flavors has to be picked up
// FlavorRepository.java 74
func getFlavorPartsWithLatest(flavorParts, latestFlavorParts []cf.FlavorPart) map[cf.FlavorPart]bool {
	flavorPartWithLatest := make(map[cf.FlavorPart]bool)
	if len(flavorParts) >= 1 && len(latestFlavorParts) == 0{
		for _, flavorPart := range flavorParts {
			flavorPartWithLatest[flavorPart] = false
		}
		return flavorPartWithLatest
	}

	if len(latestFlavorParts) >= 1 {
		for _, flavorPart := range latestFlavorParts {
			flavorPartWithLatest[flavorPart] = true
		}
	}
	return flavorPartWithLatest
}

// helper function used to query through flavor description with a given key-value pair
func findFlavorByKeyValue(tx *gorm.DB, key, value string) *gorm.DB {
	defaultLog.Trace("postgres/flavor_store:findFlavorByKeyValue() Entering")
	defer defaultLog.Trace("postgres/flavor_store:findFlavorByKeyValue() Leaving")

	if tx == nil || key == "" || value == "" {
		return nil
	}
	tx = tx.Model(&flavor{}).Select("content, signature").Where(`content @> '{ "meta": {"description": {"` + key + `":"` + value + `"}}}'`)
	return tx
}

// retrieve flavors
func (f *FlavorStore) Retrieve(flavorId uuid.UUID) (*hvs.SignedFlavor, error) {
	defaultLog.Trace("postgres/flavor_store:Retrieve() Entering")
	defer defaultLog.Trace("postgres/flavor_store:Retrieve() Leaving")

	sf := hvs.SignedFlavor{}
	row := f.Store.Db.Model(flavor{}).Select("content, signature").Where(&flavor{ID: flavorId}).Row()
	if err := row.Scan((*PGFlavorContent)(&sf.Flavor), &sf.Signature); err != nil {
		return nil, errors.Wrap(err, "postgres/flavor_store:Retrieve() - Could not scan record ")
	}
	return &sf, nil
}

// delete flavors
func (f *FlavorStore) Delete(flavorId uuid.UUID) error {
	defaultLog.Trace("postgres/flavor_store:Delete() Entering")
	defer defaultLog.Trace("postgres/flavor_store:Delete() Leaving")

	dbFlavor := flavor{
		ID: flavorId,
	}
	if err := f.Store.Db.Where(&dbFlavor).Delete(&dbFlavor).Error; err != nil {
		return errors.Wrap(err, "postgres/flavor_store:Delete() failed to delete Flavor")
	}
	return nil
}

func (f *FlavorStore) GetUniqueFlavorTypesThatExistForHost(hwId uuid.UUID) (map[cf.FlavorPart]bool, error) {
	uniqueFlavorTypesForHost := make(map[cf.FlavorPart]bool)

	// check for HOST_UNIQUE flavor part
	hostHasHostUniqueFlavor, err := f.isHostHavingFlavorType(hwId.String(), cf.FlavorPartHostUnique.String())
	if err != nil{
		return nil, err
	}
	if hostHasHostUniqueFlavor {
		defaultLog.Debugf("Host [%s] has %s flavor type", hwId.String(), cf.FlavorPartHostUnique.String())
		uniqueFlavorTypesForHost[cf.FlavorPartHostUnique] = true
	}

	// check for ASSET_TAG flavor part
	hostHasAssetTagFlavor, err := f.isHostHavingFlavorType(hwId.String(), cf.FlavorPartAssetTag.String())
	if err != nil{
		return nil, err
	}
	if hostHasAssetTagFlavor {
		defaultLog.Debugf("Host [%s] has %s flavor type", hwId.String(), cf.FlavorPartAssetTag.String())
		uniqueFlavorTypesForHost[cf.FlavorPartAssetTag] = true
	}

	if len (uniqueFlavorTypesForHost) == 0{
		return nil, nil
	}

	return uniqueFlavorTypesForHost, nil
}

func (f *FlavorStore) GetFlavorTypesInFlavorgroup(flvGrpId uuid.UUID, flvParts []cf.FlavorPart) (map[cf.FlavorPart]bool, error) {
	flavorTypesInFlavorGroup := make(map[cf.FlavorPart]bool)
	if flvParts == nil || len(flvParts) == 0{
		flvParts = cf.GetFlavorTypes()
	}
	for _, flvrPart := range flvParts{
		flavorgroupContainsFlavorType, err := f.flavorgroupContainsFlavorType(flvGrpId.String(), flvrPart.String())
		if err != nil{
			return nil, err
		}
		if flavorgroupContainsFlavorType {
			defaultLog.Debugf("Flavorgroup [%s] contains flavor type [%s]", flvGrpId.String(), strings.Join(cf.GetFlavorTypesString(flvParts), ","))
			flavorTypesInFlavorGroup[flvrPart] = true
		}
	}

	if len(flavorTypesInFlavorGroup) == 0{
		defaultLog.Debugf("Flavorgroup [%s] does not contain flavor type [%s]", flvGrpId.String(), cf.GetFlavorTypesString(flvParts))
		return nil, nil
	}

	return flavorTypesInFlavorGroup, nil
}

//Check whether flavors exists for given flavorPart and hardware uuid, associated with host_unique flavorgroup
func (f *FlavorStore) isHostHavingFlavorType(hwId, flavorType string) (bool, error) {
	var tx *gorm.DB
	var count int
	tx = f.Store.Db.Model(&flavor{}).Joins("INNER JOIN flavorgroup_flavor as l ON flavor.id = l.flavor_id").
		Joins("INNER JOIN flavorgroup as fg ON l.flavorgroup_id = fg.id").
		Where("fg.name = 'host_unique'").
		Where("flavor.content -> 'meta' -> 'description' ->> 'flavor_part' = ?", flavorType).
		Where("LOWER(flavor.content -> 'meta' -> 'description' ->> 'hardware_uuid') = ?)", strings.ToLower(hwId))

	if err := tx.Count(&count).Error; err != nil{
		return false, errors.Wrap(err,"postgres/flavor_store:isHostHavingFlavorType() failed to execute query")
	}

	if count > 0{
		return true, nil
	}
	return false, nil
}

// Checks whether any flavors exists with given flavorPart and associated with flavorgroup for given flavorgroup Id fgId
// and which has policies with given flavorPart.
func (f *FlavorStore) flavorgroupContainsFlavorType(fgId , flavorPart string) (bool, error) {
	var tx *gorm.DB
	var count int
	tx = f.Store.Db.Model(&flavor{}).Joins("INNER JOIN flavorgroup_flavor as l ON flavor.id = l.flavor_id").
		Joins("INNER JOIN flavorgroup as fg ON l.flavorgroup_id = fg.id, json_array_elements(fg.flavor_type_match_policy ->'flavor_match_policies') policies").
		Where("fg.id = ?", fgId).
		Where("policies ->> 'flavor_part' = ?", flavorPart).
		Where("flavor.content -> 'meta' -> 'description' ->> 'flavor_part' = ?", flavorPart)

	if err := tx.Count(&count).Error; err != nil{
		return false, errors.Wrap(err,"postgres/flavor_store:flavorgroupContainsFlavorType() failed to execute query")
	}

	if count > 0{
		return true, nil
	}

	return false, nil
}
