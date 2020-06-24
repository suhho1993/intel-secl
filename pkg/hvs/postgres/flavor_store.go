/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package postgres

import (
	"github.com/google/uuid"
	"github.com/intel-secl/intel-secl/v3/pkg/hvs/domain/models"
	hcTypes "github.com/intel-secl/intel-secl/v3/pkg/lib/host-connector/types"
	"github.com/intel-secl/intel-secl/v3/pkg/model/hvs"
	"github.com/jinzhu/gorm"
	"github.com/pkg/errors"
	"reflect"
	"time"
)

type FlavorStore struct {
	Store *DataStore
}

func NewFlavorStore(store *DataStore) *FlavorStore {
	return &FlavorStore{store}
}

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
		flavorPartsWithLatestMap, err := getFlavorPartsWithLatest(flavorFilter.FlavorParts, flavorFilter.FlavorPartsWithLatest)
		if err != nil {
			defaultLog.WithError(err).Error("Error while getting the list of flavor parts with latest match policy")
			return nil, errors.Wrap(err, "postgres/flavor_store:Search() failed to search flavors with flavor filter criteria")
		}
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

func buildMultipleFlavorPartQueryString(tx *gorm.DB, fgId uuid.UUID, hostManifest *hcTypes.HostManifest, flavorPartsWithLatest map[string]bool) *gorm.DB {
	// TODO: to be implemented
	return tx
}

func getFlavorPartsWithLatest(flavorParts, latestFlavorParts []string) (map[string]bool, error) {
	flavorPartWithLatest := make(map[string]bool)
	if len(flavorParts) >= 1 {
		for _, flavorPart := range flavorParts {
			flavorPartWithLatest[flavorPart] = false
		}
	}

	if len(latestFlavorParts) >= 1 {
		for _, flavorPart := range latestFlavorParts {
			flavorPartWithLatest[flavorPart] = true
		}
	}
	return flavorPartWithLatest, nil
}

func findFlavorByKeyValue(tx *gorm.DB, key, value string) *gorm.DB {
	defaultLog.Trace("postgres/flavor_store:findFlavorByKeyValue() Entering")
	defer defaultLog.Trace("postgres/flavor_store:findFlavorByKeyValue() Leaving")

	if tx == nil || key == "" || value == "" {
		return nil
	}
	tx = tx.Model(&flavor{}).Select("content, signature").Where(`content @> '{ "meta": {"description": {"` + key + `":"` + value + `"}}}'`)
	return tx
}

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

func (f *FlavorStore) Delete(flavorId uuid.UUID) error {
	defaultLog.Trace("postgres/flavor_store:Delete() Entering")
	defer defaultLog.Trace("postgres/flavor_store:Delete() Leaving")

	dbFlavor := flavor{
		ID: flavorId,
	}
	if err := f.Store.Db.Delete(&dbFlavor).Error; err != nil {
		return errors.Wrap(err, "postgres/flavor_store:Delete() failed to delete Flavor")
	}
	return nil
}
