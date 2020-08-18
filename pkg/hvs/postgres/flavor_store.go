/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package postgres

import (
	"github.com/google/uuid"
	"github.com/intel-secl/intel-secl/v3/pkg/hvs/domain/models"
	fc "github.com/intel-secl/intel-secl/v3/pkg/lib/flavor/common"
	fConst "github.com/intel-secl/intel-secl/v3/pkg/lib/flavor/constants"
	"github.com/intel-secl/intel-secl/v3/pkg/model/hvs"
	"github.com/jinzhu/gorm"
	"github.com/pkg/errors"
	"strconv"
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

	if signedFlavor.Flavor.Meta.ID == uuid.Nil {
		signedFlavor.Flavor.Meta.ID = uuid.New()
	}

	dbf := flavor{
		ID:         signedFlavor.Flavor.Meta.ID,
		Content:    PGFlavorContent(signedFlavor.Flavor),
		CreatedAt:  time.Now(),
		Label:      signedFlavor.Flavor.Meta.Description.Label,
		FlavorPart: signedFlavor.Flavor.Meta.Description.FlavorPart,
		Signature:  signedFlavor.Signature,
	}

	if err := f.Store.Db.Create(&dbf).Error; err != nil {
		return nil, errors.Wrap(err, "postgres/flavor_store:Create() failed to create flavor")
	}
	return signedFlavor, nil
}

func (f *FlavorStore) Search(flavorFilter *models.FlavorVerificationFC) ([]hvs.SignedFlavor, error) {
	defaultLog.Trace("postgres/flavor_store:Search() Entering")
	defer defaultLog.Trace("postgres/flavor_store:Search() Leaving")

	var tx *gorm.DB
	var err error

	tx = f.Store.Db.Table("flavor f").Select("f.id, f.content, f.signature")
	// build partial query with all the given flavor Id's
	if len(flavorFilter.FlavorFC.Ids) > 0 {
		var flavorIds []string
		for _, fId := range flavorFilter.FlavorFC.Ids {
			flavorIds = append(flavorIds, fId.String())
		}
		tx = tx.Where("f.id IN (?)", flavorFilter.FlavorFC.Ids)
	}
	// build partial query with the given key-value pair from falvor description
	if flavorFilter.FlavorFC.Key != "" && flavorFilter.FlavorFC.Value != "" {
		tx = tx.Where("f.content -> 'meta' -> 'description' ->> ? = ?", flavorFilter.FlavorFC.Key, flavorFilter.FlavorFC.Value)
	}
	if flavorFilter.FlavorFC.FlavorgroupID.String() != "" ||
		len(flavorFilter.FlavorFC.FlavorParts) >= 1 || len(flavorFilter.FlavorPartsWithLatest) >= 1 || flavorFilter.FlavorMeta != nil || len(flavorFilter.FlavorMeta) >= 1 {
		if len(flavorFilter.FlavorFC.FlavorParts) >= 1 {
			flavorFilter.FlavorPartsWithLatest = getFlavorPartsWithLatestMap(flavorFilter.FlavorFC.FlavorParts, flavorFilter.FlavorPartsWithLatest)
		}
		// add all flavor parts in list of flavor Parts
		tx = f.buildMultipleFlavorPartQueryString(tx, flavorFilter.FlavorFC.FlavorgroupID, flavorFilter.FlavorMeta, flavorFilter.FlavorPartsWithLatest)
	}

	if tx == nil {
		return nil, errors.New("postgres/flavor_store:Search() Unexpected Error. Could not build gorm query" +
			" object in flavor Search function")
	}

	rows, err := tx.Rows()
	if err != nil {
		return nil, errors.Wrap(err, "postgres/flavor_store:Search() failed to retrieve records from db")
	}
	defer rows.Close()

	signedFlavors := []hvs.SignedFlavor{}

	for rows.Next() {
		sf := hvs.SignedFlavor{}
		if err := rows.Scan(&sf.Flavor.Meta.ID, (*PGFlavorContent)(&sf.Flavor), &sf.Signature); err != nil {
			return nil, errors.Wrap(err, "postgres/flavor_store:Search() failed to scan record")
		}
		signedFlavors = append(signedFlavors, sf)
	}
	return signedFlavors, nil
}

func (f *FlavorStore) buildMultipleFlavorPartQueryString(tx *gorm.DB, fgId uuid.UUID, flavorMetaMap map[fc.FlavorPart]map[string]interface{}, flavorPartsWithLatest map[fc.FlavorPart]bool) *gorm.DB {
	defaultLog.Trace("postgres/flavor_store:buildMultipleFlavorPartQueryString() Entering")
	defer defaultLog.Trace("postgres/flavor_store:buildMultipleFlavorPartQueryString() Leaving")

	var biosQuery *gorm.DB
	var osQuery *gorm.DB
	var aTagQuery *gorm.DB
	var softwareQuery *gorm.DB
	var hostUniqueQuery *gorm.DB

	if flavorPartsWithLatest != nil && len(flavorPartsWithLatest) >= 1 {
		for flavorPart := range flavorPartsWithLatest {
			switch flavorPart {
			case fc.FlavorPartPlatform:
				biosQuery = f.Store.Db
				biosQuery = buildFlavorPartQueryStringWithFlavorParts(fc.FlavorPartPlatform.String(), fgId.String(), biosQuery)
				// build biosQuery
				if len(flavorMetaMap) >= 1 && len(flavorMetaMap[fc.FlavorPartPlatform]) >= 1 {
					platformFlavorMetaInfo := flavorMetaMap[fc.FlavorPartPlatform]
					// check if tboot_installed exists in the map
					if _, ok := platformFlavorMetaInfo["tboot_installed"]; ok {
						biosQuery = biosQuery.Where("f.content -> 'meta' -> 'description' ->> 'tboot_installed' = ?", strconv.FormatBool(platformFlavorMetaInfo["tboot_installed"].(bool)))
					}
					if _, ok := platformFlavorMetaInfo["bios_name"]; ok {
						biosQuery = biosQuery.Where("f.content -> 'bios' ->> 'bios_name' = ?", platformFlavorMetaInfo["bios_name"])
					}
					if _, ok := platformFlavorMetaInfo["bios_version"]; ok {
						biosQuery = biosQuery.Where("f.content -> 'bios' ->> 'bios_version' = ?", platformFlavorMetaInfo["bios_version"])
					}
					if _, ok := platformFlavorMetaInfo["hardware_features"]; ok {
						platformHwFeaturesMap := platformFlavorMetaInfo["hardware_features"]
						hwFeatureMap := platformHwFeaturesMap.(map[string]string)
						for feature, value := range hwFeatureMap {
							if feature != fConst.Cbnt+"-profile" {
								biosQuery = biosQuery.Where("f.content -> 'hardware' -> 'feature' -> ? ->> 'enabled' = ?", feature, value)
								if feature == fConst.Cbnt {
									biosQuery = biosQuery.Where("f.content -> 'hardware' -> 'feature' -> ? ->> 'profile' = ?", feature, hwFeatureMap[fConst.Cbnt+"-profile"])
								}
							}
						}
					}
				}
				if flavorPartsWithLatest[fc.FlavorPartPlatform] {
					biosQuery = biosQuery.Order("f.created_at desc").Limit(1)
				}

			case fc.FlavorPartOs:
				osQuery = f.Store.Db
				osQuery = buildFlavorPartQueryStringWithFlavorParts(fc.FlavorPartOs.String(), fgId.String(), osQuery)
				// build biosQuery
				if len(flavorMetaMap) >= 1 && len(flavorMetaMap[fc.FlavorPartOs]) >= 1 {
					osFlavorMetaInfo := flavorMetaMap[fc.FlavorPartOs]
					// check if tboot_installed exists in the map
					if _, ok := osFlavorMetaInfo["tboot_installed"]; ok {
						osQuery = osQuery.Where("f.content -> 'meta' -> 'description' ->> 'tboot_installed' = ?", strconv.FormatBool(osFlavorMetaInfo["tboot_installed"].(bool)))
					}
					if _, ok := osFlavorMetaInfo["os_name"]; ok {
						osQuery = osQuery.Where("f.content -> 'meta' -> 'description'->> 'os_name' = ?", osFlavorMetaInfo["os_name"])

					}
					if _, ok := osFlavorMetaInfo["os_version"]; ok {
						osQuery = osQuery.Where("f.content -> 'meta' -> 'description'->> 'os_version' = ?", osFlavorMetaInfo["os_version"])

					}
					if _, ok := osFlavorMetaInfo["vmm_name"]; ok {
						osQuery = osQuery.Where("f.content -> 'meta' -> 'description'->> 'vmm_name' = ?", osFlavorMetaInfo["vmm_name"])

					}
					if _, ok := osFlavorMetaInfo["vmm_version"]; ok {
						osQuery = osQuery.Where("f.content -> 'meta' -> 'description'->> 'vmm_version' = ?", osFlavorMetaInfo["vmm_version"])

					}
				}
				if flavorPartsWithLatest[fc.FlavorPartOs] {
					osQuery = osQuery.Order("f.created_at desc").Limit(1)
				}

			case fc.FlavorPartHostUnique:
				hostUniqueQuery = f.Store.Db
				hostUniqueFlavorMetaInfo := flavorMetaMap[fc.FlavorPartHostUnique]
				hostUniqueQuery = hostUniqueQuery.Table("flavor f")
				hostUniqueQuery = hostUniqueQuery.Select("f.id")
				hostUniqueQuery = hostUniqueQuery.Where("f.content -> 'meta' -> 'description' ->> 'flavor_part' = ?", fc.FlavorPartHostUnique.String())
				if _, ok := hostUniqueFlavorMetaInfo["tboot_installed"]; ok {
					hostUniqueQuery = hostUniqueQuery.Where("f.content -> 'meta' -> 'description' ->> 'tboot_installed' = ?", strconv.FormatBool(hostUniqueFlavorMetaInfo["tboot_installed"].(bool)))
				}
				if _, ok := hostUniqueFlavorMetaInfo["hardware_uuid"]; ok {
					hostUniqueQuery = hostUniqueQuery.Where("f.content -> 'meta' -> 'description' ->> 'hardware_uuid' = ?", strings.ToLower(hostUniqueFlavorMetaInfo["hardware_uuid"].(string)))
				}

				if flavorPartsWithLatest[fc.FlavorPartHostUnique] {
					hostUniqueQuery = hostUniqueQuery.Order("f.created_at desc").Limit(1)
				}

			case fc.FlavorPartSoftware:
				softwareQuery = f.Store.Db
				softwareQuery = buildFlavorPartQueryStringWithFlavorParts(fc.FlavorPartSoftware.String(), fgId.String(), softwareQuery)
				softwareFlavorMetaInfo := flavorMetaMap[fc.FlavorPartSoftware]
				if _, ok := softwareFlavorMetaInfo["measurementXML_labels"]; ok {
					softwareQuery = softwareQuery.Where("f.label IN (?)", softwareFlavorMetaInfo["measurementXML_labels"])
				}
				if flavorPartsWithLatest[fc.FlavorPartSoftware] {
					softwareQuery = softwareQuery.Order("f.created_at desc").Limit(1)
				}

			case fc.FlavorPartAssetTag:
				aTagQuery = f.Store.Db
				aTagQuery = aTagQuery.Table("flavor f").Select("f.id").Where("f.content -> 'meta' -> 'description' ->> 'flavor_part' = ?", fc.FlavorPartAssetTag)
				aTagFlavorMetaInfo := flavorMetaMap[fc.FlavorPartAssetTag]
				if _, ok := aTagFlavorMetaInfo["hardware_uuid"]; ok {
					aTagQuery = aTagQuery.Where("f.content -> 'meta' -> 'description' ->> 'hardware_uuid' = ?", aTagFlavorMetaInfo["hardware_uuid"])
				}
				if flavorPartsWithLatest[fc.FlavorPartAssetTag] {
					aTagQuery = aTagQuery.Order("f.created_at desc").Limit(1)
				}

			default:
				defaultLog.Error("postgres/flavor_store:buildMultipleFlavorPartQueryString() Invalid flavor part")
				return nil
			}
		}
	}

	subQuery := tx
	// add bios query to sub query
	if biosQuery != nil {
		biosSubQuery := biosQuery.SubQuery()
		subQuery = subQuery.Where("f.id IN ?", biosSubQuery)
	}
	// add OS query string to sub query
	if osQuery != nil {
		osSubQuery := osQuery.SubQuery()
		if biosQuery != nil {
			subQuery = subQuery.Or("f.id IN ?", osSubQuery)
		} else {
			subQuery = subQuery.Where("f.id IN ?", osSubQuery)
		}
	}
	// add software query to sub query
	if softwareQuery != nil {
		softwareSubQuery := softwareQuery.SubQuery()
		if biosQuery != nil || osQuery != nil {
			subQuery = subQuery.Or("f.id IN ?", softwareSubQuery)
		} else {
			subQuery = subQuery.Where("f.id IN ?", softwareSubQuery)
		}
	}
	// add asset tag query to sub query
	if aTagQuery != nil {
		aTagSubQuery := aTagQuery.SubQuery()
		if biosQuery != nil || osQuery != nil || softwareQuery != nil {
			subQuery = subQuery.Or("f.id IN ?", aTagSubQuery)
		} else {
			subQuery = subQuery.Where("f.id IN ?", aTagSubQuery)
		}
	}
	// add host-unique query to sub query
	if hostUniqueQuery != nil {
		hostUniqueSubQuery := hostUniqueQuery.SubQuery()
		if biosQuery != nil || osQuery != nil || softwareQuery != nil || aTagQuery != nil {
			subQuery = subQuery.Or("f.id IN ?", hostUniqueSubQuery)
		} else {
			subQuery = subQuery.Where("f.id IN ?", hostUniqueSubQuery)
		}
	}
	// check if none of the flavor part queries are not formed,
	if subQuery != nil && (biosQuery != nil || aTagQuery != nil || softwareQuery != nil || hostUniqueQuery != nil || osQuery != nil) {
		tx = subQuery
	} else if fgId != uuid.Nil {
		fgSubQuery := buildFlavorPartQueryStringWithFlavorgroup(fgId.String(), tx).SubQuery()
		tx = tx.Where("f.id IN ?", fgSubQuery)
	}
	return tx
}

func buildFlavorPartQueryStringWithFlavorParts(flavorpart, flavorgroupId string, tx *gorm.DB) *gorm.DB {
	defaultLog.Trace("postgres/flavor_store:buildFlavorPartQueryStringWithFlavorParts() Entering")
	defer defaultLog.Trace("postgres/flavor_store:buildFlavorPartQueryStringWithFlavorParts() Leaving")

	if flavorgroupId != "" && uuid.MustParse(flavorgroupId) != uuid.Nil {
		subQuery := buildFlavorPartQueryStringWithFlavorgroup(flavorgroupId, tx)
		tx = subQuery.Where("f.content -> 'meta' -> 'description' ->> 'flavor_part' = ?", flavorpart)
	} else {
		tx = tx.Table("flavor f").Select("f.id").Joins("INNER JOIN flavorgroup_flavor fgf ON f.id = fgf.flavor_id")
		tx = tx.Joins("INNER JOIN flavor_group fg ON fgf.flavorgroup_id = fg.id")
		tx = tx.Where("f.content -> 'meta' -> 'description' ->> 'flavor_part' = ?", flavorpart)
	}
	return tx
}

func buildFlavorPartQueryStringWithFlavorgroup(flavorgroupId string, tx *gorm.DB) *gorm.DB {
	defaultLog.Trace("postgres/flavor_store:buildFlavorPartQueryStringWithFlavorgroup() Entering")
	defer defaultLog.Trace("postgres/flavor_store:buildFlavorPartQueryStringWithFlavorgroup() Leaving")

	tx = tx.Table("flavor f").Select("f.id").Joins("INNER JOIN flavorgroup_flavor fgf ON f.id = fgf.flavor_id")
	tx = tx.Joins("INNER JOIN flavor_group fg ON fgf.flavorgroup_id = fg.id")
	tx = tx.Where("fg.id = ?", flavorgroupId)
	return tx
}

// helper function used to add the list of flavor parts in the map[flavorPart]bool, indicating if latest flavor is required
func getFlavorPartsWithLatestMap(flavorParts []fc.FlavorPart, flavorPartsWithLatestMap map[fc.FlavorPart]bool) map[fc.FlavorPart]bool {
	if len(flavorParts) <= 0 {
		return flavorPartsWithLatestMap
	}
	if len(flavorPartsWithLatestMap) <= 0 {
		flavorPartsWithLatestMap = make(map[fc.FlavorPart]bool)
	}
	for _, flavorPart := range flavorParts {
		if _, ok := flavorPartsWithLatestMap[flavorPart]; !ok {
			flavorPartsWithLatestMap[flavorPart] = false
		}
	}

	return flavorPartsWithLatestMap
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

func (f *FlavorStore) GetUniqueFlavorTypesThatExistForHost(hwId uuid.UUID) (map[fc.FlavorPart]bool, error) {
	uniqueFlavorTypesForHost := make(map[fc.FlavorPart]bool)

	// check for HOST_UNIQUE flavor part
	hostHasHostUniqueFlavor, err := f.isHostHavingFlavorType(hwId.String(), fc.FlavorPartHostUnique.String())
	if err != nil {
		return nil, err
	}
	if hostHasHostUniqueFlavor {
		defaultLog.Debugf("Host [%s] has %s flavor type", hwId.String(), fc.FlavorPartHostUnique.String())
		uniqueFlavorTypesForHost[fc.FlavorPartHostUnique] = true
	}

	// check for ASSET_TAG flavor part
	hostHasAssetTagFlavor, err := f.isHostHavingFlavorType(hwId.String(), fc.FlavorPartAssetTag.String())
	if err != nil {
		return nil, err
	}
	if hostHasAssetTagFlavor {
		defaultLog.Debugf("Host [%s] has %s flavor type", hwId.String(), fc.FlavorPartAssetTag.String())
		uniqueFlavorTypesForHost[fc.FlavorPartAssetTag] = true
	}

	if len(uniqueFlavorTypesForHost) == 0 {
		return nil, nil
	}

	return uniqueFlavorTypesForHost, nil
}

func (f *FlavorStore) GetFlavorTypesInFlavorgroup(flvGrpId uuid.UUID, flvParts []fc.FlavorPart) (map[fc.FlavorPart]bool, error) {
	flavorTypesInFlavorGroup := make(map[fc.FlavorPart]bool)
	if flvParts == nil || len(flvParts) == 0 {
		flvParts = fc.GetFlavorTypes()
	}
	for _, flvrPart := range flvParts {
		flavorgroupContainsFlavorType, err := f.flavorgroupContainsFlavorType(flvGrpId.String(), flvrPart.String())
		if err != nil {
			return nil, err
		}
		if flavorgroupContainsFlavorType {
			defaultLog.Debugf("Flavorgroup [%s] contains flavor type [%s]", flvGrpId.String(), strings.Join(fc.GetFlavorTypesString(flvParts), ","))
			flavorTypesInFlavorGroup[flvrPart] = true
		}
	}

	if len(flavorTypesInFlavorGroup) == 0 {
		defaultLog.Debugf("Flavorgroup [%s] does not contain flavor type [%s]", flvGrpId.String(), fc.GetFlavorTypesString(flvParts))
		return nil, nil
	}

	return flavorTypesInFlavorGroup, nil
}

//Check whether flavors exists for given flavorPart and hardware uuid, associated with host_unique flavorgroup
func (f *FlavorStore) isHostHavingFlavorType(hwId, flavorType string) (bool, error) {
	var tx *gorm.DB
	var count int
	tx = f.Store.Db.Model(&flavor{}).Joins("INNER JOIN flavorgroup_flavor as l ON flavor.id = l.flavor_id").
		Joins("INNER JOIN flavor_group as fg ON l.flavorgroup_id = fg.id").
		Where("fg.name = 'host_unique'").
		Where("flavor.content -> 'meta' -> 'description' ->> 'flavor_part' = ?", flavorType).
		Where("LOWER(flavor.content -> 'meta' -> 'description' ->> 'hardware_uuid') = ?", strings.ToLower(hwId))

	if err := tx.Count(&count).Error; err != nil {
		return false, errors.Wrap(err, "postgres/flavor_store:isHostHavingFlavorType() failed to execute query")
	}

	if count > 0 {
		return true, nil
	}
	return false, nil
}

// Checks whether any flavors exists with given flavorPart and associated with flavorgroup for given flavorgroup Id fgId
// and which has policies with given flavorPart.
func (f *FlavorStore) flavorgroupContainsFlavorType(fgId, flavorPart string) (bool, error) {
	var tx *gorm.DB
	var count int

	tx = f.Store.Db.Model(&flavor{}).Joins("INNER JOIN flavorgroup_flavor as l ON flavor.id = l.flavor_id").
		Joins("INNER JOIN flavor_group as fg ON l.flavorgroup_id = fg.id, jsonb_array_elements(fg.flavor_type_match_policy) policies").
		Where("fg.id = ?", fgId).
		Where("fg.name != ?", models.FlavorGroupsHostUnique.String()).
		Where("policies ->> 'flavor_part' = ?", flavorPart).
		Where("flavor.content -> 'meta' -> 'description' ->> 'flavor_part' = ?", flavorPart)
	if err := tx.Count(&count).Error; err != nil {
		return false, errors.Wrap(err, "postgres/flavor_store:flavorgroupContainsFlavorType() failed to execute query")
	}

	if count > 0 {
		return true, nil
	}

	return false, nil
}
