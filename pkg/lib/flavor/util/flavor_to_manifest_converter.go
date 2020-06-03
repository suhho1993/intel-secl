/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package util

import (
	"encoding/json"
	"github.com/intel-secl/intel-secl/v3/pkg/model/hvs"
	taModel "github.com/intel-secl/intel-secl/v3/pkg/model/ta"
	"github.com/pkg/errors"
	"reflect"
)

/**
 *
 * @author mullas
 */

// FlavorToManifestConverter is a utility for extracting Manifest from a Flavor
type FlavorToManifestConverter struct {
}

// GetManifestXML extracts the Manifest from the Flavor
func (fmc FlavorToManifestConverter) GetManifestXML(flavor hvs.Flavor) (string, error) {
	log.Trace("flavor/util/flavor_to_manifest_converter:GetManifestXML() Entering")
	defer log.Trace("flavor/util/flavor_to_manifest_converter:GetManifestXML() Leaving")

	var manifest taModel.Manifest
	var err error

	manifest = fmc.getManifestFromFlavor(flavor)

	manifestXML, err := json.Marshal(manifest)
	if err != nil {
		return "", errors.Wrap(err, "FlavorToManifestConverter: failed to parse Manifest XML")
	}
	return string(manifestXML), nil
}

// getManifestFromFlavor constructs the Manifest from the Flavor
func (fmc FlavorToManifestConverter) getManifestFromFlavor(flavor hvs.Flavor) taModel.Manifest {
	log.Trace("flavor/util/flavor_to_manifest_converter:getManifestFromFlavor() Entering")
	defer log.Trace("flavor/util/flavor_to_manifest_converter:getManifestFromFlavor() Leaving")

	var manifest taModel.Manifest
	manifest.DigestAlg = flavor.Meta.Description.DigestAlgorithm
	manifest.Label = flavor.Meta.Description.Label
	manifest.Uuid = flavor.Meta.ID.String()
	// extract the manifest types from the flavor based on the measurement types
	var allMeasurements []taModel.MeasurementType
	for _, meT := range flavor.Software.Measurements {
		allMeasurements = append(allMeasurements, meT)
	}
	var allManifestTypes []interface{}
	for _, meT := range allMeasurements {
		allManifestTypes = append(allManifestTypes, fmc.getManifestType(meT))
	}
	for _, maT := range allManifestTypes {
		switch reflect.TypeOf(maT) {
		case reflect.TypeOf(taModel.FileManifestType{}):
			manifest.File = append(manifest.File, maT.(taModel.FileManifestType))
		case reflect.TypeOf(taModel.DirManifestType{}):
			manifest.Dir = append(manifest.Dir, maT.(taModel.DirManifestType))
		case reflect.TypeOf(taModel.SymlinkManifestType{}):
			manifest.Symlink = append(manifest.Symlink, maT.(taModel.SymlinkManifestType))
		}
	}
	return manifest
}

func (fmc FlavorToManifestConverter) getManifestType(measurement taModel.MeasurementType) taModel.ManifestType {
	log.Trace("flavor/util/flavor_to_manifest_converter:getManifestType() Entering")
	defer log.Trace("flavor/util/flavor_to_manifest_converter:getManifestType() Leaving")

	var manType taModel.ManifestType
	switch reflect.TypeOf(measurement) {
	case reflect.TypeOf(taModel.FileMeasurementType{}):
		manType = taModel.FileManifestType{
			Path:       measurement.(taModel.FileMeasurementType).Path,
			SearchType: measurement.(taModel.FileMeasurementType).SearchType,
		}
	case reflect.TypeOf(taModel.DirectoryMeasurementType{}):
		manType = taModel.DirManifestType{
			Path:       measurement.(taModel.DirectoryMeasurementType).Path,
			SearchType: measurement.(taModel.DirectoryMeasurementType).SearchType,
			Include:    measurement.(taModel.DirectoryMeasurementType).Include,
			Exclude:    measurement.(taModel.DirectoryMeasurementType).Exclude,
			FilterType: measurement.(taModel.DirectoryMeasurementType).FilterType,
		}
	case reflect.TypeOf(taModel.SymlinkMeasurementType{}):
		manType = taModel.SymlinkManifestType{
			Path:       measurement.(taModel.SymlinkMeasurementType).Path,
			SearchType: measurement.(taModel.SymlinkMeasurementType).SearchType,
		}
	}
	return manType
}
