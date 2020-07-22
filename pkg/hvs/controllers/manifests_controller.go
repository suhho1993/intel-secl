/*
 *  Copyright (C) 2020 Intel Corporation
 *  SPDX-License-Identifier: BSD-3-Clause
 */

package controllers

import (
	"github.com/google/uuid"
	"github.com/intel-secl/intel-secl/v3/pkg/hvs/domain"
	commErr "github.com/intel-secl/intel-secl/v3/pkg/lib/common/err"
	commLogMsg "github.com/intel-secl/intel-secl/v3/pkg/lib/common/log/message"
	"github.com/intel-secl/intel-secl/v3/pkg/lib/flavor/common"
	"github.com/intel-secl/intel-secl/v3/pkg/lib/flavor/util"
	"net/http"
	"strings"
)

type ManifestsController struct {
	FlavorStore domain.FlavorStore
}

func NewManifestsController(fs domain.FlavorStore) *ManifestsController {
	return &ManifestsController{
		FlavorStore: fs,
	}
}

func (controller ManifestsController) GetManifest(w http.ResponseWriter, r *http.Request) (interface{}, int, error) {
	defaultLog.Trace("controllers/manifests_controller:GetManifest() Entering")
	defer defaultLog.Trace("controllers/manifests_controller:GetManifest() Leaving")

	flavorId := r.URL.Query().Get("id")
	parsedFlavorId, err := uuid.Parse(flavorId)
	if err != nil {
		secLog.WithError(err).Errorf("controllers/manifests_controller:"+
			"GetManifest() %s : Invalid ID provided as query parameter", commLogMsg.InvalidInputBadParam)
		return nil, http.StatusBadRequest, &commErr.ResourceError{Message: "Invalid ID provided as query parameter"}
	}

	signedFlavor, err := controller.FlavorStore.Retrieve(parsedFlavorId)
	if err != nil {
		if strings.Contains(err.Error(), commErr.RowsNotFound) {
			secLog.WithError(err).Errorf("controllers/manifests_controller:"+
				"GetManifest() %s : Flavor with given ID does not exist", commLogMsg.InvalidInputBadParam)
			return "", http.StatusBadRequest, &commErr.ResourceError{"Flavor with given ID does not exist"}
		} else {
			defaultLog.WithError(err).Errorf("controllers/manifests_controller:"+
				"GetManifest() %s : Failed to search flavor from store", commLogMsg.AppRuntimeErr)
			return nil, http.StatusInternalServerError, &commErr.ResourceError{Message: "Failed to search flavor from store"}
		}
	}

	var fmc util.FlavorToManifestConverter
	if signedFlavor.Flavor.Meta.Description.FlavorPart == string(common.FlavorPartSoftware) {
		manifest := fmc.GetManifestFromFlavor(signedFlavor.Flavor)
		return manifest, http.StatusOK, nil
	} else {
		secLog.WithError(err).Errorf("controllers/manifests_controller:"+
			"GetManifest() %s : Flavor associated with the provided id is not a SOFTWARE flavor", commLogMsg.InvalidInputBadParam)
		return nil, http.StatusBadRequest, &commErr.ResourceError{Message: "Flavor associated with the provided id is not " +
			"a SOFTWARE flavor"}
	}
}
