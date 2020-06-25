/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package controllers

import (
	"encoding/json"
	"github.com/google/uuid"
	"github.com/gorilla/mux"
	"github.com/intel-secl/intel-secl/v3/pkg/hvs/domain"
	"github.com/intel-secl/intel-secl/v3/pkg/hvs/domain/models"
	commErr "github.com/intel-secl/intel-secl/v3/pkg/lib/common/err"
	commLogMsg "github.com/intel-secl/intel-secl/v3/pkg/lib/common/log/message"
	"github.com/intel-secl/intel-secl/v3/pkg/lib/common/validation"
	"github.com/intel-secl/intel-secl/v3/pkg/model/hvs"
	"github.com/pkg/errors"
	"net/http"
	"strconv"
	"strings"
)

type FlavorgroupController struct {
	FlavorGroupStore domain.FlavorGroupStore
}

func (controller FlavorgroupController) Create(w http.ResponseWriter, r *http.Request) (interface{}, int, error) {
	defaultLog.Trace("controllers/flavorgroup_controller:Create() Entering")
	defer defaultLog.Trace("controllers/flavorgroup_controller:Create() Leaving")

	if r.ContentLength == 0 {
		secLog.Error("controllers/flavorgroup_controller:Create() The request body is not provided")
		return nil, http.StatusBadRequest, &commErr.ResourceError{Message: "The request body is not provided"}
	}

	var reqFlavorGroup hvs.FlavorGroup
	// Decode the incoming json data to note struct
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()

	err := dec.Decode(&reqFlavorGroup)
	if err != nil {
		defaultLog.WithError(err).Errorf("controllers/flavorgroup_controller:Create() %s :  Failed to decode request body as FlavorGroup", commLogMsg.AppRuntimeErr)
		return nil, http.StatusBadRequest, &commErr.ResourceError{Message: "Unable to decode JSON request body"}
	}

	if err := ValidateFlavorGroup(reqFlavorGroup); err != nil {
		secLog.Errorf("controllers/flavorgroup_controller:Create()  %s", err.Error())
		return nil, http.StatusBadRequest, &commErr.ResourceError{Message: err.Error()}
	}

	existingFlavorGroups, err := controller.FlavorGroupStore.Search(&models.FlavorGroupFilterCriteria{
		NameEqualTo: reqFlavorGroup.Name,
	})
	if existingFlavorGroups != nil && len(existingFlavorGroups.Flavorgroups) > 0 {
		secLog.WithField("Name", existingFlavorGroups.Flavorgroups[0].Name).Warningf("%s: Trying to create duplicated FlavorGroup from addr: %s", commLogMsg.InvalidInputBadParam, r.RemoteAddr)
		return nil, http.StatusBadRequest, &commErr.ResourceError{Message: "FlavorGroup with same name already exist"}
	}

	// Persistence
	newFlavorGroup, err := controller.FlavorGroupStore.Create(&reqFlavorGroup)
	if err != nil {
		secLog.WithError(err).Error("controllers/flavorgroup_controller:Create() Flavorgroup save failed")
		return nil, http.StatusInternalServerError, errors.Errorf("Error while inserting a new Flavorgroup")
	}
	secLog.WithField("Name", reqFlavorGroup.Name).Infof("%s: FlavorGroup created by: %s", commLogMsg.PrivilegeModified, r.RemoteAddr)
	return newFlavorGroup, http.StatusCreated, nil
}

func (controller FlavorgroupController) Search(w http.ResponseWriter, r *http.Request) (interface{}, int, error) {
	defaultLog.Trace("controllers/flavorgroup_controller:Search() Entering")
	defer defaultLog.Trace("controllers/flavorgroup_controller:Search() Leaving")

	// check for query parameters
	defaultLog.WithField("query", r.URL.Query()).Trace("query flavorgroups")
	id := r.URL.Query().Get("id")
	nameEqualTo := r.URL.Query().Get("nameEqualTo")
	nameContains := r.URL.Query().Get("nameContains")
	hostId := r.URL.Query().Get("hostId")
	includeFlavorContent := r.URL.Query().Get("includeFlavorContent")

	var filter *models.FlavorGroupFilterCriteria = nil

	if id != "" || nameEqualTo != "" || nameContains != "" || hostId != "" {
		filter = &models.FlavorGroupFilterCriteria{
			Id:           id,
			NameEqualTo:  nameEqualTo,
			NameContains: nameContains,
			HostId:       hostId,
		}
		if err := ValidateFgCriteria(*filter); err != nil {
			secLog.Errorf("controllers/flavorgroup_controller:Search()  %s", err.Error())
			return nil, http.StatusBadRequest, &commErr.ResourceError{Message: err.Error()}
		}
	}

	flavorgroupCollection, err := controller.FlavorGroupStore.Search(filter)
	if err != nil {
		secLog.WithError(err).Error("controllers/flavorgroup_controller:Search() Flavorgroup get all failed")
		return nil, http.StatusInternalServerError, errors.Errorf("Unable to search Flavorgroups")
	}

	//TODO: get the collection of flavorId's from mw_link_flavor_flavorgroup
	if flavorContent, err := strconv.ParseBool(includeFlavorContent); err == nil && flavorContent {
		defaultLog.Info("TODO: Populate flavors data")
	}
	secLog.Infof("%s: Return flavorgroup query to: %s", commLogMsg.AuthorizedAccess, r.RemoteAddr)
	return flavorgroupCollection, http.StatusOK, nil
}

func (controller FlavorgroupController) Delete(w http.ResponseWriter, r *http.Request) (interface{}, int, error) {
	defaultLog.Trace("controllers/flavorgroup_controller:Delete() Entering")
	defer defaultLog.Trace("controllers/flavorgroup_controller:Delete() Leaving")

	id := uuid.MustParse(mux.Vars(r)["id"])

	delFlavorGroup, err := controller.FlavorGroupStore.Retrieve(id)
	if err != nil {
		if strings.Contains(err.Error(), commErr.RowsNotFound) {
			secLog.WithError(err).WithField("id", id).Error(
				"controllers/flavorgroup_controller:Delete()  FlavorGroup with given ID does not exist")
			return nil, http.StatusNotFound, &commErr.ResourceError{Message: "FlavorGroup with given ID does not exist"}
		} else {
			secLog.WithError(err).WithField("id", id).Error(
				"controllers/flavorgroup_controller:Delete() attempt to delete invalid FlavorGroup")
			return nil, http.StatusInternalServerError, &commErr.ResourceError{Message: "Failed to delete FlavorGroup"}
		}
	}
	//TODO: Check if the flavor group is linked to any host

	if err := controller.FlavorGroupStore.Delete(id); err != nil {
		defaultLog.WithError(err).WithField("id", id).Info(
			"controllers/flavorgroup_controller:Delete() failed to delete FlavorGroup")
		return nil, http.StatusInternalServerError, &commErr.ResourceError{Message: "Failed to delete FlavorGroup"}
	}
	secLog.WithField("user", delFlavorGroup.Name).Infof("FlavorGroup deleted by: %s", r.RemoteAddr)
	return nil, http.StatusNoContent, nil
}

func (controller FlavorgroupController) Retrieve(w http.ResponseWriter, r *http.Request) (interface{}, int, error) {
	defaultLog.Trace("controllers/flavorgroup_controller:Retrieve() Entering")
	defer defaultLog.Trace("controllers/flavorgroup_controller:Retrieve() Leaving")

	id := uuid.MustParse(mux.Vars(r)["id"])

	flavorGroup, err := controller.FlavorGroupStore.Retrieve(id)
	if err != nil {
		if strings.Contains(err.Error(), commErr.RowsNotFound) {
			secLog.WithError(err).WithField("id", id).Error(
				"controllers/flavorgroup_controller:Retrieve() FlavorGroup with given ID does not exist")
			return nil, http.StatusNotFound, &commErr.ResourceError{Message: "FlavorGroup with given ID does not exist"}
		} else {
			secLog.WithError(err).WithField("id", id).Error(
				"controllers/flavorgroup_controller:Retrieve() failed to retrieve FlavorGroup")
			return nil, http.StatusInternalServerError, &commErr.ResourceError{Message: "Failed to retrieve FlavorGroup"}
		}
	}

	//TODO: get the collection of flavorId's from mw_link_flavor_flavorgroup
	return flavorGroup, http.StatusOK, nil
}

func ValidateFlavorGroup(flavorGroup hvs.FlavorGroup) error {
	defaultLog.Trace("controllers/flavorgroup_controller:ValidateFlavorGroup() Entering")
	defer defaultLog.Trace("controllers/flavorgroup_controller:ValidateFlavorGroup() Leaving")

	if flavorGroup.Name == "" {
		return errors.New("FlavorGroup Name must be specified")
	}
	if flavorGroup.Name != "" {
		if errs := validation.ValidateNameString(flavorGroup.Name); errs != nil {
			return errors.Wrap(errs, "Valid FlavorGroup Name must be specified")
		}
	}
	if len(flavorGroup.MatchPolicies) == 0 {
		return errors.New("Flavor Type Match Policy Collection must be specified")
	}
	return nil
}

func ValidateFgCriteria(filterCriteria models.FlavorGroupFilterCriteria) error {
	defaultLog.Trace("controllers/flavorgroup_controller:ValidateFgCriteria() Entering")
	defer defaultLog.Trace("controllers/flavorgroup_controller:ValidateFgCriteria() Leaving")

	if filterCriteria.Id != "" {
		if _, errs := uuid.Parse(filterCriteria.Id); errs != nil {
			return errors.New("Invalid UUID format of the Flavorgroup Identifier")
		}
	}
	if filterCriteria.NameEqualTo != "" {
		if errs := validation.ValidateNameString(filterCriteria.NameEqualTo); errs != nil {
			return errors.Wrap(errs, "Valid contents for NameEqualTo must be specified")
		}
	}
	if filterCriteria.NameContains != "" {
		if errs := validation.ValidateNameString(filterCriteria.NameContains); errs != nil {
			return errors.Wrap(errs, "Valid contents for NameContains must be specified")
		}
	}
	if filterCriteria.HostId != "" {
		if _, errs := uuid.Parse(filterCriteria.HostId); errs != nil {
			return errors.New("Invalid UUID format of the Host Identifier")
		}
	}
	return nil
}
