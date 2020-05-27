/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package controllers

import (
	"encoding/json"
	"github.com/gorilla/mux"
	"github.com/intel-secl/intel-secl/v3/pkg/hvs/domain"
	"github.com/intel-secl/intel-secl/v3/pkg/hvs/types"
	commLogMsg "github.com/intel-secl/intel-secl/v3/pkg/lib/common/log/message"
	"github.com/intel-secl/intel-secl/v3/pkg/lib/common/validation"
	"github.com/intel-secl/intel-secl/v3/pkg/model/hvs"
	"github.com/pkg/errors"
	"net/http"
	"strconv"
)

type FlavorgroupController struct {
	Store domain.FlavorGroupStore
}

func (controller FlavorgroupController) Create(w http.ResponseWriter, r *http.Request) (interface{}, int, error) {
	defaultLog.Trace("controllers/flavorgroup_controller:Create() Entering")
	defer defaultLog.Trace("controllers/flavorgroup_controller:Create() Leaving")

	if r.ContentLength == 0 {
		secLog.Error("controllers/flavorgroup_controller:Create() The request body is not provided")
		return nil, http.StatusBadRequest, errors.Errorf("The request body is not provided")
	}

	var reqFlavorGroup hvs.FlavorGroup
	// Decode the incoming json data to note struct
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()

	err := dec.Decode(&reqFlavorGroup)
	if err != nil {
		defaultLog.WithError(err).Errorf("controllers/flavorgroup_controller:Create() %s :  Failed to decode request body as FlavorGroup", commLogMsg.AppRuntimeErr)
		return nil, http.StatusBadRequest, errors.Wrap(err, "Unable to decode JSON request body")
	}

	if reqFlavorGroup.Name == "" || (&reqFlavorGroup.FlavorMatchPolicyCollection == nil && reqFlavorGroup.Name != types.HostUnique.String()) {
		secLog.Error("controllers/flavorgroup_controller:Create()  flavorgroup name and flavor match policy must be specified")
		return nil, http.StatusBadRequest, errors.Errorf("flavorgroup name and flavor match policy must be specified")
	}

	existingFlavorGroups, err := controller.Store.Search(&hvs.FlavorGroupFilterCriteria{
		NameEqualTo: reqFlavorGroup.Name,
	})
	if existingFlavorGroups != nil && len(existingFlavorGroups.Flavorgroups) > 0 {
		secLog.WithField("Name", existingFlavorGroups.Flavorgroups[0].Name).Warningf("%s: Trying to create duplicated FlavorGroup from addr: %s", commLogMsg.InvalidInputBadParam, r.RemoteAddr)
		return nil, http.StatusBadRequest, errors.Errorf("FlavorGroup with same name already exist.")
	}

	// Persistence
	newFlavorGroup, err := controller.Store.Create(&reqFlavorGroup)
	if err != nil {
		secLog.WithError(err).Error("controllers/flavorgroup_controller:Create() Flavorgroup save failed")
		return nil, http.StatusInternalServerError, errors.Wrap(err, "Error on inserting Flavorgroup")
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

	var filter *hvs.FlavorGroupFilterCriteria = nil

	//TODO: Add input validation
	if id != "" || nameEqualTo != "" || nameContains != "" || hostId != "" {
		filter = &hvs.FlavorGroupFilterCriteria{
			Id:           id,
			NameEqualTo:  nameEqualTo,
			NameContains: nameContains,
			HostId:       hostId,
		}
	}

	flavorgroupCollection, err := controller.Store.Search(filter)
	if err != nil {
		secLog.WithError(err).Error("controllers/flavorgroup_controller:Search() Flavorgroup get all failed")
		return nil, http.StatusInternalServerError, errors.Wrap(err, "Unable to search Flavorgroups")
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

	id := mux.Vars(r)["id"]
	validationErr := validation.ValidateUUIDv4(id)
	if validationErr != nil {
		secLog.WithError(validationErr).WithField("id", id).Info(
			"controllers/flavorgroup_controller:Delete() attempt to delete invalid FlavorGroup")
		return nil, http.StatusBadRequest, errors.Errorf("Invalid UUID format of the identifier provided")
	}

	delFlavorGroup, err := controller.Store.Retrieve(id)
	if err != nil {
		secLog.WithError(err).WithField("id", id).Info(
			"controllers/flavorgroup_controller:Delete() attempt to delete invalid FlavorGroup")
		return nil, http.StatusInternalServerError, errors.Errorf("Failed to delete FlavorGroup")
	}
	if delFlavorGroup == nil {
		secLog.WithError(err).WithField("id", id).Info(
			"controllers/flavorgroup_controller:Delete() attempt to delete invalid FlavorGroup")
		return nil, http.StatusNotFound, errors.Errorf("FlavorGroup with given ID does not exist")
	}
	//TODO: Check if the flavor group is linked to any host

	if err := controller.Store.Delete(id); err != nil {
		defaultLog.WithError(err).WithField("id", id).Info(
			"controllers/flavorgroup_controller:Delete() failed to delete FlavorGroup")
		return nil, http.StatusInternalServerError, errors.Errorf("Failed to delete FlavorGroup")
	}
	secLog.WithField("user", delFlavorGroup.Name).Infof("FlavorGroup deleted by: %s", r.RemoteAddr)
	return nil, http.StatusNoContent, nil
}

func (controller FlavorgroupController) Retrieve(w http.ResponseWriter, r *http.Request) (interface{}, int, error) {
	defaultLog.Trace("controllers/flavorgroup_controller:Retrieve() Entering")
	defer defaultLog.Trace("controllers/flavorgroup_controller:Retrieve() Leaving")

	id := mux.Vars(r)["id"]
	validationErr := validation.ValidateUUIDv4(id)
	if validationErr != nil {
		secLog.WithError(validationErr).WithField("id", id).Info(
			"controllers/flavorgroup_controller:Retrieve() attempt to retrieve invalid FlavorGroup")
		return nil, http.StatusBadRequest, errors.Errorf("Invalid UUID format of the identifier provided")
	}

	flavorGroup, err := controller.Store.Retrieve(id)
	if err != nil {
		secLog.WithError(err).WithField("id", id).Info(
			"controllers/flavorgroup_controller:Retrieve() failed to retrieve FlavorGroup")
		return nil, http.StatusInternalServerError, errors.Errorf("Failed to retrieve FlavorGroup")
	}
	if flavorGroup == nil {
		secLog.WithError(err).WithField("id", id).Info(
			"controllers/flavorgroup_controller:Retrieve() failed to retrieve FlavorGroup")
		return nil, http.StatusNotFound, errors.Errorf("FlavorGroup with given ID does not exist")
	}

	//TODO: get the collection of flavorId's from mw_link_flavor_flavorgroup
	return flavorGroup, http.StatusOK, nil
}
