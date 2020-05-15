/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package resource

import (
	"encoding/json"
	"github.com/gorilla/mux"
	"github.com/intel-secl/intel-secl/v3/pkg/hvs/constants"
	"github.com/intel-secl/intel-secl/v3/pkg/hvs/repository"
	"github.com/intel-secl/intel-secl/v3/pkg/hvs/types"
	commLogMsg "github.com/intel-secl/intel-secl/v3/pkg/lib/common/log/message"
	"github.com/intel-secl/intel-secl/v3/pkg/lib/common/validation"
	"github.com/intel-secl/intel-secl/v3/pkg/model/hvs"
	"net/http"
	"strconv"
)

func SetFlavorGroups(r *mux.Router, db repository.HVSDatabase) {
	r.Handle("/flavorgroups", errorHandler(requiresPermission(createFlavorGroup(db),
		[]string{constants.FlavorGroupCreate}))).Methods("POST")
	r.Handle("/flavorgroups", errorHandler(requiresPermission(queryFlavorGroups(db),
		[]string{constants.FlavorGroupSearch}))).Methods("GET")
	r.Handle("/flavorgroups/{id:(?i:[a-fA-F0-9]{8}-[a-fA-F0-9]{4}-4[a-fA-F0-9]{3}-[8|9|aA|bB][a-fA-F0-9]{3}-[a-fA-F0-9]{12}$)}",
		errorHandler(requiresPermission(deleteFlavorGroup(db), []string{constants.FlavorGroupDelete}))).Methods("DELETE")
	r.Handle("/flavorgroups/{id:(?i:[a-fA-F0-9]{8}-[a-fA-F0-9]{4}-4[a-fA-F0-9]{3}-[8|9|aA|bB][a-fA-F0-9]{3}-[a-fA-F0-9]{12}$)}",
		errorHandler(requiresPermission(getFlavorGroup(db),[]string{constants.FlavorGroupRetrieve}))).Methods("GET")
}

func createFlavorGroup(db repository.HVSDatabase) endpointHandler {
	defaultLog.Trace("flavorgroups:createFlavorGroup() Entering")
	defer defaultLog.Trace("flavorgroups:createFlavorGroup() Leaving")

	return func(w http.ResponseWriter, r *http.Request) error {
		dec := json.NewDecoder(r.Body)
		dec.DisallowUnknownFields()

		var reqFlavorGroup hvs.FlavorGroup
		err := dec.Decode(&reqFlavorGroup)
		if err != nil {
			defaultLog.WithError(err).Errorf("flavorgroups:createFlavorGroup() %s :  Failed to encode request body as FlavorGroup", commLogMsg.AppRuntimeErr)
			return &resourceError{Message: err.Error(), StatusCode: http.StatusBadRequest}
		}

		if r.ContentLength == 0 {
			secLog.Error("flavorgroups:createFlavorGroup() The request body was not provided")
			return &resourceError{Message: "The request body was not provided", StatusCode: http.StatusBadRequest}
		}

		if reqFlavorGroup.Name == "" || (&reqFlavorGroup.FlavorMatchPolicyCollection == nil && reqFlavorGroup.Name != types.HOST_UNIQUE) {
			secLog.Error("flavorgroups:createFlavorGroup()  flavorgroup name and flavor match policy must be specified")
			return &resourceError{Message: "flavorgroup name and flavor match policy must be specified", StatusCode: http.StatusBadRequest}
		}

		existingFlavorGroups, err := db.FlavorGroupRepository().RetrieveAll(&hvs.FlavorGroupFilterCriteria{
			NameEqualTo: reqFlavorGroup.Name,
		})
		if existingFlavorGroups != nil && len(existingFlavorGroups.Flavorgroups) > 0 {
			secLog.WithField("Name", existingFlavorGroups.Flavorgroups[0].Name).Warningf("%s: Trying to create duplicated FlavorGroup from addr: %s", commLogMsg.InvalidInputBadParam, r.RemoteAddr)
			return &resourceError{Message: "FlavorGroup with same name already exists.", StatusCode: http.StatusBadRequest}
		}

		newFlavorGroup, err := db.FlavorGroupRepository().Create(&reqFlavorGroup)
		if err != nil {
			secLog.WithError(err).Error("flavorgroups:createFlavorGroup() Flavorgroup save failed")
			return &resourceError{Message: "Flavorgroup save failed", StatusCode: http.StatusInternalServerError}
		}
		secLog.WithField("Name", reqFlavorGroup.Name).Infof("%s: FlavorGroup created by: %s", commLogMsg.PrivilegeModified, r.RemoteAddr)

		w.WriteHeader(http.StatusCreated) // HTTP 201
		w.Header().Set("Content-Type", "application/json")
		err = json.NewEncoder(w).Encode(newFlavorGroup)
		if err != nil {
			return &resourceError{Message: "Unable to encode Flavorgroup", StatusCode: http.StatusInternalServerError}
		}
		return nil
	}
}

func queryFlavorGroups(db repository.HVSDatabase) endpointHandler {
	defaultLog.Trace("flavorgroups:queryFlavorGroups() Entering")
	defer defaultLog.Trace("flavorgroups:queryFlavorGroups() Leaving")

	return func(w http.ResponseWriter, r *http.Request) error {
		// check for query parameters
		defaultLog.WithField("query", r.URL.Query()).Trace("query flavorgroups")
		id := r.URL.Query().Get("id")
		nameEqualTo := r.URL.Query().Get("nameEqualTo")
		nameContains := r.URL.Query().Get("nameContains")
		hostId := r.URL.Query().Get("hostId")
		includeFlavorContent := r.URL.Query().Get("includeFlavorContent")

		var filter *hvs.FlavorGroupFilterCriteria = nil

		if id != "" || nameEqualTo != "" || nameContains != "" || hostId != "" {
			filter = &hvs.FlavorGroupFilterCriteria{
				Id:           id,
				NameEqualTo:  nameEqualTo,
				NameContains: nameContains,
				HostId:       hostId,
			}
		}

		flavorgroups, err := db.FlavorGroupRepository().RetrieveAll(filter)
		if err != nil {
			secLog.WithError(err).Error("flavorgroups:queryFlavorGroups() Flavorgroup get all failed")
			return &resourceError{Message: "Unable to search Flavorgroups", StatusCode: http.StatusInternalServerError}
		}

		//TODO: get the collection of flavorId's from mw_link_flavor_flavorgroup
		if flavorContent, err := strconv.ParseBool(includeFlavorContent); err == nil && flavorContent {
			defaultLog.Info("TODO: Populate flavors data")
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(flavorgroups)
		secLog.Infof("%s: Return flavorgroup query to: %s", commLogMsg.AuthorizedAccess, r.RemoteAddr)
		return nil
	}
}

func deleteFlavorGroup(db repository.HVSDatabase) endpointHandler {
	defaultLog.Trace("flavorgroups:deleteFlavorGroup() Entering")
	defer defaultLog.Trace("flavorgroups:deleteFlavorGroup() Leaving")

	return func(w http.ResponseWriter, r *http.Request) error {
		id := mux.Vars(r)["id"]
		validation_err := validation.ValidateUUIDv4(id)
		if validation_err != nil {
			return &resourceError{Message: validation_err.Error(), StatusCode: http.StatusBadRequest}
		}

		delFlavorGroup, err := db.FlavorGroupRepository().Retrieve(id)
		if delFlavorGroup == nil || err != nil {
			defaultLog.WithError(err).WithField("id", id).Info("attempt to delete invalid FlavorGroup")
			return &resourceError{Message: "Flavorgroup doesn't exists", StatusCode: http.StatusNotFound}
		}
		//TODO: Check if the flavor group is linked to any host

		if err := db.FlavorGroupRepository().Delete(id); err != nil {
			return &resourceError{Message: "failed to delete FlavorGroup", StatusCode: http.StatusInternalServerError}
		}
		secLog.WithField("user", delFlavorGroup.Name).Infof("FlavorGroup deleted by: %s", r.RemoteAddr)
		w.WriteHeader(http.StatusNoContent)
		return nil
	}
}

func getFlavorGroup(db repository.HVSDatabase) endpointHandler {
	defaultLog.Trace("flavorgroups:getFlavorGroup() Entering")
	defer defaultLog.Trace("flavorgroups:getFlavorGroup() Leaving")

	return func(w http.ResponseWriter, r *http.Request) error {
		id := mux.Vars(r)["id"]
		validation_err := validation.ValidateUUIDv4(id)
		if validation_err != nil {
			return &resourceError{Message: validation_err.Error(), StatusCode: http.StatusBadRequest}
		}

		flavorGroup, err := db.FlavorGroupRepository().Retrieve(id)
		if err != nil {
			defaultLog.WithError(err).WithField("id", id).Info("failed to retrieve FlavorGroup")
			return &resourceError{Message: "failed to retrieve FlavorGroup", StatusCode: http.StatusInternalServerError}
		}
		if flavorGroup == nil {
			secLog.Error("flavorgroups:getFlavorGroup()  flavorgroup with specified Id could not be located")
			return &resourceError{Message: "Flavorgroup doesn't exists", StatusCode: http.StatusNotFound}
		}

		//TODO: get the collection of flavorId's from mw_link_flavor_flavorgroup
		w.Header().Set("Content-Type", "application/json")
		err = json.NewEncoder(w).Encode(flavorGroup)
		if err != nil {
			return &resourceError{Message: "Unable to encode Flavorgroup", StatusCode: http.StatusInternalServerError}
		}
		secLog.WithField("Name", flavorGroup.Name).Infof("%s: Return get FlavorGroup request to: %s", commLogMsg.AuthorizedAccess, r.RemoteAddr)
		return nil
	}
}
