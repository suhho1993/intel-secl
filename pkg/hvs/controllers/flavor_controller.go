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
	dm "github.com/intel-secl/intel-secl/v3/pkg/hvs/domain/models"
	"github.com/intel-secl/intel-secl/v3/pkg/hvs/utils"
	commErr "github.com/intel-secl/intel-secl/v3/pkg/lib/common/err"
	commLogMsg "github.com/intel-secl/intel-secl/v3/pkg/lib/common/log/message"
	"github.com/intel-secl/intel-secl/v3/pkg/lib/common/validation"
	fc "github.com/intel-secl/intel-secl/v3/pkg/lib/flavor/common"
	"github.com/pkg/errors"
	"net/http"
	"strings"
)

type FlavorController struct {
	Store domain.FlavorStore
}

func (controller FlavorController) Create(w http.ResponseWriter, r *http.Request) (interface{}, int, error) {
	defaultLog.Trace("controllers/flavor_controller:Create() Entering")
	defer defaultLog.Trace("controllers/flavor_controller:Create() Leaving")

	if r.ContentLength == 0 {
		secLog.Error("controllers/flavor_controller:Create() The request body is not provided")
		return nil, http.StatusBadRequest, &commErr.ResourceError{Message: "The request body is not provided"}
	}

	var flavorCreateCriteria dm.FlavorCreateCriteria
	// Decode the incoming json data to note struct
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()

	err := dec.Decode(&flavorCreateCriteria)
	if err != nil {
		defaultLog.WithError(err).Errorf("controllers/flavor_controller:Create() %s :  Failed to decode request body as Flavor", commLogMsg.AppRuntimeErr)
		return nil, http.StatusBadRequest, &commErr.ResourceError{Message: "Unable to decode JSON request body"}
	}

	err = validateFlavorCreateCriteria(flavorCreateCriteria)
	if err != nil {
		defaultLog.WithError(err).Error("controllers/flavor_controller:Create() Invalid flavor create criteria")
		return nil, http.StatusBadRequest, &commErr.ResourceError{Message: "Invalid flavor create criteria"}
	}

	return createFlavors(flavorCreateCriteria, controller)
}

func createFlavors(criteria dm.FlavorCreateCriteria, controller FlavorController) (interface{}, int, error) {
	return nil, http.StatusCreated, nil
}

func (controller FlavorController) Search(w http.ResponseWriter, r *http.Request) (interface{}, int, error) {
	defaultLog.Trace("controllers/flavor_controller:Search() Entering")
	defer defaultLog.Trace("controllers/flavor_controller:Search() Leaving")

	// check for query parameters
	defaultLog.WithField("query", r.URL.Query()).Trace("query flavors")
	id := r.URL.Query().Get("id")
	key := r.URL.Query().Get("key")
	value := r.URL.Query().Get("value")
	flavorgroupId := r.URL.Query().Get("flavorgroupId")
	flavorParts := r.URL.Query()["flavorParts"]

	var filterCriteria *dm.FlavorFilterCriteria = nil

	if id != "" || key != "" || value != "" || flavorgroupId != "" || len(flavorParts) > 0 {
		filterId, _ := uuid.Parse(id)
		filterFlavorgroupId, _ := uuid.Parse(flavorgroupId)
		filterCriteria = &dm.FlavorFilterCriteria{
			Id:            filterId,
			Key:           key,
			Value:         value,
			FlavorGroupID: filterFlavorgroupId,
			FlavorParts:   flavorParts,
		}
		if err := ValidateFlavorFilterCriteria(*filterCriteria); err != nil {
			secLog.Errorf("controllers/flavor_controller:Search()  %s", err.Error())
			return nil, http.StatusBadRequest, &commErr.ResourceError{Message: err.Error()}
		}
	}

	flavorCollection, err := controller.Store.Search(filterCriteria)
	if err != nil {
		secLog.WithError(err).Error("controllers/flavor_controller:Search() Flavor get all failed")
		return nil, http.StatusInternalServerError, errors.Errorf("Unable to search Flavors")
	}

	secLog.Infof("%s: Return flavor query to: %s", commLogMsg.AuthorizedAccess, r.RemoteAddr)
	return flavorCollection, http.StatusOK, nil
}

func (controller FlavorController) Delete(w http.ResponseWriter, r *http.Request) (interface{}, int, error) {
	defaultLog.Trace("controllers/flavor_controller:Delete() Entering")
	defer defaultLog.Trace("controllers/flavor_controller:Delete() Leaving")

	id, _ := uuid.Parse(mux.Vars(r)["id"])
	_, err := controller.Store.Retrieve(id)
	if err != nil {
		if strings.Contains(err.Error(), commErr.RowsNotFound) {
			secLog.WithError(err).WithField("id", id).Info(
				"controllers/flavor_controller:Delete()  Flavor with given ID does not exist")
			return nil, http.StatusNotFound, &commErr.ResourceError{Message: "Flavor with given ID does not exist"}
		} else {
			secLog.WithError(err).WithField("id", id).Info(
				"controllers/flavor_controller:Delete() attempt to delete invalid Flavor")
			return nil, http.StatusInternalServerError, &commErr.ResourceError{Message: "Failed to delete Flavor"}
		}
	}
	//TODO: Check if the flavor-flavorgroup is link exists
	//TODO: Check if the flavor-host link exists
	if err := controller.Store.Delete(id); err != nil {
		defaultLog.WithError(err).WithField("id", id).Info(
			"controllers/flavor_controller:Delete() failed to delete Flavor")
		return nil, http.StatusInternalServerError, &commErr.ResourceError{Message: "Failed to delete Flavor"}
	}
	return nil, http.StatusNoContent, nil
}

func (controller FlavorController) Retrieve(w http.ResponseWriter, r *http.Request) (interface{}, int, error) {
	defaultLog.Trace("controllers/flavor_controller:Retrieve() Entering")
	defer defaultLog.Trace("controllers/flavor_controller:Retrieve() Leaving")

	id, _ := uuid.Parse(mux.Vars(r)["id"])
	flavor, err := controller.Store.Retrieve(id)
	if err != nil {
		if strings.Contains(err.Error(), commErr.RowsNotFound) {
			secLog.WithError(err).WithField("id", id).Info(
				"controllers/flavor_controller:Retrieve() Flavor with given ID does not exist")
			return nil, http.StatusNotFound, &commErr.ResourceError{Message: "Flavor with given ID does not exist"}
		} else {
			secLog.WithError(err).WithField("id", id).Info(
				"controllers/flavor_controller:Retrieve() failed to retrieve Flavor")
			return nil, http.StatusInternalServerError, &commErr.ResourceError{Message: "Failed to retrieve Flavor with the given ID"}
		}
	}
	return flavor, http.StatusOK, nil
}

func ValidateFlavorFilterCriteria(filter dm.FlavorFilterCriteria) error {
	defaultLog.Trace("controllers/flavor_controller:ValidateFlavorFilterCriteria() Entering")
	defer defaultLog.Trace("controllers/flavor_controller:ValidateFlavorFilterCriteria() Leaving")

	if filter.Id.String() != "" {
		if _, errs := uuid.Parse(filter.Id.String()); errs != nil {
			return errors.New("Invalid UUID format of the Flavor Identifier")
		}
	}
	if filter.Key != "" {
		if errs := validation.ValidateNameString(filter.Key); errs != nil {
			return errors.Wrap(errs, "Valid contents for filter Key must be specified")
		}
	}
	if filter.Value != "" {
		if errs := validation.ValidateStrings([]string{filter.Value}); errs != nil {
			return errors.Wrap(errs, "Valid contents for filter Value must be specified")
		}
	}
	if filter.FlavorGroupID.String() != "" {
		if _, errs := uuid.Parse(filter.FlavorGroupID.String()); errs != nil {
			return errors.New("Invalid UUID format of the Flavorgroup identifier as a flavor filter")
		}
	}

	if len(filter.FlavorParts) > 0 {
		if err := validateFlavorParts(filter.FlavorParts); err != nil {
			return err
		}
	}
	return nil
}

func validateFlavorCreateCriteria(criteria dm.FlavorCreateCriteria) error {
	if criteria.ConnectionString == "" && len(criteria.FlavorCollection.Flavors) == 0 && len(criteria.SignedFlavorCollection.SignedFlavors) == 0 {
		secLog.Error("controllers/flavor_controller: validateFlavorCreateCriteria() Valid host connection string or flavor content must be given")
		return errors.New("Valid host connection string or flavor content must be given")
	}
	if criteria.ConnectionString != "" {
		err := utils.ValidateConnectionString(criteria.ConnectionString)
		if err != nil  {
			secLog.Error("controllers/flavor_controller: validateFlavorCreateCriteria() Invalid host connection string")
			return errors.New("Invalid host connection string")
		}
	}
	if len(criteria.FlavorParts) > 0 {
		if err := validateFlavorParts(criteria.FlavorParts); err != nil {
			return err
		}
	}
	if criteria.FlavorgroupName != "" {
		err := validation.ValidateStrings([]string{criteria.FlavorgroupName})
		if err != nil {
			return errors.New("Invalid flavorgroup name given as a flavor create criteria")
		}
	}
	return nil
}

func validateFlavorParts(flavorParts []string) error {
	// validate if the given flavor parts are valid
	for _, flavorPart := range flavorParts {
		var fp fc.FlavorPart
		if err := (&fp).Parse(flavorPart); err != nil {
			return errors.New("Valid FlavorPart as a filter must be specified")
		}
	}
	return nil
}
