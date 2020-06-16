/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package controllers

import (
	"encoding/json"
	"github.com/google/uuid"
	"github.com/gorilla/mux"
	"github.com/intel-secl/intel-secl/v3/pkg/hvs/domain/models"
	"github.com/intel-secl/intel-secl/v3/pkg/hvs/postgres"
	"github.com/intel-secl/intel-secl/v3/pkg/hvs/util"
	commErr "github.com/intel-secl/intel-secl/v3/pkg/lib/common/err"
	commLogMsg "github.com/intel-secl/intel-secl/v3/pkg/lib/common/log/message"
	"github.com/intel-secl/intel-secl/v3/pkg/lib/common/validation"
	"github.com/intel-secl/intel-secl/v3/pkg/model/hvs"
	"github.com/pkg/errors"
	"net/http"
	"strings"
)

type HostController struct {
	HStore  *postgres.HostStore
	FGStore *postgres.FlavorGroupStore
}

func NewHostController(hs *postgres.HostStore, fgs *postgres.FlavorGroupStore) *HostController {
	return &HostController{
		HStore:  hs,
		FGStore: fgs,
	}
}

func (hc *HostController) Create(w http.ResponseWriter, r *http.Request) (interface{}, int, error) {
	defaultLog.Trace("controllers/host_controller:Create() Entering")
	defer defaultLog.Trace("controllers/host_controller:Create() Leaving")

	if r.ContentLength == 0 {
		secLog.Error("controllers/host_controller:Create() The request body was not provided")
		return nil, http.StatusBadRequest, &commErr.ResourceError{Message:"The request body was not provided"}
	}

	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()

	var reqHost hvs.Host
	err := dec.Decode(&reqHost)
	if err != nil {
		secLog.WithError(err).Errorf("controllers/host_controller:Create() %s :  Failed to decode request body as Host", commLogMsg.AppRuntimeErr)
		return nil, http.StatusBadRequest, &commErr.ResourceError{Message:"Unable to decode JSON request body"}
	}

	if err := validateHostCreateCriteria(reqHost); err != nil {
		secLog.WithError(err).Error("controllers/host_controller:Create() Invalid create criteria")
		return nil, http.StatusBadRequest, &commErr.ResourceError{Message: err.Error()}
	}

	existingHosts, err := hc.HStore.Search(&models.HostFilterCriteria{
		NameEqualTo: reqHost.HostName,
	})
	if err != nil {
		secLog.WithError(err).Error("controllers/host_controller:Create() Host search failed")
		return nil, http.StatusInternalServerError, &commErr.ResourceError{Message: "Failed to create Host"}
	}

	if existingHosts != nil && len(existingHosts.Hosts) > 0 {
		secLog.WithField("Name", existingHosts.Hosts[0].HostName).Warningf("%s: Trying to create duplicate Host from addr: %s", commLogMsg.InvalidInputBadParam, r.RemoteAddr)
		return nil, http.StatusBadRequest, &commErr.ResourceError{Message: "Host with this name already exist"}
	}

	//TODO: connect to the host and retrieve the host manifest

	var flavorgroupNames []string
	if len(reqHost.FlavorgroupNames) != 0 {
		flavorgroupNames = reqHost.FlavorgroupNames
	} else {
		flavorgroupNames = append(flavorgroupNames, models.FlavorGroupsAutomatic.String())
	}

	//TODO: Link to default software and workload groups if host is linux

	//TODO: remove credentials from connection string for host table storage

	createdHost, err := hc.HStore.Create(&reqHost)
	if err != nil {
		secLog.WithError(err).Error("controllers/host_controller:Create() Host create failed")
		return nil, http.StatusInternalServerError, &commErr.ResourceError{Message: "Failed to create Host"}
	}

	//TODO: create credential

	if err := hc.linkFlavorgroupsToHost(flavorgroupNames, createdHost.Id); err != nil {
		return nil, http.StatusInternalServerError, &commErr.ResourceError{Message: "Failed to associate Host with flavorgroups"}
	}

	//TODO: Add host to flavor-verify queue

	secLog.WithField("host", createdHost).Infof("%s: Host created by: %s", commLogMsg.PrivilegeModified, r.RemoteAddr)
	return createdHost, http.StatusCreated, nil
}

func (hc *HostController) Retrieve(w http.ResponseWriter, r *http.Request) (interface{}, int, error) {
	defaultLog.Trace("controllers/host_controller:Retrieve() Entering")
	defer defaultLog.Trace("controllers/host_controller:Retrieve() Leaving")

	id := uuid.MustParse(mux.Vars(r)["id"])
	host, err := hc.HStore.Retrieve(id)
	if err != nil {
		if strings.Contains(err.Error(), commErr.RowsNotFound) {
			secLog.WithError(err).WithField("id", id).Error("controllers/host_controller:Retrieve() Host with specified ID could not be located")
			return nil, http.StatusNotFound, &commErr.ResourceError{Message:"Host with specified id does not exist"}
		} else {
			secLog.WithError(err).WithField("id", id).Error("controllers/host_controller:Retrieve() Host retrieve failed")
			return nil, http.StatusInternalServerError, &commErr.ResourceError{Message: "Failed to retrieve Host"}
		}
	}

	secLog.WithField("host", host).Infof("%s: Host retrieved by: %s", commLogMsg.AuthorizedAccess, r.RemoteAddr)
	return host, http.StatusOK, nil
}

func (hc *HostController) Update(w http.ResponseWriter, r *http.Request) (interface{}, int, error) {
	defaultLog.Trace("controllers/host_controller:Update() Entering")
	defer defaultLog.Trace("controllers/host_controller:Update() Leaving")

	id := uuid.MustParse(mux.Vars(r)["id"])
	host, err := hc.HStore.Retrieve(id)
	if err != nil {
		if strings.Contains(err.Error(), commErr.RowsNotFound) {
			secLog.WithError(err).WithField("id", id).Error("controllers/host_controller:Update() Host with specified id could not be located")
			return nil, http.StatusNotFound, &commErr.ResourceError{Message:"Host with specified id does not exist"}
		} else {
			secLog.WithError(err).WithField("id", id).Error("controllers/host_controller:Update() Host retrieve failed")
			return nil, http.StatusInternalServerError, &commErr.ResourceError{Message: "Failed to update Host"}
		}
	}

	if r.ContentLength == 0 {
		secLog.Error("controllers/host_controller:Update() The request body was not provided")
		return nil, http.StatusBadRequest, &commErr.ResourceError{Message:"The request body was not provided"}
	}

	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()

	var reqHost hvs.Host
	err = dec.Decode(&reqHost)
	if err != nil {
		secLog.WithError(err).Errorf("controllers/host_controller:Update() %s :  Failed to decode request body as Host", commLogMsg.AppRuntimeErr)
		return nil, http.StatusBadRequest, &commErr.ResourceError{Message:"Unable to decode JSON request body"}
	}

	if reqHost.HostName != "" {
		host.HostName = reqHost.HostName
	}

	if reqHost.HardwareUuid != uuid.Nil {
		host.HardwareUuid = reqHost.HardwareUuid
	}

	if reqHost.Description != "" {
		host.Description = reqHost.Description
	}

	if reqHost.ConnectionString != "" {
		//TODO: remove credentials from connection string for host table storage
	}

	updatedHost, err := hc.HStore.Update(host)
	if err != nil {
		secLog.WithError(err).Error("controllers/host_controller:Update() Host update failed")
		return nil, http.StatusInternalServerError, &commErr.ResourceError{Message: "Failed to update Host"}
	}

	//TODO: update credential

	if len(reqHost.FlavorgroupNames) != 0 {
		if err := hc.linkFlavorgroupsToHost(reqHost.FlavorgroupNames, updatedHost.Id); err != nil {
			return nil, http.StatusInternalServerError, &commErr.ResourceError{Message: "Failed to associate Host with flavorgroups"}
		}

		updatedHost.FlavorgroupNames = reqHost.FlavorgroupNames
	}

	//TODO: Since the host has been updated, add it to the verify queue

	secLog.WithField("host", updatedHost).Infof("%s: Host updated by: %s", commLogMsg.PrivilegeModified, r.RemoteAddr)
	return updatedHost, http.StatusCreated, nil
}

func (hc *HostController) Delete(w http.ResponseWriter, r *http.Request) (interface{}, int, error) {
	defaultLog.Trace("controllers/host_controller:Delete() Entering")
	defer defaultLog.Trace("controllers/host_controller:Delete() Leaving")

	id := uuid.MustParse(mux.Vars(r)["id"])
	host, err := hc.HStore.Retrieve(id)
	if err != nil {
		if strings.Contains(err.Error(), commErr.RowsNotFound) {
			secLog.WithError(err).WithField("id", id).Error("controllers/host_controller:Delete()  Host with specified id could not be located")
			return nil, http.StatusNotFound, &commErr.ResourceError{Message:"Host with specified id does not exist"}
		} else {
			secLog.WithError(err).WithField("id", id).Error("controllers/host_controller:Delete() Host retrieve failed")
			return nil, http.StatusInternalServerError, &commErr.ResourceError{Message: "Failed to delete Host"}
		}
	}

	//TODO: delete host reports for the host

	//TODO: delete host status for the host

	//TODO: Delete all the links between the flavors and the host

	//TODO: Delete all the links between the flavorgroups and the host

	if err := hc.HStore.Delete(id); err != nil {
		defaultLog.WithError(err).WithField("id", id).Error("controllers/host_controller:Delete() Host delete failed")
		return nil, http.StatusInternalServerError, &commErr.ResourceError{Message:"Failed to delete Host"}
	}

	secLog.WithField("host", host).Infof("Host deleted by: %s", r.RemoteAddr)
	return nil, http.StatusNoContent, nil
}

func (hc *HostController) Search(w http.ResponseWriter, r *http.Request) (interface{}, int, error) {
	defaultLog.Trace("controllers/host_controller:Search() Entering")
	defer defaultLog.Trace("controllers/host_controller:Search() Leaving")

	// check for query parameters
	defaultLog.WithField("query", r.URL.Query()).Trace("query hosts")
	id := r.URL.Query().Get("id")
	key := r.URL.Query().Get("key")
	value := r.URL.Query().Get("value")
	nameEqualTo := r.URL.Query().Get("nameEqualTo")
	nameContains := r.URL.Query().Get("nameContains")
	hostHardwareId := r.URL.Query().Get("hostHardwareId")

	var filter *models.HostFilterCriteria = nil
	if id != "" || key != "" || value != "" || nameEqualTo != "" || nameContains != "" || hostHardwareId != "" {
		filter = &models.HostFilterCriteria{
			Id:             id,
			Key:            key,
			Value:          value,
			NameEqualTo:    nameEqualTo,
			NameContains:   nameContains,
			HostHardwareId: hostHardwareId,
		}

		if err := validateHostFilterCriteria(filter); err != nil {
			secLog.WithError(err).Error("controllers/host_controller:Search() Invalid filter criteria")
			return nil, http.StatusBadRequest, &commErr.ResourceError{Message: err.Error()}
		}
	}

	hosts, err := hc.HStore.Search(filter)
	if err != nil {
		secLog.WithError(err).Error("controllers/host_controller:Search() Host search failed")
		return nil, http.StatusInternalServerError, errors.Errorf("Failed to search Hosts")
	}

	secLog.Infof("%s: Hosts searched by: %s", commLogMsg.AuthorizedAccess, r.RemoteAddr)
	return hosts, http.StatusOK, nil
}

func validateHostCreateCriteria(host hvs.Host) error {
	defaultLog.Trace("controllers/host_controller:validateHostCreateCriteria() Entering")
	defer defaultLog.Trace("controllers/host_controller:validateHostCreateCriteria() Leaving")

	if host.HostName == "" || host.ConnectionString == "" {
		return errors.New("Host connection string and host name must be specified")
	}

	if err := validation.ValidateHostname(host.HostName); err != nil {
		return errors.Wrap(err, "Valid Host Name must be specified")
	}

	//TODO: Add validation for Connection String

	return nil
}

func validateHostFilterCriteria(criteria *models.HostFilterCriteria) error {
	defaultLog.Trace("controllers/host_controller:validateHostFilterCriteria() Entering")
	defer defaultLog.Trace("controllers/host_controller:validateHostFilterCriteria() Leaving")

	if criteria.Id != "" {
		if _, err := uuid.Parse(criteria.Id); err != nil {
			return errors.New("Invalid id query param value, must be UUIDv4")
		}
	}
	if criteria.Key != "" {
		if err := validation.ValidateNameString(criteria.Key); err != nil {
			return errors.Wrap(err, "Valid contents for key must be specified")
		}
	}
	if criteria.Value != "" {
		if err := validation.ValidateNameString(criteria.Value); err != nil {
			return errors.Wrap(err, "Valid contents for value must be specified")
		}
	}
	if criteria.NameEqualTo != "" {
		if err := validation.ValidateNameString(criteria.NameEqualTo); err != nil {
			return errors.Wrap(err, "Valid contents for nameEqualTo must be specified")
		}
	}
	if criteria.NameContains != "" {
		if err := validation.ValidateNameString(criteria.NameContains); err != nil {
			return errors.Wrap(err, "Valid contents for nameContains must be specified")
		}
	}
	if criteria.HostHardwareId != "" {
		if err := validation.ValidateHardwareUUID(criteria.HostHardwareId); err != nil {
			return errors.New("Invalid hostHardwareId query param value, must be UUID")
		}
	}
	return nil
}

func (hc *HostController) linkFlavorgroupsToHost(flavorgroupNames []string, hostId uuid.UUID) error {
	defaultLog.Trace("controllers/host_controller:linkFlavorgroupsToHost() Entering")
	defer defaultLog.Trace("controllers/host_controller:linkFlavorgroupsToHost() Leaving")

	var flavorgroupIds []uuid.UUID
	for _, flavorgroupName := range flavorgroupNames {
		existingFlavorGroups, _ := hc.FGStore.Search(&models.FlavorGroupFilterCriteria{
			NameEqualTo: flavorgroupName,
		})
		if existingFlavorGroups != nil && len(existingFlavorGroups.Flavorgroups) > 0 {
			flavorgroupIds = append(flavorgroupIds, existingFlavorGroups.Flavorgroups[0].ID)
		} else {
			flavorgroup, err := hc.createNewFlavorGroup(flavorgroupName)
			if err != nil {
				return errors.Wrapf(err, "Could not create flavorgroup with name : %s", flavorgroupName)
			}
			flavorgroupIds = append(flavorgroupIds, flavorgroup.ID)
		}
	}

	for _, flavorgroupId := range flavorgroupIds {
		linkExists, err := hc.flavorGroupHostLinkExists(flavorgroupId, hostId)
		if err != nil {
			return errors.Wrap(err, "Could not check flavorgroup-host link existence")
		}
		if !linkExists {
			//TODO: Link host with flavorgroup
		}
	}

	return nil
}

func (hc *HostController) createNewFlavorGroup(flavorgroupName string) (*hvs.FlavorGroup, error) {
	defaultLog.Trace("controllers/host_controller:createNewFlavorGroup() Entering")
	defer defaultLog.Trace("controllers/host_controller:createNewFlavorGroup() Leaving")

	fg := util.CreateFlavorGroupByName(flavorgroupName)
	flavorgroup, err := hc.FGStore.Create(&fg)
	if err != nil {
		return nil, err
	}

	return flavorgroup, nil
}

func (hc *HostController) flavorGroupHostLinkExists(flavorgroupId, hostId uuid.UUID) (bool, error) {
	defaultLog.Trace("controllers/host_controller:flavorGroupHostLinkExists() Entering")
	defer defaultLog.Trace("controllers/host_controller:flavorGroupHostLinkExists() Leaving")

	//TODO: retrieve the flavorgroup-host link using flavorgroup id and host id
	return true, nil
}
