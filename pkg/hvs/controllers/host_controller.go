/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package controllers

import (
	"encoding/json"
	"github.com/google/uuid"
	"github.com/gorilla/mux"
	"github.com/intel-secl/intel-secl/v3/pkg/hvs/config"
	"github.com/intel-secl/intel-secl/v3/pkg/hvs/constants"
	"github.com/intel-secl/intel-secl/v3/pkg/hvs/domain"
	"github.com/intel-secl/intel-secl/v3/pkg/hvs/domain/models"
	"github.com/intel-secl/intel-secl/v3/pkg/hvs/utils"
	commErr "github.com/intel-secl/intel-secl/v3/pkg/lib/common/err"
	commLogMsg "github.com/intel-secl/intel-secl/v3/pkg/lib/common/log/message"
	"github.com/intel-secl/intel-secl/v3/pkg/lib/common/validation"
	hostconnector "github.com/intel-secl/intel-secl/v3/pkg/lib/host-connector"
	"github.com/intel-secl/intel-secl/v3/pkg/lib/host-connector/types"
	"github.com/intel-secl/intel-secl/v3/pkg/model/hvs"
	model "github.com/intel-secl/intel-secl/v3/pkg/model/ta"
	"github.com/pkg/errors"
	"net/http"
	"strings"
)

type HostController struct {
	HStore  domain.HostStore
	FGStore domain.FlavorGroupStore
}

func NewHostController(hs domain.HostStore, fgs domain.FlavorGroupStore) *HostController {
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

	if reqHost.HostName == "" || reqHost.ConnectionString == "" {
		secLog.Error("controllers/host_controller:Create() Host connection string and host name must be specified")
		return nil, http.StatusBadRequest, &commErr.ResourceError{Message: "Host connection string and host name must be specified"}
	}

	if err := validateHostCreateCriteria(reqHost); err != nil {
		secLog.WithError(err).Error("controllers/host_controller:Create() Invalid host data")
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

	connectionString, err := utils.GenerateConnectionString(reqHost.ConnectionString)
	if err != nil {
		defaultLog.WithError(err).Error("controllers/host_controller:Create() Could not generate formatted connection string")
		return nil, http.StatusBadRequest, &commErr.ResourceError{Message: err.Error()}
	}

	defaultLog.Debugf("Connecting to host to get the host manifest and the hardware UUID of the host : %s", reqHost.HostName)
	// connect to the host and retrieve the host manifest
	hostInfo, err := getHostInfo(connectionString)
	if err != nil {
		var hostState string
		//TODO: Determine host-state
		defaultLog.Warnf("Could not connect to host, hardware UUID and host manifest will not be set: %s", hostState)
	}

	var hwUuid uuid.UUID
	if hostInfo != nil && hostInfo.HardwareUUID != "" {
		hwid, err := uuid.Parse(hostInfo.HardwareUUID)
		if err == nil {
			hwUuid = hwid
		}
	}

	var fgNames []string
	if len(reqHost.FlavorgroupNames) != 0 {
		fgNames = reqHost.FlavorgroupNames
	} else {
		defaultLog.Debug("Flavorgroup names not present in request, associating with default ones")
		fgNames = append(fgNames, models.FlavorGroupsAutomatic.String())
	}

	// Link to default software and workload groups if host is linux
	if hostInfo != nil && isLinuxHost(hostInfo) {
		defaultLog.Debug("Host is linux, associating with default software flavorgroups")
		for _, component := range hostInfo.InstalledComponents {
			if component == types.HostComponentTagent.String() {
				fgNames = append(fgNames, models.FlavorGroupsPlatformSoftware.String())
			} else if component == types.HostComponentWlagent.String() {
				fgNames = append(fgNames, models.FlavorGroupsWorkloadSoftware.String())
			}
		}
	}

	// remove credentials from connection string for host table storage
	csWithoutCredentials := utils.GetConnectionStringWithoutCredentials(connectionString)
	defaultLog.Debugf("connection string without credentials : %s", csWithoutCredentials)

	reqHost.HardwareUuid = hwUuid
	reqHost.FlavorgroupNames = fgNames
	reqHost.ConnectionString = csWithoutCredentials

	createdHost, err := hc.HStore.Create(&reqHost)
	if err != nil {
		secLog.WithError(err).Error("controllers/host_controller:Create() Host create failed")
		return nil, http.StatusInternalServerError, &commErr.ResourceError{Message: "Failed to create Host"}
	}

	//TODO: create credential

	defaultLog.Debugf("Associating host %s with flavorgroups %+q", reqHost.HostName, fgNames)
	if err := hc.linkFlavorgroupsToHost(fgNames, createdHost.Id); err != nil {
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

	if r.ContentLength == 0 {
		secLog.Error("controllers/host_controller:Update() The request body was not provided")
		return nil, http.StatusBadRequest, &commErr.ResourceError{Message:"The request body was not provided"}
	}

	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()

	var reqHost hvs.Host
	err := dec.Decode(&reqHost)
	if err != nil {
		secLog.WithError(err).Errorf("controllers/host_controller:Update() %s :  Failed to decode request body as Host", commLogMsg.AppRuntimeErr)
		return nil, http.StatusBadRequest, &commErr.ResourceError{Message:"Unable to decode JSON request body"}
	}

	if err := validateHostCreateCriteria(reqHost); err != nil {
		secLog.WithError(err).Error("controllers/host_controller:Update() Invalid host data")
		return nil, http.StatusBadRequest, &commErr.ResourceError{Message: err.Error()}
	}

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
		connectionString, err := utils.GenerateConnectionString(reqHost.ConnectionString)
		if err != nil {
			defaultLog.WithError(err).Error("controllers/host_controller:Update() Could not generate formatted connection string")
			return nil, http.StatusBadRequest, &commErr.ResourceError{Message: err.Error()}
		}

		// remove credentials from connection string for host table storage
		csWithoutCredentials := utils.GetConnectionStringWithoutCredentials(connectionString)
		defaultLog.Debugf("connection string without credentials : %s", csWithoutCredentials)

		host.ConnectionString = csWithoutCredentials

		//TODO: update credential
	}

	updatedHost, err := hc.HStore.Update(host)
	if err != nil {
		secLog.WithError(err).Error("controllers/host_controller:Update() Host update failed")
		return nil, http.StatusInternalServerError, &commErr.ResourceError{Message: "Failed to update Host"}
	}

	if len(reqHost.FlavorgroupNames) != 0 {
		defaultLog.Debugf("Associating host %s with flavorgroups : %+q", host.HostName, reqHost.FlavorgroupNames)
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

	if host.HostName != "" {
		if err := validation.ValidateHostname(host.HostName); err != nil {
			return errors.Wrap(err, "Valid Host Name must be specified")
		}
	}
	if host.ConnectionString != "" {
		return utils.ValidateConnectionString(host.ConnectionString)
	}
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
		if err := validation.ValidateStrings([]string{criteria.Key}); err != nil {
			return errors.Wrap(err, "Valid contents for key must be specified")
		}
	}
	if criteria.Value != "" {
		if err := validation.ValidateStrings([]string{criteria.Value}); err != nil {
			return errors.Wrap(err, "Valid contents for value must be specified")
		}
	}
	if criteria.NameEqualTo != "" {
		if err := validation.ValidateHostname(criteria.NameEqualTo); err != nil {
			return errors.Wrap(err, "Valid contents for nameEqualTo must be specified")
		}
	}
	if criteria.NameContains != "" {
		if err := validation.ValidateHostname(criteria.NameContains); err != nil {
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

func getHostInfo(cs string) (*model.HostInfo, error) {
	defaultLog.Trace("controllers/host_controller:getHostInfo() Entering")
	defer defaultLog.Trace("controllers/host_controller:getHostInfo() Leaving")

	conf := config.Global()
	hc, err := hostconnector.NewHostConnector(cs, conf.AASApiUrl, constants.TrustedCaCertsDir)
	if err != nil {
		return nil, errors.Wrap(err, "Could not instantiate host connector")
	}

	hostInfo, err := hc.GetHostDetails()
	return &hostInfo, err
}

func isLinuxHost(hostInfo *model.HostInfo) bool {
	defaultLog.Trace("controllers/host_controller:isLinuxHost() Entering")
	defer defaultLog.Trace("controllers/host_controller:isLinuxHost() Leaving")

	osName := strings.ToUpper(strings.TrimSpace(hostInfo.OSName))
	// true when running on a linux host that is not a docker container
	if osName != types.OsWindows.String() && osName != types.OsWindows2k16.String() &&
		osName != types.OsWindows2k16dc.String() && osName != types.OsVMware.String() &&
		!hostInfo.IsDockerEnvironment {
		return true
	}
	return false
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

	fg := utils.CreateFlavorGroupByName(flavorgroupName)
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
