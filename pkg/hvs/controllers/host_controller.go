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
	"github.com/intel-secl/intel-secl/v3/pkg/hvs/domain"
	"github.com/intel-secl/intel-secl/v3/pkg/hvs/domain/models"
	"github.com/intel-secl/intel-secl/v3/pkg/hvs/utils"
	commErr "github.com/intel-secl/intel-secl/v3/pkg/lib/common/err"
	commLogMsg "github.com/intel-secl/intel-secl/v3/pkg/lib/common/log/message"
	"github.com/intel-secl/intel-secl/v3/pkg/lib/common/validation"
	hostconnector "github.com/intel-secl/intel-secl/v3/pkg/lib/host-connector"
	"github.com/intel-secl/intel-secl/v3/pkg/model/hvs"
	model "github.com/intel-secl/intel-secl/v3/pkg/model/ta"
	"github.com/pkg/errors"
	"net/http"
	"net/url"
	"strings"
)

type HostController struct {
	HStore    domain.HostStore
	RStore    domain.ReportStore
	HSStore   domain.HostStatusStore
	FGStore   domain.FlavorGroupStore
	HCStore   domain.HostCredentialStore
	CertStore *models.CertificatesStore
}

func NewHostController(hs domain.HostStore, rs domain.ReportStore, hss domain.HostStatusStore,
	fgs domain.FlavorGroupStore, hcs domain.HostCredentialStore, certStore *models.CertificatesStore) *HostController {
	return &HostController{
		HStore:    hs,
		RStore:    rs,
		HSStore:   hss,
		FGStore:   fgs,
		HCStore:   hcs,
		CertStore: certStore,
	}
}

func (hc *HostController) Create(w http.ResponseWriter, r *http.Request) (interface{}, int, error) {
	defaultLog.Trace("controllers/host_controller:Create() Entering")
	defer defaultLog.Trace("controllers/host_controller:Create() Leaving")

	if r.ContentLength == 0 {
		secLog.Error("controllers/host_controller:Create() The request body was not provided")
		return nil, http.StatusBadRequest, &commErr.ResourceError{Message: "The request body was not provided"}
	}

	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()

	var reqHost hvs.Host
	err := dec.Decode(&reqHost)
	if err != nil {
		secLog.WithError(err).Errorf("controllers/host_controller:Create() %s :  Failed to decode request body as Host", commLogMsg.AppRuntimeErr)
		return nil, http.StatusBadRequest, &commErr.ResourceError{Message: "Unable to decode JSON request body"}
	}

	createdHost, status, err := hc.CreateHost(reqHost)
	if err != nil {
		return nil, status, err
	}

	secLog.WithField("host", createdHost).Infof("%s: Host created by: %s", commLogMsg.PrivilegeModified, r.RemoteAddr)
	return createdHost, status, nil
}

func (hc *HostController) Retrieve(w http.ResponseWriter, r *http.Request) (interface{}, int, error) {
	defaultLog.Trace("controllers/host_controller:Retrieve() Entering")
	defer defaultLog.Trace("controllers/host_controller:Retrieve() Leaving")

	id := uuid.MustParse(mux.Vars(r)["id"])
	host, err := hc.HStore.Retrieve(id)
	if err != nil {
		if strings.Contains(err.Error(), commErr.RowsNotFound) {
			defaultLog.WithError(err).WithField("id", id).Error("controllers/host_controller:Retrieve() Host with specified ID could not be located")
			return nil, http.StatusNotFound, &commErr.ResourceError{Message:"Host with specified id does not exist"}
		} else {
			defaultLog.WithError(err).WithField("id", id).Error("controllers/host_controller:Retrieve() Host retrieve failed")
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

	reqHost.Id = uuid.MustParse(mux.Vars(r)["id"])
	updatedHost, status, err := hc.UpdateHost(reqHost)
	if err != nil {
		return nil, status, err
	}

	//TODO: Since the host has been updated, add it to the verify queue

	secLog.WithField("host", updatedHost).Infof("%s: Host updated by: %s", commLogMsg.PrivilegeModified, r.RemoteAddr)
	return updatedHost, status, nil
}

func (hc *HostController) Delete(w http.ResponseWriter, r *http.Request) (interface{}, int, error) {
	defaultLog.Trace("controllers/host_controller:Delete() Entering")
	defer defaultLog.Trace("controllers/host_controller:Delete() Leaving")

	id := uuid.MustParse(mux.Vars(r)["id"])
	host, err := hc.HStore.Retrieve(id)
	if err != nil {
		if strings.Contains(err.Error(), commErr.RowsNotFound) {
			defaultLog.WithError(err).WithField("id", id).Error("controllers/host_controller:Delete()  Host with specified id could not be located")
			return nil, http.StatusNotFound, &commErr.ResourceError{Message:"Host with specified id does not exist"}
		} else {
			defaultLog.WithError(err).WithField("id", id).Error("controllers/host_controller:Delete() Host retrieve failed")
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
	criteria, err := populateHostFilterCriteria(r.URL.Query())
	if err != nil {
		secLog.WithError(err).Error("controllers/host_controller:Search() Invalid filter criteria")
		return nil, http.StatusBadRequest, &commErr.ResourceError{Message: err.Error()}
	}

	if criteria.Key != "" {
		hostIds, err := hc.HSStore.FindHostIdsByKeyValue(criteria.Key, criteria.Value)
		if err != nil {
			defaultLog.WithError(err).Error("controllers/host_controller:Search() HostStatus FindHostIdsByKeyValue failed")
			return nil, http.StatusInternalServerError, errors.Errorf("Failed to search Hosts")
		}
		criteria.IdList = hostIds
	}

	hosts, err := hc.HStore.Search(criteria)
	if err != nil {
		defaultLog.WithError(err).Error("controllers/host_controller:Search() Host search failed")
		return nil, http.StatusInternalServerError, errors.Errorf("Failed to search Hosts")
	}
	hostCollection := hvs.HostCollection{Hosts: hosts}

	secLog.Infof("%s: Hosts searched by: %s", commLogMsg.AuthorizedAccess, r.RemoteAddr)
	return hostCollection, http.StatusOK, nil
}

func (hc *HostController) CreateHost(reqHost hvs.Host) (interface{}, int, error) {
	defaultLog.Trace("controllers/host_controller:CreateHost() Entering")
	defer defaultLog.Trace("controllers/host_controller:CreateHost() Leaving")

	if reqHost.HostName == "" || reqHost.ConnectionString == "" {
		secLog.Error("controllers/host_controller:CreateHost() Host connection string and host name must be specified")
		return nil, http.StatusBadRequest, &commErr.ResourceError{Message: "Host connection string and host name must be specified"}
	}

	if err := validateHostCreateCriteria(reqHost); err != nil {
		secLog.WithError(err).Error("controllers/host_controller:CreateHost() Invalid host data")
		return nil, http.StatusBadRequest, &commErr.ResourceError{Message: err.Error()}
	}

	existingHosts, err := hc.HStore.Search(&models.HostFilterCriteria{
		NameEqualTo: reqHost.HostName,
	})
	if err != nil {
		defaultLog.WithError(err).Error("controllers/host_controller:CreateHost() Host search failed")
		return nil, http.StatusInternalServerError, &commErr.ResourceError{Message: "Failed to create Host"}
	}

	if existingHosts != nil && len(existingHosts) > 0 {
		secLog.WithField("Name", existingHosts[0].HostName).Warningf("%s: Trying to create duplicate Host", commLogMsg.InvalidInputBadParam)
		return nil, http.StatusBadRequest, &commErr.ResourceError{Message: "Host with this name already exist"}
	}

	connectionString, err := utils.GenerateConnectionString(reqHost.ConnectionString)
	if err != nil {
		defaultLog.WithError(err).Error("controllers/host_controller:CreateHost() Could not generate formatted connection string")
		return nil, http.StatusBadRequest, &commErr.ResourceError{Message: err.Error()}
	}

	defaultLog.Debugf("Connecting to host to get the host manifest and the hardware UUID of the host : %s", reqHost.HostName)
	// connect to the host and retrieve the host manifest
	hostInfo, err := hc.getHostInfo(connectionString)
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
	if hostInfo != nil && utils.IsLinuxHost(hostInfo) {
		defaultLog.Debug("Host is linux, associating with default software flavorgroups")
		swFgs := utils.GetDefaultSoftwareFlavorGroups(hostInfo.InstalledComponents)
		fgNames = append(fgNames, swFgs...)
	}

	// remove credentials from connection string for host table storage
	csWithoutCredentials := utils.GetConnectionStringWithoutCredentials(connectionString)
	defaultLog.Debugf("connection string without credentials : %s", csWithoutCredentials)

	reqHost.HardwareUuid = hwUuid
	reqHost.FlavorgroupNames = fgNames
	reqHost.ConnectionString = csWithoutCredentials

	createdHost, err := hc.HStore.Create(&reqHost)
	if err != nil {
		defaultLog.WithError(err).Error("controllers/host_controller:CreateHost() Host create failed")
		return nil, http.StatusInternalServerError, &commErr.ResourceError{Message: "Failed to create Host"}
	}

	//TODO: create credential

	defaultLog.Debugf("Associating host %s with flavorgroups %+q", reqHost.HostName, fgNames)
	if err := hc.linkFlavorgroupsToHost(fgNames, createdHost.Id); err != nil {
		return nil, http.StatusInternalServerError, &commErr.ResourceError{Message: "Failed to associate Host with flavorgroups"}
	}

	//TODO: Add host to flavor-verify queue

	return createdHost, http.StatusCreated, nil
}

func (hc *HostController) UpdateHost(reqHost hvs.Host) (interface{}, int, error) {
	defaultLog.Trace("controllers/host_controller:UpdateHost() Entering")
	defer defaultLog.Trace("controllers/host_controller:UpdateHost() Leaving")

	_, err := hc.HStore.Retrieve(reqHost.Id)
	if err != nil {
		if strings.Contains(err.Error(), commErr.RowsNotFound) {
			defaultLog.WithError(err).WithField("id", reqHost.Id).Error("controllers/host_controller:UpdateHost() Host with specified id could not be located")
			return nil, http.StatusNotFound, &commErr.ResourceError{Message:"Host with specified id does not exist"}
		} else {
			defaultLog.WithError(err).WithField("id", reqHost.Id).Error("controllers/host_controller:UpdateHost() Host retrieve failed")
			return nil, http.StatusInternalServerError, &commErr.ResourceError{Message: "Failed to update Host"}
		}
	}

	if reqHost.ConnectionString != "" {
		connectionString, err := utils.GenerateConnectionString(reqHost.ConnectionString)
		if err != nil {
			defaultLog.WithError(err).Error("controllers/host_controller:UpdateHost() Could not generate formatted connection string")
			return nil, http.StatusBadRequest, &commErr.ResourceError{Message: err.Error()}
		}

		// remove credentials from connection string for host table storage
		csWithoutCredentials := utils.GetConnectionStringWithoutCredentials(connectionString)
		defaultLog.Debugf("connection string without credentials : %s", csWithoutCredentials)

		reqHost.ConnectionString = csWithoutCredentials

		//TODO: update credential
	}

	updatedHost, err := hc.HStore.Update(&reqHost)
	if err != nil {
		defaultLog.WithError(err).Error("controllers/host_controller:UpdateHost() Host update failed")
		return nil, http.StatusInternalServerError, &commErr.ResourceError{Message: "Failed to update Host"}
	}

	if len(reqHost.FlavorgroupNames) != 0 {
		defaultLog.Debugf("Associating host %s with flavorgroups : %+q", updatedHost.HostName, reqHost.FlavorgroupNames)
		if err := hc.linkFlavorgroupsToHost(reqHost.FlavorgroupNames, updatedHost.Id); err != nil {
			return nil, http.StatusInternalServerError, &commErr.ResourceError{Message: "Failed to associate Host with flavorgroups"}
		}

		updatedHost.FlavorgroupNames = reqHost.FlavorgroupNames
	}

	return updatedHost, http.StatusOK, nil
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

func populateHostFilterCriteria(params url.Values) (*models.HostFilterCriteria, error) {
	defaultLog.Trace("controllers/host_controller:populateHostFilterCriteria() Entering")
	defer defaultLog.Trace("controllers/host_controller:populateHostFilterCriteria() Leaving")

	var criteria models.HostFilterCriteria

	if params.Get("id") != "" {
		id, err := uuid.Parse(params.Get("id"))
		if err != nil {
			return nil, errors.New("Invalid id query param value, must be UUID")
		}
		criteria.Id = id

	} else if params.Get("nameEqualTo") != "" {
		name := params.Get("nameEqualTo")
		if err := validation.ValidateHostname(name); err != nil {
			return nil, errors.Wrap(err, "Valid contents for nameEqualTo must be specified")
		}
		criteria.NameEqualTo = name

	} else if params.Get("nameContains") != "" {
		name := params.Get("nameContains")
		if err := validation.ValidateHostname(name); err != nil {
			return nil, errors.Wrap(err, "Valid contents for nameContains must be specified")
		}
		criteria.NameContains = name

	} else if params.Get("hostHardwareId") != "" {
		hwid, err := uuid.Parse(params.Get("hostHardwareId"))
		if err != nil {
			return nil, errors.New("Invalid hostHardwareId query param value, must be UUID")
		}
		criteria.HostHardwareId = hwid

	} else if params.Get("key") != "" && params.Get("value") != "" {
		key := params.Get("key")
		value := params.Get("value")
		if err := validation.ValidateStrings([]string{key, value}); err != nil {
			return nil, errors.Wrap(err, "Valid contents for key and value must be specified")
		}
		criteria.Key = key
		criteria.Value = value
	}

	return &criteria, nil
}

func (hc *HostController) getHostInfo(cs string) (*model.HostInfo, error) {
	defaultLog.Trace("controllers/host_controller:getHostInfo() Entering")
	defer defaultLog.Trace("controllers/host_controller:getHostInfo() Leaving")

	certList, err := hc.CertStore.GetCertificates(models.CaCertTypesRootCa.String())
	if err != nil {
		return nil, errors.Wrap(err, "Error getting list of CA certificates from Certificate store")
	}
	conf := config.Global()
	hconnector, err := hostconnector.NewHostConnector(cs, conf.AASApiUrl, certList)
	if err != nil {
		return nil, errors.Wrap(err, "Could not instantiate host connector")
	}

	hostInfo, err := hconnector.GetHostDetails()
	return &hostInfo, err
}
