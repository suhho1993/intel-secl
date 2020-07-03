/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package controllers

import (
	"encoding/json"
	"fmt"
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
	hcConstants "github.com/intel-secl/intel-secl/v3/pkg/lib/host-connector/constants"
	hcUtil "github.com/intel-secl/intel-secl/v3/pkg/lib/host-connector/util"
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
	HTManager domain.HostTrustManager
}

func NewHostController(hs domain.HostStore, rs domain.ReportStore, hss domain.HostStatusStore,
	fgs domain.FlavorGroupStore, hcs domain.HostCredentialStore, cs *models.CertificatesStore,
	htm domain.HostTrustManager) *HostController {
	return &HostController{
		HStore:    hs,
		RStore:    rs,
		HSStore:   hss,
		FGStore:   fgs,
		HCStore:   hcs,
		CertStore: cs,
		HTManager: htm,
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

	id := uuid.MustParse(mux.Vars(r)["hId"])
	host, status, err := hc.retrieveHost(id)
	if err != nil {
		return nil, status, err
	}

	secLog.WithField("host", host).Infof("%s: Host retrieved by: %s", commLogMsg.AuthorizedAccess, r.RemoteAddr)
	return host, status, nil
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

	reqHost.Id = uuid.MustParse(mux.Vars(r)["hId"])
	updatedHost, status, err := hc.UpdateHost(reqHost)
	if err != nil {
		return nil, status, err
	}

	defaultLog.Debugf("Adding host %v to flavor-verify queue", reqHost.Id)
	// Since the host has been updated, add it to the verify queue
	err = hc.HTManager.VerifyHostsAsync([]uuid.UUID{reqHost.Id}, true, false)
	if err != nil {
		defaultLog.WithError(err).Error("controllers/host_controller:CreateHost() Host to Flavor Verify Queue addition failed")
		return nil, http.StatusInternalServerError, &commErr.ResourceError{Message: "Failed to add Host to Flavor Verify Queue"}
	}

	secLog.WithField("host", updatedHost).Infof("%s: Host updated by: %s", commLogMsg.PrivilegeModified, r.RemoteAddr)
	return updatedHost, status, nil
}

func (hc *HostController) Delete(w http.ResponseWriter, r *http.Request) (interface{}, int, error) {
	defaultLog.Trace("controllers/host_controller:Delete() Entering")
	defer defaultLog.Trace("controllers/host_controller:Delete() Leaving")

	id := uuid.MustParse(mux.Vars(r)["hId"])
	host, status, err := hc.retrieveHost(id)
	if err != nil {
		return nil, status, err
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

	connectionString, credential, err := hc.GenerateConnectionString(reqHost.ConnectionString)
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

	// create credential
	var hostCredential models.HostCredential
	hostCredential.HostId = createdHost.Id
	hostCredential.HostName = createdHost.HostName
	hostCredential.Credential = credential
	if createdHost.HardwareUuid != uuid.Nil {
		hostCredential.HardwareUuid = createdHost.HardwareUuid
	}

	_, err = hc.HCStore.Create(&hostCredential)
	if err != nil {
		defaultLog.WithError(err).Error("controllers/host_controller:CreateHost() Host Credential create failed")
		return nil, http.StatusInternalServerError, &commErr.ResourceError{Message: "Failed to create Host Credential"}
	}

	defaultLog.Debugf("Associating host %s with flavorgroups %+q", reqHost.HostName, fgNames)
	if err := hc.linkFlavorgroupsToHost(fgNames, createdHost.Id); err != nil {
		defaultLog.WithError(err).Error("controllers/host_controller:CreateHost() Host FlavorGroup association failed")
		return nil, http.StatusInternalServerError, &commErr.ResourceError{Message: "Failed to associate Host with flavorgroups"}
	}

	defaultLog.Debugf("Adding host %s to flavor-verify queue", reqHost.HostName)
	// Since we are adding a new host, the forceUpdate flag should be set to true so that
	// we connect to the host and get the latest host manifest to verify against.
	err = hc.HTManager.VerifyHostsAsync([]uuid.UUID{createdHost.Id}, true, false)
	if err != nil {
		defaultLog.WithError(err).Error("controllers/host_controller:CreateHost() Host to Flavor Verify Queue addition failed")
		return nil, http.StatusInternalServerError, &commErr.ResourceError{Message: "Failed to add Host to Flavor Verify Queue"}
	}

	return createdHost, http.StatusCreated, nil
}

func (hc *HostController) UpdateHost(reqHost hvs.Host) (interface{}, int, error) {
	defaultLog.Trace("controllers/host_controller:UpdateHost() Entering")
	defer defaultLog.Trace("controllers/host_controller:UpdateHost() Leaving")

	_, status, err := hc.retrieveHost(reqHost.Id)
	if err != nil {
		return nil, status, err
	}

	if reqHost.ConnectionString != "" {
		connectionString, credential, err := hc.GenerateConnectionString(reqHost.ConnectionString)
		if err != nil {
			defaultLog.WithError(err).Error("controllers/host_controller:UpdateHost() Could not generate formatted connection string")
			return nil, http.StatusBadRequest, &commErr.ResourceError{Message: err.Error()}
		}

		// remove credentials from connection string for host table storage
		csWithoutCredentials := utils.GetConnectionStringWithoutCredentials(connectionString)
		defaultLog.Debugf("connection string without credentials : %s", csWithoutCredentials)

		reqHost.ConnectionString = csWithoutCredentials

		// update credential
		hostCredential, err := hc.HCStore.FindByHostId(reqHost.Id)
		if err != nil {
			if strings.Contains(err.Error(), commErr.RowsNotFound) {
				defaultLog.Debugf("controllers/host_controller:UpdateHost() Host Credential with specified host id could not be located")
				hostCredential = nil
			} else {
				defaultLog.WithError(err).WithField("hostId", reqHost.Id).Error("controllers/host_controller:UpdateHost() Host Credential retrieve failed")
				return nil, http.StatusInternalServerError, &commErr.ResourceError{Message: "Failed to retrieve Host Credential from database"}
			}
		}

		if hostCredential != nil {
			hostCredential.Credential = credential
			_, err = hc.HCStore.Update(hostCredential)
			if err != nil {
				defaultLog.WithError(err).Error("controllers/host_controller:UpdateHost() Host Credential update failed")
				return nil, http.StatusInternalServerError, &commErr.ResourceError{Message: "Failed to update Host Credential"}
			}
		}
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

func (hc *HostController) retrieveHost(id uuid.UUID) (interface{}, int, error) {
	defaultLog.Trace("controllers/host_controller:retrieveHost() Entering")
	defer defaultLog.Trace("controllers/host_controller:retrieveHost() Leaving")

	host, err := hc.HStore.Retrieve(id)
	if err != nil {
		if strings.Contains(err.Error(), commErr.RowsNotFound) {
			defaultLog.WithError(err).WithField("id", id).Error("controllers/host_controller:retrieveHost() Host with specified id could not be located")
			return nil, http.StatusNotFound, &commErr.ResourceError{Message:"Host with specified id does not exist"}
		} else {
			defaultLog.WithError(err).WithField("id", id).Error("controllers/host_controller:retrieveHost() Host retrieve failed")
			return nil, http.StatusInternalServerError, &commErr.ResourceError{Message: "Failed to retrieve Host from database"}
		}
	}
	return host, http.StatusOK, nil
}

// GenerateConnectionString creates a formatted connection string. If the username and password are not specified, then it would retrieve it
// from the credential table and forms the complete connection string.
func (hc *HostController) GenerateConnectionString(cs string) (string, string, error) {
	defaultLog.Trace("controllers/host_controller:GenerateConnectionString() Entering")
	defer defaultLog.Trace("controllers/host_controller:GenerateConnectionString() Leaving")

	vc, err := hcUtil.GetConnectorDetails(cs)
	if err != nil {
		return "", "", errors.Wrap(err, "Could not get vendor details from connection string")
	}

	conf := config.Global()
	var username, password, credential string

	if vc.Vendor != hcConstants.VMWARE {
		username = "u=" + conf.HVS.Username
		password = "p=" + conf.HVS.Password
		credential = fmt.Sprintf("%s;%s", username, password)
	} else {
		//if credentials not specified in connection string, retrieve from credential table
		if !strings.Contains(cs, "u=") || !strings.Contains(cs, "p=") {
			var hostname string
			// If the connection string is for VMware, we would have this substring from which we need to extract
			// the host name. Otherwise we can extract the host name after the https:// in the connection string.
			if strings.Contains(cs, "h=") {
				hostname = vc.Configuration.Hostname
			} else {
				hostname = strings.Split(strings.Split(cs, "//")[1], ":")[0]
			}

			if hostname == "" {
				return "", "", errors.New("Host connection string is formatted incorrectly, cannot retrieve host name")
			}

			// Fetch credentials from db
			hostCredential, err := hc.HCStore.FindByHostName(hostname)
			if err != nil {
				return "", "", errors.Wrap(err, "Credentials must be provided for the host connection string")
			}

			credential = hostCredential.Credential
			username = strings.Split(credential, ";")[0]
			password = strings.Split(credential, ";")[1]
		} else {
			username = vc.Configuration.Username
			password = vc.Configuration.Password
			credential = fmt.Sprintf("u=%s;p=%s", username, password)
		}
	}

	// validate credential information values are not null or empty
	if credential == "" {
		return "", "", errors.New("Credentials must be provided for the host connection string")
	}

	if username == "" {
		return "", "", errors.New("Username must be provided in the host connection string")
	}

	if password == "" {
		return "", "", errors.New("Password must be provided in the host connection string")
	}

	return fmt.Sprintf("%s;%s", cs, credential), credential, nil
}

func (hc *HostController) getHostInfo(cs string) (*model.HostInfo, error) {
	defaultLog.Trace("controllers/host_controller:getHostInfo() Entering")
	defer defaultLog.Trace("controllers/host_controller:getHostInfo() Leaving")

	certList, err := hc.CertStore.GetCertificates(models.CaCertTypesRootCa.String())
	if err != nil {
		return nil, errors.Wrap(err, "Error getting list of CA certificates from Certificate store")
	}
	conf := config.Global()
	htcFactory := hostconnector.NewHostConnectorFactory(conf.AASApiUrl, certList)
	hconnector, err := htcFactory.NewHostConnector(cs)
	if err != nil {
		return nil, errors.Wrap(err, "Could not instantiate host connector")
	}

	hostInfo, err := hconnector.GetHostDetails()
	return &hostInfo, err
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
			linkExists, err := hc.flavorGroupHostLinkExists(hostId, existingFlavorGroups.Flavorgroups[0].ID)
			if err != nil {
				return errors.Wrap(err, "Could not check host-flavorgroup link existence")
			}
			if !linkExists {
				flavorgroupIds = append(flavorgroupIds, existingFlavorGroups.Flavorgroups[0].ID)
			}
		} else {
			flavorgroup, err := hc.createNewFlavorGroup(flavorgroupName)
			if err != nil {
				return errors.Wrapf(err, "Could not create flavorgroup with name : %s", flavorgroupName)
			}
			flavorgroupIds = append(flavorgroupIds, flavorgroup.ID)
		}
	}

	defaultLog.Debugf("Linking host %v with flavorgroups %+q", hostId, flavorgroupIds)
	if err := hc.HStore.AddFlavorgroups(hostId, flavorgroupIds); err != nil {
		return errors.Wrap(err, "Could not create host-flavorgroup links")
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

func (hc *HostController) flavorGroupHostLinkExists(hostId, flavorgroupId uuid.UUID) (bool, error) {
	defaultLog.Trace("controllers/host_controller:flavorGroupHostLinkExists() Entering")
	defer defaultLog.Trace("controllers/host_controller:flavorGroupHostLinkExists() Leaving")

	// retrieve the host-flavorgroup link using host id and flavorgroup id
	_, err := hc.HStore.RetrieveFlavorgroup(hostId, flavorgroupId)
	if err != nil {
		if strings.Contains(err.Error(), commErr.RowsNotFound) {
			return false, nil
		} else {
			return false, err
		}
	}
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

func (hc *HostController) AddFlavorgroup(w http.ResponseWriter, r *http.Request) (interface{}, int, error) {
	defaultLog.Trace("controllers/host_controller:AddFlavorgroup() Entering")
	defer defaultLog.Trace("controllers/host_controller:AddFlavorgroup() Leaving")

	if r.ContentLength == 0 {
		secLog.Error("controllers/host_controller:AddFlavorgroup() The request body was not provided")
		return nil, http.StatusBadRequest, &commErr.ResourceError{Message: "The request body was not provided"}
	}

	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()

	var reqHostFlavorgroup hvs.HostFlavorgroup
	err := dec.Decode(&reqHostFlavorgroup)
	if err != nil {
		secLog.WithError(err).Errorf("controllers/host_controller:AddFlavorgroup() %s :  Failed to decode request body as Host Flavorgroup link", commLogMsg.AppRuntimeErr)
		return nil, http.StatusBadRequest, &commErr.ResourceError{Message: "Unable to decode JSON request body"}
	}

	if reqHostFlavorgroup.FlavorgroupId == uuid.Nil {
		secLog.Error("controllers/host_controller:AddFlavorgroup() Flavorgroup Id must be specified")
		return nil, http.StatusBadRequest, &commErr.ResourceError{Message: "Flavorgroup Id must be specified"}
	}

	hId := uuid.MustParse(mux.Vars(r)["hId"])
	_, status, err := hc.retrieveHost(hId)
	if err != nil {
		return nil, status, err
	}

	_, err = hc.FGStore.Retrieve(reqHostFlavorgroup.FlavorgroupId)
	if err != nil {
		if strings.Contains(err.Error(), commErr.RowsNotFound) {
			defaultLog.WithError(err).WithField("id", reqHostFlavorgroup.FlavorgroupId).Error("controllers/host_controller:AddFlavorgroup() Flavorgroup with specified id could not be located")
			return nil, http.StatusNotFound, &commErr.ResourceError{Message:"Flavorgroup with specified id does not exist"}
		} else {
			defaultLog.WithError(err).WithField("id", reqHostFlavorgroup.FlavorgroupId).Error("controllers/host_controller:AddFlavorgroup() Flavorgroup retrieve failed")
			return nil, http.StatusInternalServerError, &commErr.ResourceError{Message: "Failed to retrieve Flavorgroup from database"}
		}
	}

	defaultLog.Debugf("Linking host %v with flavorgroup %v", hId, reqHostFlavorgroup.FlavorgroupId)
	reqHostFlavorgroup.HostId = hId
	err = hc.HStore.AddFlavorgroups(hId, []uuid.UUID{reqHostFlavorgroup.FlavorgroupId})
	if err != nil {
		defaultLog.WithError(err).Error("controllers/host_controller:AddFlavorgroup() Host Flavorgroup association failed")
		return nil, http.StatusInternalServerError, &commErr.ResourceError{Message: "Failed to associate Host with Flavorgroup"}
	}

	defaultLog.Debugf("Adding host %v to flavor-verify queue", hId)
	err = hc.HTManager.VerifyHostsAsync([]uuid.UUID{hId}, false, false)
	if err != nil {
		defaultLog.WithError(err).Error("controllers/host_controller:CreateHost() Host to Flavor Verify Queue addition failed")
		return nil, http.StatusInternalServerError, &commErr.ResourceError{Message: "Failed to add Host to Flavor Verify Queue"}
	}

	secLog.WithField("host-flavorgroup-link", reqHostFlavorgroup).Infof("%s: Host Flavorgroup link created by: %s", commLogMsg.PrivilegeModified, r.RemoteAddr)
	return reqHostFlavorgroup, http.StatusCreated, nil
}

func (hc *HostController) RetrieveFlavorgroup(w http.ResponseWriter, r *http.Request) (interface{}, int, error) {
	defaultLog.Trace("controllers/host_controller:RetrieveFlavorgroup() Entering")
	defer defaultLog.Trace("controllers/host_controller:RetrieveFlavorgroup() Leaving")

	hId := uuid.MustParse(mux.Vars(r)["hId"])
	fgId := uuid.MustParse(mux.Vars(r)["fgId"])
	hostFlavorgroup, status, err := hc.retrieveFlavorgroup(hId, fgId)
	if err != nil {
		return nil, status, err
	}

	secLog.WithField("host-flavorgroup-link", hostFlavorgroup).Infof("%s: Host Flavorgroup link retrieved by: %s", commLogMsg.AuthorizedAccess, r.RemoteAddr)
	return hostFlavorgroup, status, nil
}

func (hc *HostController) RemoveFlavorgroup(w http.ResponseWriter, r *http.Request) (interface{}, int, error) {
	defaultLog.Trace("controllers/host_controller:RemoveFlavorgroup() Entering")
	defer defaultLog.Trace("controllers/host_controller:RemoveFlavorgroup() Leaving")

	hId := uuid.MustParse(mux.Vars(r)["hId"])
	fgId := uuid.MustParse(mux.Vars(r)["fgId"])
	hostFlavorgroup, status, err := hc.retrieveFlavorgroup(hId, fgId)
	if err != nil {
		return nil, status, err
	}

	if err := hc.HStore.RemoveFlavorgroups(hId, []uuid.UUID{fgId}); err != nil {
		defaultLog.WithError(err).Error("controllers/host_controller:RemoveFlavorgroup() Host Flavorgroup link delete failed")
		return nil, http.StatusInternalServerError, &commErr.ResourceError{Message:"Failed to delete Host Flavorgroup link"}
	}

	secLog.WithField("host-flavorgroup-link", hostFlavorgroup).Infof("Host Flavorgroup link deleted by: %s", r.RemoteAddr)
	return nil, http.StatusNoContent, nil
}

func (hc *HostController) SearchFlavorgroups(w http.ResponseWriter, r *http.Request) (interface{}, int, error) {
	defaultLog.Trace("controllers/host_controller:SearchFlavorgroups() Entering")
	defer defaultLog.Trace("controllers/host_controller:SearchFlavorgroups() Leaving")

	hId := uuid.MustParse(mux.Vars(r)["hId"])
	fgIds, err := hc.HStore.SearchFlavorgroups(hId)
	if err != nil {
		defaultLog.WithError(err).Error("controllers/host_controller:SearchFlavorgroups() Host Flavorgroup links search failed")
		return nil, http.StatusInternalServerError, errors.Errorf("Failed to search Host Flavorgroup links")
	}

	var hostFlavorgroups []hvs.HostFlavorgroup
	for _, fgId := range fgIds {
		hostFlavorgroups = append(hostFlavorgroups, hvs.HostFlavorgroup{
			HostId:        hId,
			FlavorgroupId: fgId,
		})
	}
	hostFlavorgroupCollection := hvs.HostFlavorgroupCollection{HostFlavorgroups: hostFlavorgroups}

	secLog.Infof("%s: Host Flavorgroup links searched by: %s", commLogMsg.AuthorizedAccess, r.RemoteAddr)
	return hostFlavorgroupCollection, http.StatusOK, nil
}

func (hc *HostController) retrieveFlavorgroup(hId, fgId uuid.UUID) (interface{}, int, error) {
	defaultLog.Trace("controllers/host_controller:retrieveFlavorgroup() Entering")
	defer defaultLog.Trace("controllers/host_controller:retrieveFlavorgroup() Leaving")

	hostFlavorgroup, err := hc.HStore.RetrieveFlavorgroup(hId, fgId)
	if err != nil {
		if strings.Contains(err.Error(), commErr.RowsNotFound) {
			defaultLog.WithError(err).Error("controllers/host_controller:RetrieveFlavorgroup() Host Flavorgroup link with specified ids could not be located")
			return nil, http.StatusNotFound, &commErr.ResourceError{Message:"Host Flavorgroup link with specified ids does not exist"}
		} else {
			defaultLog.WithError(err).Error("controllers/host_controller:RetrieveFlavorgroup() Host Foavorgroup link retrieve failed")
			return nil, http.StatusInternalServerError, &commErr.ResourceError{Message: "Failed to retrieve Host Flavorgroup link from database"}
		}
	}
	return hostFlavorgroup, http.StatusOK, nil
}
