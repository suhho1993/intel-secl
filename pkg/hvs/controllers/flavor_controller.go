/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */

package controllers

import (
	"crypto"
	"crypto/rsa"
	"encoding/json"
	"github.com/google/uuid"
	"github.com/gorilla/mux"
	"github.com/intel-secl/intel-secl/v3/pkg/hvs/domain"
	dm "github.com/intel-secl/intel-secl/v3/pkg/hvs/domain/models"
	"github.com/intel-secl/intel-secl/v3/pkg/hvs/utils"
	commErr "github.com/intel-secl/intel-secl/v3/pkg/lib/common/err"
	commLogMsg "github.com/intel-secl/intel-secl/v3/pkg/lib/common/log/message"
	"github.com/intel-secl/intel-secl/v3/pkg/lib/common/validation"
	"github.com/intel-secl/intel-secl/v3/pkg/lib/flavor"
	fc "github.com/intel-secl/intel-secl/v3/pkg/lib/flavor/common"
	fConst "github.com/intel-secl/intel-secl/v3/pkg/lib/flavor/constants"
	fm "github.com/intel-secl/intel-secl/v3/pkg/lib/flavor/model"
	fType "github.com/intel-secl/intel-secl/v3/pkg/lib/flavor/types"
	fu "github.com/intel-secl/intel-secl/v3/pkg/lib/flavor/util"
	hcType "github.com/intel-secl/intel-secl/v3/pkg/lib/host-connector/types"
	"github.com/intel-secl/intel-secl/v3/pkg/model/hvs"
	"github.com/pkg/errors"
	"net/http"
	"reflect"
	"strings"
)

type FlavorController struct {
	FStore    domain.FlavorStore
	FGStore   domain.FlavorGroupStore
	HStore    domain.HostStore
	CertStore *dm.CertificatesStore
	HostCon   HostController
}

func NewFlavorController(fs domain.FlavorStore, fgs domain.FlavorGroupStore, hs domain.HostStore, certStore *dm.CertificatesStore, hcConfig domain.HostControllerConfig) *FlavorController {
	// certStore should have an entry for Flavor Signing CA
	if _, found := (*certStore)[dm.CertTypesFlavorSigning.String()]; !found {
		defaultLog.Errorf("controllers/flavor_controller:NewFlavorController() %s : Flavor Signing KeyPair not found in CertStore", commLogMsg.AppRuntimeErr)
		return nil
	}

	var fsKey crypto.PrivateKey
	fsKey = (*certStore)[dm.CertTypesFlavorSigning.String()].Key
	if fsKey == nil {
		defaultLog.Errorf("controllers/flavor_controller:NewFlavorController() %s : Flavor Signing Key not found in CertStore", commLogMsg.AppRuntimeErr)
		return nil
	}

	hController := HostController{
		HStore:   hs,
		HCConfig: hcConfig,
	}

	return &FlavorController{
		FStore:    fs,
		FGStore:   fgs,
		HStore:    hs,
		CertStore: certStore,
		HostCon:   hController,
	}
}

func (fcon *FlavorController) Create(w http.ResponseWriter, r *http.Request) (interface{}, int, error) {
	defaultLog.Trace("controllers/flavor_controller:Create() Entering")
	defer defaultLog.Trace("controllers/flavor_controller:Create() Leaving")
	secLog.Infof("Request to create flavors received")
	if r.ContentLength == 0 {
		secLog.Error("controllers/flavor_controller:Create() The request body is not provided")
		return nil, http.StatusBadRequest, &commErr.ResourceError{Message: "The request body is not provided"}
	}

	var flavorCreateReq dm.FlavorCreateRequest
	// Decode the incoming json data to note struct
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()

	err := dec.Decode(&flavorCreateReq)
	if err != nil {
		defaultLog.WithError(err).Errorf("controllers/flavor_controller:Create() %s :  Failed to decode request body as Flavor", commLogMsg.AppRuntimeErr)
		return nil, http.StatusBadRequest, &commErr.ResourceError{Message: "Unable to decode JSON request body"}
	}

	defaultLog.Debug("Validating create flavor request")
	err = validateFlavorCreateRequest(flavorCreateReq)
	if err != nil {
		defaultLog.WithError(err).Error("controllers/flavor_controller:Create() Invalid flavor create criteria")
		return nil, http.StatusBadRequest, &commErr.ResourceError{Message: "Invalid flavor create criteria"}
	}

	signedFlavors, err := fcon.createFlavors(flavorCreateReq)
	if err != nil {
		return nil, http.StatusInternalServerError, &commErr.ResourceError{Message: err.Error()}
	}
	secLog.Info("Flavors created successfully")
	return signedFlavors, http.StatusCreated, nil
}

func (fcon *FlavorController) createFlavors(flavorReq dm.FlavorCreateRequest) ([]hvs.SignedFlavor, error) {
	defaultLog.Trace("controllers/flavor_controller:createFlavors() Entering")
	defer defaultLog.Trace("controllers/flavor_controller:createFlavors() Leaving")

	var flavorParts []fc.FlavorPart
	var platformFlavor *fType.PlatformFlavor
	flavorFlavorPartMap := make(map[fc.FlavorPart][]hvs.SignedFlavor)

	if flavorReq.ConnectionString != "" {
		// get flavor from host
		// get host manifest from the host
		defaultLog.Debug("Host connection string given, trying to create flavors from host")
		connectionString, _, err := GenerateConnectionString(flavorReq.ConnectionString, &fcon.HostCon)
		if err != nil {
			defaultLog.Error("controllers/flavor_controller:CreateFlavors() Could not generate formatted connection string")
			return nil, errors.Wrap(err, "Error while generating a formatted connection string")
		}
		defaultLog.Debugf("Getting host manifest from host %s", connectionString)
		hostManifest, err := fcon.getHostManifest(connectionString)
		if err != nil {
			defaultLog.Error("controllers/flavor_controller:CreateFlavors() Error getting host manifest")
			return nil, errors.Wrap(err, "Error getting host manifest")
		}
		// TODO: check if an asset tag certificate for the host with given HwUUID exists
		// create a platform flavor with the host manifest information
		defaultLog.Debug("Creating flavor from host manifest using flavor library")
		newPlatformFlavor, err := flavor.NewPlatformFlavorProvider(hostManifest, nil)
		if err != nil {
			defaultLog.Errorf("controllers/flavor_controller:createFlavors() Error while creating platform flavor instance from host manifest and tag certificate")
			return nil, errors.Wrap(err, "Error while creating platform flavor instance from host manifest and tag certificate")
		}
		platformFlavor, err = newPlatformFlavor.GetPlatformFlavor()
		if err != nil {
			defaultLog.Errorf("controllers/flavor_controller:createFlavors() Error while creating platform flavors for host %s", hostManifest.HostInfo.HardwareUUID)
			return nil, errors.Wrapf(err, " Error while creating platform flavors for host %s", hostManifest.HostInfo.HardwareUUID)
		}
		// add all the flavor parts from create request to the list flavor parts to be associated with a flavorgroup
		if len(flavorReq.FlavorParts) >= 1 {
			for _, flavorPart := range flavorReq.FlavorParts {
				flavorParts = append(flavorParts, flavorPart)
			}
		}

	} else if len(flavorReq.FlavorCollection) >= 1 || len(flavorReq.SignedFlavorCollection) >= 1 {
		defaultLog.Debug("Creating flavors from flavor content")
		var flavorSignKey = (*fcon.CertStore)[dm.CertTypesFlavorSigning.String()].Key
		// create flavors from flavor content
		// TODO: currently checking only the unsigned flavors
		for _, flavor := range flavorReq.FlavorCollection {
			// TODO : check if BIOS flavor part name is still accepted, if it is update the flavorpart to PLATFORM
			defaultLog.Debug("Validating flavor meta content for flavor part")
			if err := validateFlavorMetaContent(&flavor.Meta); err != nil {
				defaultLog.Error("controllers/flavor_controller:createFlavors() Valid flavor content must be given, invalid flavor meta data")
				return nil, errors.Wrap(err, "Invalid flavor content")
			}
			// get flavor part form the content
			var fp fc.FlavorPart
			if err := (&fp).Parse(flavor.Meta.Description.FlavorPart); err != nil {
				defaultLog.Error("controllers/flavor_controller:createFlavors() Valid flavor part must be given")
				return nil, errors.Wrap(err, "Error parsing flavor part")
			}
			// check if flavor part already exists in flavor-flavorPart map, else sign the flavor and add it to the map
			var platformFlavorUtil fu.PlatformFlavorUtil
			fBytes, err := json.Marshal(flavor)
			if err != nil {
				defaultLog.Error("controllers/flavor_controller:createFlavors() Error while marshalling flavor content")
				return nil, errors.Wrap(err, "Error while marshalling flavor content")
			}
			defaultLog.Debug("Signing the flavor content")
			signedFlavorStr, err := platformFlavorUtil.GetSignedFlavor(string(fBytes), flavorSignKey.(*rsa.PrivateKey))
			if err != nil {
				defaultLog.Error("controllers/flavor_controller:createFlavors() Error getting signed flavor from flavor library")
				return nil, errors.Wrap(err, "Error getting signed flavor from flavor library")
			}
			var signedFlavor hvs.SignedFlavor
			if err = json.Unmarshal([]byte(signedFlavorStr), &signedFlavor); err != nil {
				defaultLog.Error("controllers/flavor_controller:createFlavors() Error while trying to unmarshal signed flavor")
				return nil, errors.Wrap(err, "Error while trying to unmarshal signed flavor")
			}
			if _, ok := flavorFlavorPartMap[fp]; ok {
				// sign the flavor and add it to the same flavor list
				flavorFlavorPartMap[fp] = append(flavorFlavorPartMap[fp], signedFlavor)
			} else {
				// add the flavor to the new list
				flavorFlavorPartMap[fp] = []hvs.SignedFlavor{signedFlavor}
			}
			flavorParts = append(flavorParts, fp)
		}
		if len(flavorFlavorPartMap) == 0 {
			defaultLog.Error("controllers/flavor_controller:createFlavors() Valid flavor content must be given")
			return nil, errors.New("Valid flavor content must be given")
		}
	}
	var err error
	// add all flavorparts to default flavorgroups if flavorgroup name is not given
	if flavorReq.FlavorgroupName == "" && len(flavorReq.FlavorParts) == 0 {
		for _, flavorPart := range fc.GetFlavorTypes() {
			flavorParts = append(flavorParts, flavorPart)
		}
	}
	// get the flavorgroup name
	fgName := flavorReq.FlavorgroupName
	if fgName == "" {
		fgName = dm.FlavorGroupsAutomatic.String()
	}
	// check if the flavorgroup is already created, else create flavorgroup
	flavorgroup, err := fcon.createFGIfNotExists(fgName)
	if err != nil || flavorgroup.ID == uuid.Nil {
		defaultLog.Error("controllers/flavor_controller:createFlavors() Error getting flavorgroup")
		return nil, err
	}

	// if platform flavor was retrieved from host, break it into the flavor part flavor map using the flavorgroup id
	if platformFlavor != nil {
		flavorFlavorPartMap = fcon.retrieveFlavorCollection(platformFlavor, flavorgroup.ID, flavorParts)
	}

	if flavorFlavorPartMap == nil || len(flavorFlavorPartMap) == 0 {
		defaultLog.Error("controllers/flavor_controller:createFlavors() Cannot create flavors")
		return nil, errors.New("Unable to create Flavors")
	}
	return fcon.addFlavorToFlavorgroup(flavorFlavorPartMap, flavorgroup.ID)
}

func (fcon *FlavorController) getHostManifest(cs string) (*hcType.HostManifest, error) {
	defaultLog.Trace("controllers/flavor_controller:getHostManifest() Entering")
	defer defaultLog.Trace("controllers/flavor_controller:getHostManifest() Leaving")
	hostConnector, err := fcon.HostCon.HCConfig.HostConnectorProvider.NewHostConnector(cs)
	if err != nil {
		return nil, errors.Wrap(err, "Could not instantiate host connector")
	}
	hostManifest, err := hostConnector.GetHostManifest()
	return &hostManifest, err
}

func (fcon *FlavorController) addFlavorToFlavorgroup(flavorFlavorPartMap map[fc.FlavorPart][]hvs.SignedFlavor, flavorgroupId uuid.UUID) ([]hvs.SignedFlavor, error) {
	defaultLog.Trace("controllers/flavor_controller:addFlavorToFlavorgroup() Entering")
	defer defaultLog.Trace("controllers/flavor_controller:addFlavorToFlavorgroup() Leaving")

	defaultLog.Debug("Adding flavors to flavorgroup")
	var returnSignedFlavors []hvs.SignedFlavor
	var flavorIds []uuid.UUID

	for flavorPart, signedFlavors := range flavorFlavorPartMap {
		for _, signedFlavor := range signedFlavors {
			signedFlavorCreated, err := fcon.FStore.Create(&signedFlavor)
			if err != nil {
				defaultLog.Error("controllers/flavor_controller: addFlavorToFlavorgroup() : Unable to create flavors")
				return nil, err
			}
			// if the flavor is created, associate it with an appropriate flavorgroup
			if signedFlavorCreated != nil && signedFlavorCreated.Flavor.Meta.ID.String() != "" {
				// add the created flavor to the list of flavors to be returned
				returnSignedFlavors = append(returnSignedFlavors, *signedFlavorCreated)
				if flavorPart == fc.FlavorPartAssetTag {
					if err = fcon.addFlavorToUniqueFlavorgroup(signedFlavorCreated.Flavor, true); err != nil {
						defaultLog.Error("controllers/flavor_controller:addFlavorToFlavorgroup() Unable to add flavor to HOST_UNIQUE flavorgroup")
						return nil, err
					}
				} else if flavorPart == fc.FlavorPartHostUnique {
					if err = fcon.addFlavorToUniqueFlavorgroup(signedFlavorCreated.Flavor, false); err != nil {
						defaultLog.Error("controllers/flavor_controller:addFlavorToFlavorgroup() Unable to add flavor to HOST_UNIQUE flavorgroup")
						return nil, err
					}
				} else if flavorPart == fc.FlavorPartSoftware && strings.Contains(signedFlavorCreated.Flavor.Meta.Description.Label, fConst.DefaultSoftwareFlavorPrefix) {
					if err = fcon.addFlavorToIseclSoftwareFlavorgroup(signedFlavorCreated.Flavor, dm.FlavorGroupsPlatformSoftware.String()); err != nil {
						defaultLog.Error("controllers/flavor_controller:addFlavorToFlavorgroup() Unable to add flavor to default platform software flavorgroup")
						return nil, err
					}
				} else if flavorPart == fc.FlavorPartSoftware && strings.Contains(signedFlavorCreated.Flavor.Meta.Description.Label, fConst.DefaultWorkloadFlavorPrefix) {
					if err = fcon.addFlavorToIseclSoftwareFlavorgroup(signedFlavorCreated.Flavor, dm.FlavorGroupsWorkloadSoftware.String()); err != nil {
						defaultLog.Error("controllers/flavor_controller:addFlavorToFlavorgroup() Unable to add flavor to default workload software flavorgroup")
						return nil, err
					}
				} else {
					flavorIds = append(flavorIds, signedFlavorCreated.Flavor.Meta.ID)
				}
			} else {
				defaultLog.Error("controllers/flavor_controller: addFlavorToFlavorgroup(): Unable to create flavors")
				return nil, errors.New("Unable to create flavors")
			}
		}
	}

	if flavorgroupId == uuid.Nil || len(flavorIds) == 0 {
		defaultLog.Info("controllers/flavor_controller: addFlavorToFlavorgroup(): Missing flavorgroupID or flavorId's")
		return returnSignedFlavors, nil
	}

	// for flavorparts PLATFORM and OS, we have to associate it to a particular flavorgroup
	// add falvors to flavorgroup
	if len(flavorIds) >= 1 {
		_, err := fcon.FGStore.AddFlavors(flavorgroupId, flavorIds)
		if err != nil {
			defaultLog.Errorf("controllers/flavor_controller: addFlavorToFlavorgroup(): Error while adding flavors to flavorgroup %s", flavorgroupId.String())
			return nil, err
		}
	}
	// TODO: add host to flavor verify queue
	return returnSignedFlavors, nil
}

func (fcon FlavorController) addFlavorToUniqueFlavorgroup(flavor hvs.Flavor, forceUpdate bool) error {
	defaultLog.Trace("controllers/flavor_controller:addFlavorToUniqueFlavorgroup() Entering")
	defer defaultLog.Trace("controllers/flavor_controller:addFlavorToUniqueFlavorgroup() Leaving")
	var err error
	// check if HOST_UNIQUE flavorgroup exists
	flavorgroup, err := fcon.createFGIfNotExists(dm.FlavorGroupsHostUnique.String())
	if err != nil || flavorgroup.ID == uuid.Nil {
		defaultLog.Error("controllers/flavor_controller:createFlavors() Error getting flavorgroup")
		return err
	}
	// create flavor-flavorgroup link association
	_, err = fcon.FGStore.AddFlavors(flavorgroup.ID, []uuid.UUID{flavor.Meta.ID})
	if err != nil {
		defaultLog.Errorf("controllers/flavor_controller: addFlavorToUniqueFlavorgroup(): Error while adding flavors to flavorgroup %s", flavorgroup.ID.String())
		return err
	}
	// retrive hostID and host hardwareUUID and host to flavor verify queue
	var hostName string
	var hostHardwareUUID uuid.UUID

	if !reflect.DeepEqual(flavor.Meta, fm.Meta{}) && !reflect.DeepEqual(flavor.Meta.Description, fm.Description{}) && flavor.Meta.Description.Label != "" {
		hostName = flavor.Meta.Description.Label
	}

	if !reflect.DeepEqual(flavor.Meta, fm.Meta{}) && !reflect.DeepEqual(flavor.Meta.Description, fm.Description{}) && flavor.Meta.Description.HardwareUUID != &uuid.Nil {
		hostHardwareUUID = *flavor.Meta.Description.HardwareUUID
	}

	if hostName == "" && hostHardwareUUID == uuid.Nil {
		defaultLog.Error("controllers/flavor_controller:addFlavorToUniqueFlavorgroup() Host name or hardware UUID must be specified in the flavor document")
		return errors.New("Host name or hardware UUID must be specified in the HOST_UNIQUE flavor")
	}

	hosts, err := fcon.HStore.Search(&dm.HostFilterCriteria{
		HostHardwareId: hostHardwareUUID,
		NameEqualTo:    hostName,
	})
	if len(hosts) == 0 && err != nil {
		defaultLog.Infof("controllers/flavor_controller: addFlavorToUniqueFlavorgroup(): Host with matching name and hardware UUID not registered")
		return nil
	}
	// TODO: add host to flavor-verify queue
	return nil
}

func (fcon FlavorController) addFlavorToIseclSoftwareFlavorgroup(flavor hvs.Flavor, softwareFgName string) error {
	defaultLog.Trace("controllers/flavor_controller:addFlavorToIseclSoftwareFlavorgroup() Entering")
	defer defaultLog.Trace("controllers/flavor_controller:addFlavorToIseclSoftwareFlavorgroup() Leaving")
	var err error
	// check if platform_software or workload_software flavorgroup exists, if not create a new one
	flavorgroup, err := fcon.createFGIfNotExists(softwareFgName)
	if err != nil || flavorgroup.ID == uuid.Nil {
		defaultLog.Error("controllers/flavor_controller:addFlavorToIseclSoftwareFlavorgroup() Error getting flavorgroup")
		return err
	}
	_, err = fcon.FGStore.AddFlavors(flavorgroup.ID, []uuid.UUID{flavor.Meta.ID})
	if err != nil {
		defaultLog.Errorf("controllers/flavor_controller: addFlavorToIseclSoftwareFlavorgroup(): Error while adding flavors to flavorgroup %s", flavorgroup.ID.String())
		return err
	}
	// TODO: add all hosts belonging to the flavorgroup to flavor-verify queue
	return nil
}

func (fcon FlavorController) retrieveFlavorCollection(platformFlavor *fType.PlatformFlavor, fgId uuid.UUID, flavorParts []fc.FlavorPart) map[fc.FlavorPart][]hvs.SignedFlavor {
	defaultLog.Trace("controllers/flavor_controller:retrieveFlavorCollection() Entering")
	defer defaultLog.Trace("controllers/flavor_controller:retrieveFlavorCollection() Leaving")
	flavorFlavorPartMap := make(map[fc.FlavorPart][]hvs.SignedFlavor)
	var flavorSignKey = (*fcon.CertStore)[dm.CertTypesFlavorSigning.String()].Key

	if fgId.String() == "" || platformFlavor == nil {
		defaultLog.Error("controllers/flavor_controller:retrieveFlavorCollection() Platform flavor and flavorgroup must be specified")
		return flavorFlavorPartMap
	}

	if len(flavorParts) == 0 {
		flavorParts = append(flavorParts, fc.FlavorPartSoftware)
	}

	for _, flavorPart := range flavorParts {
		signedFlavors, err := (*platformFlavor).GetFlavorPart(flavorPart, flavorSignKey.(*rsa.PrivateKey))
		if err != nil {
			defaultLog.Errorf("controllers/flavor_controller:retrieveFlavorCollection() Error building a flavor for flavor part %s", flavorPart)
			return flavorFlavorPartMap
		}
		for _, signedFlavor := range signedFlavors {
			if _, ok := flavorFlavorPartMap[flavorPart]; ok {
				flavorFlavorPartMap[flavorPart] = append(flavorFlavorPartMap[flavorPart], signedFlavor)
			} else {
				flavorFlavorPartMap[flavorPart] = []hvs.SignedFlavor{signedFlavor}
			}
		}
	}
	return flavorFlavorPartMap
}

func (fcon *FlavorController) Search(w http.ResponseWriter, r *http.Request) (interface{}, int, error) {
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
		var flavorPartsFilter []fc.FlavorPart
		var err error
		fId, _ := uuid.Parse(id)
		fgId, _ := uuid.Parse(flavorgroupId)
		if len(flavorParts) > 0 {
			flavorPartsFilter, err = parseFlavorParts(flavorParts)
			if err != nil {
				secLog.Errorf("controllers/flavor_controller:Search()  %s", err.Error())
				return nil, http.StatusBadRequest, &commErr.ResourceError{Message: err.Error()}
			}
		}
		filterCriteria = &dm.FlavorFilterCriteria{
			Id:            fId,
			Key:           key,
			Value:         value,
			FlavorGroupID: fgId,
			FlavorParts:   flavorPartsFilter,
		}
		if err := validateFlavorFilterCriteria(*filterCriteria); err != nil {
			secLog.Errorf("controllers/flavor_controller:Search()  %s", err.Error())
			return nil, http.StatusBadRequest, &commErr.ResourceError{Message: err.Error()}
		}
	}

	flavorCollection, err := fcon.FStore.Search(filterCriteria)
	if err != nil {
		secLog.WithError(err).Error("controllers/flavor_controller:Search() Flavor get all failed")
		return nil, http.StatusInternalServerError, errors.Errorf("Unable to search Flavors")
	}

	secLog.Infof("%s: Return flavor query to: %s", commLogMsg.AuthorizedAccess, r.RemoteAddr)
	return flavorCollection, http.StatusOK, nil
}

func (fcon *FlavorController) Delete(w http.ResponseWriter, r *http.Request) (interface{}, int, error) {
	defaultLog.Trace("controllers/flavor_controller:Delete() Entering")
	defer defaultLog.Trace("controllers/flavor_controller:Delete() Leaving")

	id, _ := uuid.Parse(mux.Vars(r)["id"])
	_, err := fcon.FStore.Retrieve(id)
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
	if err := fcon.FStore.Delete(id); err != nil {
		defaultLog.WithError(err).WithField("id", id).Info(
			"controllers/flavor_controller:Delete() failed to delete Flavor")
		return nil, http.StatusInternalServerError, &commErr.ResourceError{Message: "Failed to delete Flavor"}
	}
	return nil, http.StatusNoContent, nil
}

func (fcon *FlavorController) Retrieve(w http.ResponseWriter, r *http.Request) (interface{}, int, error) {
	defaultLog.Trace("controllers/flavor_controller:Retrieve() Entering")
	defer defaultLog.Trace("controllers/flavor_controller:Retrieve() Leaving")

	id, _ := uuid.Parse(mux.Vars(r)["id"])
	flavor, err := fcon.FStore.Retrieve(id)
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

func validateFlavorFilterCriteria(filter dm.FlavorFilterCriteria) error {
	defaultLog.Trace("controllers/flavor_controller:validateFlavorFilterCriteria() Entering")
	defer defaultLog.Trace("controllers/flavor_controller:validateFlavorFilterCriteria() Leaving")

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

	return nil
}

func validateFlavorCreateRequest(criteria dm.FlavorCreateRequest) error {
	defaultLog.Trace("controllers/flavor_controller:validateFlavorCreateRequest() Entering")
	defer defaultLog.Trace("controllers/flavor_controller:validateFlavorCreateRequest() Leaving")

	if criteria.ConnectionString == "" && len(criteria.FlavorCollection) == 0 && len(criteria.SignedFlavorCollection) == 0 {
		secLog.Error("controllers/flavor_controller: validateFlavorCreateCriteria() Valid host connection string or flavor content must be given")
		return errors.New("Valid host connection string or flavor content must be given")
	}
	if criteria.ConnectionString != "" {
		err := utils.ValidateConnectionString(criteria.ConnectionString)
		if err != nil {
			secLog.Error("controllers/flavor_controller: validateFlavorCreateCriteria() Invalid host connection string")
			return errors.New("Invalid host connection string")
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

func validateFlavorMetaContent(meta *fm.Meta) error {
	defaultLog.Trace("controllers/flavor_controller:validateFlavorMetaContent() Entering")
	defer defaultLog.Trace("controllers/flavor_controller:validateFlavorMetaContent() Leaving")
	if meta == nil || reflect.DeepEqual(meta.Description, fm.Description{}) || meta.Description.Label == "" {
		return errors.New("Invalid flavor meta content : flavor label missing")
	}
	var fp fc.FlavorPart
	if err := (&fp).Parse(meta.Description.FlavorPart); err != nil {
		return errors.New("Flavor Part must be ASSET_TAG, SOFTWARE, HOST_UNIQUE, PLATFORM or OS")
	}
	return nil
}

func parseFlavorParts(flavorParts []string) ([]fc.FlavorPart, error) {
	defaultLog.Trace("controllers/flavor_controller:parseFlavorParts() Entering")
	defer defaultLog.Trace("controllers/flavor_controller:parseFlavorParts() Leaving")
	// validate if the given flavor parts are valid and convert it to FlavorPart type
	var validFlavorParts []fc.FlavorPart
	for _, flavorPart := range flavorParts {
		var fp fc.FlavorPart
		if err := (&fp).Parse(flavorPart); err != nil {
			return nil, errors.New("Valid FlavorPart as a filter must be specified")
		}
		validFlavorParts = append(validFlavorParts, fp)
	}
	return validFlavorParts, nil
}

func (fcon *FlavorController) createFGIfNotExists(fgName string) (*hvs.FlavorGroup, error) {
	defaultLog.Trace("controllers/flavor_controller:createFGIfNotExists() Entering")
	defer defaultLog.Trace("controllers/flavor_controller:createFGIfNotExists() Leaving")

	if fgName == "" {
		defaultLog.Errorf("controllers/flavor_controller:createFGIfNotExists() Flavorgroup name cannot be nil")
		return nil, errors.New("Flavorgroup name cannot be nil")
	}

	flavorgroupExists, err := fcon.FGStore.Search(&dm.FlavorGroupFilterCriteria{
		NameEqualTo: fgName,
	})
	if err != nil {
		defaultLog.Errorf("controllers/flavor_controller:createFGIfNotExists() Error searching for flavorgroup with name %s", fgName)
		return nil, errors.Wrapf(err, "Error searching for flavorgroup with name %s", fgName)
	}

	if flavorgroupExists != nil && len(flavorgroupExists.Flavorgroups) >= 1 && flavorgroupExists.Flavorgroups[0].ID != uuid.Nil {
		return flavorgroupExists.Flavorgroups[0], nil
	}
	// if flavorgroup of the given name doesn't exist, create a new one
	var fg hvs.FlavorGroup
	var policies []hvs.FlavorMatchPolicy
	if fgName == dm.FlavorGroupsWorkloadSoftware.String() || fgName == dm.FlavorGroupsPlatformSoftware.String() {
		policies = append(policies, hvs.NewFlavorMatchPolicy(fc.FlavorPartSoftware, hvs.NewMatchPolicy(hvs.MatchTypeAnyOf, hvs.FlavorRequired)))
		fg = hvs.FlavorGroup{
			Name:          fgName,
			MatchPolicies: policies,
		}
	} else if fgName == dm.FlavorGroupsHostUnique.String() {
		fg = hvs.FlavorGroup{
			Name: fgName,
		}
	} else {
		fg = utils.CreateFlavorGroupByName(fgName)
	}

	flavorgroup, err := fcon.FGStore.Create(&fg)
	if err != nil {
		defaultLog.Errorf("controllers/flavor_controller:createFGIfNotExists() Flavor creation failed while creating flavorgroup"+
			"with name %s", fgName)
		return nil, errors.Wrap(err, "Unable to create flavorgroup")
	}
	return flavorgroup, nil
}
