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
	"net/url"
	"strconv"
	"strings"
)

type TpmEndorsementController struct {
	Store domain.TpmEndorsementStore
}

func (controller TpmEndorsementController) Create(w http.ResponseWriter, r *http.Request) (interface{}, int, error) {
	defaultLog.Trace("controllers/tpm_endorsement_controller:Create() Entering")
	defer defaultLog.Trace("controllers/tpm_endorsement_controller:Create() Leaving")

	if r.ContentLength == 0 {
		secLog.Error("controllers/tpm_endorsement_controller:Create() The request body is not provided")
		return nil, http.StatusBadRequest, &commErr.ResourceError{Message:"The request body is not provided"}
	}

	var reqTpmEndorsement hvs.TpmEndorsement
	// Decode the incoming json data to note struct
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()

	err := dec.Decode(&reqTpmEndorsement)
	if err != nil {
		secLog.WithError(err).Errorf("controllers/tpm_endorsement_controller:Create() %s :  Failed to decode request body as TpmEndorsement", commLogMsg.AppRuntimeErr)
		return nil, http.StatusBadRequest, &commErr.ResourceError{Message: "Unable to decode JSON request body"}
	}

	if err := validateTpmEndorsement(reqTpmEndorsement); err != nil {
		secLog.Errorf("controllers/tpm_endorsement_controller:Create()  %s", err.Error())
		return nil, http.StatusBadRequest, &commErr.ResourceError{Message: "Invalid input provided in request"}
	}

	existingTpmEndorsement, err := controller.Store.Search(&models.TpmEndorsementFilterCriteria{
		HardwareUuidEqualTo: reqTpmEndorsement.HardwareUUID.String(),
	})
	if existingTpmEndorsement != nil && len(existingTpmEndorsement.TpmEndorsement) > 0 {
		secLog.WithField("HardwareUUID", existingTpmEndorsement.TpmEndorsement[0].HardwareUUID).Warningf("%s: Trying to create duplicated TpmEndorsment from addr: %s", commLogMsg.InvalidInputBadParam, r.RemoteAddr)
		return nil, http.StatusBadRequest, &commErr.ResourceError{Message:"TpmEndorsement with same hardware_uuid already exist."}
	}

	// Persistence
	newTpmEndorsement, err := controller.Store.Create(&reqTpmEndorsement)
	if err != nil {
		secLog.WithError(err).Error("controllers/tpm_endorsement_controller:Create() TpmEndorsement create failed")
		return nil, http.StatusInternalServerError, &commErr.ResourceError{Message: "Error on inserting TpmEndorsement"}
	}
	secLog.WithField("HardwareUUID", reqTpmEndorsement.HardwareUUID).Infof("%s: TpmEndorsement created by: %s", commLogMsg.PrivilegeModified, r.RemoteAddr)
	return newTpmEndorsement, http.StatusCreated, nil
}

func (controller TpmEndorsementController) Update(w http.ResponseWriter, r *http.Request) (interface{}, int, error) {
	defaultLog.Trace("controllers/tpm_endorsement_controller:Update() Entering")
	defer defaultLog.Trace("controllers/tpm_endorsement_controller:Update() Leaving")

	if r.ContentLength == 0 {
		secLog.Error("controllers/tpm_endorsement_controller:Update() The request body is not provided")
		return nil, http.StatusBadRequest, &commErr.ResourceError{Message:"The request body is not provided"}
	}
	id := uuid.MustParse(mux.Vars(r)["id"])

	var reqTpmEndorsement hvs.TpmEndorsement
	// Decode the incoming json data to note struct
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()

	err := dec.Decode(&reqTpmEndorsement)
	if err != nil {
		secLog.WithError(err).Errorf("controllers/tpm_endorsement_controller:Update() %s :  Failed to decode request body as TpmEndorsement", commLogMsg.AppRuntimeErr)
		return nil, http.StatusBadRequest, &commErr.ResourceError{Message: "Unable to decode JSON request body"}
	}

	if err := validateTpmEndorsement(reqTpmEndorsement); err != nil {
		secLog.Errorf("controllers/tpm_endorsement_controller:Update()  %s", err.Error())
		return nil, http.StatusBadRequest, &commErr.ResourceError{Message: "Invalid input provided in request"}
	}

	tpmEndorsement, err := controller.Store.Retrieve(id)
	if err != nil {
		if strings.Contains(err.Error(), commErr.RowsNotFound) {
			secLog.WithError(err).WithField("id", reqTpmEndorsement.ID).Error(
				"controllers/tpm_endorsement_controller:Update() TpmEndorsement with given ID does not exist")
			return nil, http.StatusNotFound, &commErr.ResourceError{Message:"TpmEndorsement with given ID does not exist"}
		} else {
			secLog.WithError(err).WithField("id", reqTpmEndorsement.ID).Error(
				"controllers/tpm_endorsement_controller:Update() attempt to update invalid TpmEndorsement")
			return nil, http.StatusInternalServerError, &commErr.ResourceError{Message: "Failed to update TpmEndorsement"}
		}
	}

	if reqTpmEndorsement.Issuer != ""{
		tpmEndorsement.Issuer = reqTpmEndorsement.Issuer
	}

	if reqTpmEndorsement.HardwareUUID != uuid.Nil {
		tpmEndorsement.HardwareUUID = reqTpmEndorsement.HardwareUUID
	}

	if reqTpmEndorsement.Certificate != ""{
		tpmEndorsement.Certificate = reqTpmEndorsement.Certificate
	}

	if reqTpmEndorsement.Comment != ""{
		tpmEndorsement.Comment = reqTpmEndorsement.Comment
	}

	if tpmEndorsement.Revoked != reqTpmEndorsement.Revoked{
		tpmEndorsement.Revoked = reqTpmEndorsement.Revoked
	}
	// Persistence
	newTpmEndorsement, err := controller.Store.Update(tpmEndorsement)
	if err != nil {
		secLog.WithError(err).Error("controllers/tpm_endorsement_controller:Update() TpmEndorsement update failed")
		return nil, http.StatusInternalServerError, &commErr.ResourceError{Message: "Error on Saving TpmEndorsement"}
	}
	secLog.WithField("HardwareUUID", reqTpmEndorsement.HardwareUUID).Infof("%s: TpmEndorsement updated by: %s", commLogMsg.PrivilegeModified, r.RemoteAddr)
	return newTpmEndorsement, http.StatusOK, nil
}

func (controller TpmEndorsementController) Search(w http.ResponseWriter, r *http.Request) (interface{}, int, error) {
	defaultLog.Trace("controllers/tpm_endorsement_controller:Search() Entering")
	defer defaultLog.Trace("controllers/tpm_endorsement_controller:Search() Leaving")

	// check for query parameters
	defaultLog.WithField("query", r.URL.Query()).Trace("query tpmendorsements")
	filter, err := getAndValidateFilterCriteria(r.URL.Query())
	if err != nil{
		secLog.WithError(err).Error("controllers/tpm_endorsement_controller:Search() Invalid input provided in filter criteria")
		return nil, http.StatusBadRequest, &commErr.ResourceError{Message: "Invalid input provided in filter criteria"}
	}
	tpmEndorsementCollection, err := controller.Store.Search(filter)
	if err != nil {
		secLog.WithError(err).Error("controllers/tpm_endorsement_controller:Search() TpmEndorsement get all failed")
		return nil, http.StatusInternalServerError, &commErr.ResourceError{Message: "Unable to search TpmEndorsement"}
	}

	secLog.Infof("%s: Return tpm-endorsement query to: %s", commLogMsg.AuthorizedAccess, r.RemoteAddr)
	return tpmEndorsementCollection, http.StatusOK, nil
}

func (controller TpmEndorsementController) Delete(w http.ResponseWriter, r *http.Request) (interface{}, int, error) {
	defaultLog.Trace("controllers/tpm_endorsement_controller:Delete() Entering")
	defer defaultLog.Trace("controllers/tpm_endorsement_controller:Delete() Leaving")

	id := uuid.MustParse(mux.Vars(r)["id"])

	delTpmEndorsement, err := controller.Store.Retrieve(id)
	if err != nil {
		if strings.Contains(err.Error(), commErr.RowsNotFound) {
			secLog.WithError(err).WithField("id", id).Error(
				"controllers/tpm_endorsement_controller:Delete()  TpmEndorsement with given ID does not exist")
			return nil, http.StatusNotFound, &commErr.ResourceError{Message:"TpmEndorsement with given ID does not exist"}
		} else {
			secLog.WithError(err).WithField("id", id).Error(
				"controllers/tpm_endorsement_controller:Delete() attempt to delete invalid TpmEndorsement")
			return nil, http.StatusInternalServerError, &commErr.ResourceError{Message: "Failed to delete TpmEndorsement"}
		}
	}

	if err := controller.Store.Delete(id); err != nil {
		defaultLog.WithError(err).WithField("id", id).Error(
			"controllers/tpm_endorsement_controller:Delete() failed to delete TpmEndorsement")
		return nil, http.StatusInternalServerError, &commErr.ResourceError{Message:"Failed to delete TpmEndorsement"}
	}
	secLog.WithField("ID", delTpmEndorsement.ID).Infof("TpmEndorsement deleted by: %s", r.RemoteAddr)
	return nil, http.StatusNoContent, nil
}

func (controller TpmEndorsementController) Retrieve(w http.ResponseWriter, r *http.Request) (interface{}, int, error) {
	defaultLog.Trace("controllers/tpm_endorsement_controller:Retrieve() Entering")
	defer defaultLog.Trace("controllers/tpm_endorsement_controller:Retrieve() Leaving")

	id := uuid.MustParse(mux.Vars(r)["id"])

	tpmEndorsement, err := controller.Store.Retrieve(id)
	if err != nil {
		if strings.Contains(err.Error(), commErr.RowsNotFound) {
			secLog.WithError(err).WithField("id", id).Error(
				"controllers/tpm_endorsement_controller:Retrieve() TpmEndorsement with given ID does not exist")
			return nil, http.StatusNotFound, &commErr.ResourceError{Message:"TpmEndorsement with given ID does not exist"}
		} else {
			secLog.WithError(err).WithField("id", id).Error(
				"controllers/tpm_endorsement_controller:Retrieve() failed to retrieve TpmEndorsement")
			return nil, http.StatusInternalServerError, &commErr.ResourceError{Message: "Failed to retrieve TpmEndorsement"}
		}
	}

	secLog.WithField("ID", tpmEndorsement.ID).Infof("TpmEndorsement retrieved by: %s", r.RemoteAddr)
	return tpmEndorsement, http.StatusOK, nil
}

func (controller TpmEndorsementController) DeleteCollection(w http.ResponseWriter, r *http.Request) (interface{}, int, error) {
	defaultLog.Trace("controllers/tpm_endorsement_controller:DeleteCollection() Entering")
	defer defaultLog.Trace("controllers/tpm_endorsement_controller:DeleteCollection() Leaving")

	// check for query parameters
	defaultLog.WithField("query", r.URL.Query()).Trace("query tpmendorsements")

	filter, err := getAndValidateFilterCriteria(r.URL.Query())
	if err != nil{
		secLog.WithError(err).Error("controllers/tpm_endorsement_controller:DeleteCollection() Invalid input provided in filter criteria")
		return nil, http.StatusBadRequest, &commErr.ResourceError{Message: "Invalid input provided in filter criteria"}
	}

	tpmEndorsements, err := controller.Store.Search(filter)
	if err != nil {
		secLog.WithError(err).Error("controllers/tpm_endorsement_controller:DeleteCollection() failed to search TpmEndorsements for given criteria")
		return nil, http.StatusInternalServerError, &commErr.ResourceError{Message: "Failed to search TpmEndorsements for given criteria"}
	}

	if len(tpmEndorsements.TpmEndorsement) == 0{
		return nil, http.StatusNoContent, nil
	}

	for _, te := range tpmEndorsements.TpmEndorsement{
		err := controller.Store.Delete(te.ID)
		if err != nil{
			defaultLog.WithError(err).Errorf("Failed to delete TpmEndorsements for ID %s", te.ID.String())
			return nil, http.StatusInternalServerError, &commErr.ResourceError{Message: "Failed to delete TpmEndorsements for given criteria"}
		}
	}
	secLog.Infof("TpmEndorsements deleted by: %s", r.RemoteAddr)
	return nil, http.StatusNoContent, nil
}

func getAndValidateFilterCriteria(query url.Values) (*models.TpmEndorsementFilterCriteria, error) {
	defaultLog.Trace("controllers/tpm_endorsement_controller:getAndValidateFilterCriteria() Entering")
	defer defaultLog.Trace("controllers/tpm_endorsement_controller:getAndValidateFilterCriteria() Leaving")

	id := query.Get("id")
	hardwareUuidEqualTo := query.Get("hardwareUuidEqualTo")
	issuerEqualTo := query.Get("issuerEqualTo")
	revokedEqualTo := query.Get("revokedEqualTo")
	issuerContains := query.Get("issuerContains")
	commentEqualTo := query.Get("commentEqualTo")
	commentContains := query.Get("commentContains")

	var filter *models.TpmEndorsementFilterCriteria
	if id != "" || hardwareUuidEqualTo != "" || issuerEqualTo != "" || revokedEqualTo != "" || issuerContains != "" || commentEqualTo != "" || commentContains != "" {
		filter = &models.TpmEndorsementFilterCriteria{
			Id:                  id,
			HardwareUuidEqualTo: hardwareUuidEqualTo,
			IssuerEqualTo:       issuerEqualTo,
			RevokedEqualTo:      revokedEqualTo,
			CommentEqualTo:      commentEqualTo,
			CommentContains:     commentContains,
			IssuerContains:      issuerContains,
		}
		if err := validateTpmEndorsementFilterCriteria(*filter); err != nil {
			return nil, errors.Wrap(err,"Valid contents should be provided for filter criteria")
		}
	}
	return filter, nil
}


func validateTpmEndorsement(reqTpmEndorsement hvs.TpmEndorsement) error{
	defaultLog.Trace("controllers/tpm_endorsement_controller:validateTpmEndorsement() Entering")
	defer defaultLog.Trace("controllers/tpm_endorsement_controller:validateTpmEndorsement() Leaving")

	if reqTpmEndorsement.HardwareUUID == uuid.Nil || reqTpmEndorsement.Certificate == "" || reqTpmEndorsement.Issuer == "" {
		defaultLog.Error("controllers/tpm_endorsement_controller:validateTpmEndorsement()  hardware_uuid, certificate and issuer must be specified")
		return errors.New("hardware_uuid, certificate and issuer must be specified")
	}

	if err := validation.ValidateBase64String(reqTpmEndorsement.Certificate); err != nil {
		return errors.Wrap(err, "Valid contents for Certificate must be specified")
	}

	if err := validation.ValidateIssuer(reqTpmEndorsement.Issuer); err != nil {
		return errors.Wrap(err, "Valid contents for Issuer must be specified")
	}

	if reqTpmEndorsement.Comment != ""{
		if errs := validation.ValidateStrings(strings.Split(reqTpmEndorsement.Comment, " ")); errs != nil {
			return errors.Wrap(errs, "Valid contents for Comment must be specified")
		}
	}

	return nil
}

func validateTpmEndorsementFilterCriteria(reqTpmEndorsement models.TpmEndorsementFilterCriteria) error{
	defaultLog.Trace("controllers/tpm_endorsement_controller:validateTpmEndorsementFilterCriteria() Entering")
	defer defaultLog.Trace("controllers/tpm_endorsement_controller:validateTpmEndorsementFilterCriteria() Leaving")

	if reqTpmEndorsement.IssuerContains != ""{
		if errs := validation.ValidateIssuer(reqTpmEndorsement.IssuerContains); errs != nil {
			return errors.Wrap(errs, "Valid contents for IssuerContains must be specified")
		}
	}
	if reqTpmEndorsement.IssuerEqualTo != ""{
		if errs := validation.ValidateIssuer(reqTpmEndorsement.IssuerEqualTo); errs != nil {
			return errors.Wrap(errs, "Valid contents for IssuerEqualTo must be specified")
		}
	}
	if reqTpmEndorsement.CommentContains != ""{
		if errs := validation.ValidateStrings(strings.Split(reqTpmEndorsement.CommentContains, " ")); errs != nil {
			return errors.Wrap(errs, "Valid contents for CommentContains must be specified")
		}
	}
	if reqTpmEndorsement.CommentEqualTo != ""{
		if errs := validation.ValidateStrings(strings.Split(reqTpmEndorsement.CommentEqualTo, " ")); errs != nil {
			return errors.Wrap(errs, "Valid contents for CommentEqualTo must be specified")
		}
	}
	if reqTpmEndorsement.RevokedEqualTo != ""{
		if _, errs := strconv.ParseBool(reqTpmEndorsement.RevokedEqualTo); errs != nil {
			return errors.Wrap(errs, "Valid contents for RevokedEqualTo must be specified")
		}
	}
	if reqTpmEndorsement.Id != ""{
		if _, errs := uuid.Parse(reqTpmEndorsement.Id); errs != nil {
			return errors.New("Invalid UUID format of the TpmEndorsement Identifier")
		}
	}
	if reqTpmEndorsement.HardwareUuidEqualTo != ""{
		if errs := validation.ValidateHardwareUUID(reqTpmEndorsement.HardwareUuidEqualTo); errs != nil {
			return errors.New("Invalid UUID format of the HardwareUuidEqualTo Identifier")
		}
	}
	return nil
}