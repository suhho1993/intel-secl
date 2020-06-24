/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package controllers

import (
	"crypto/x509"
	"encoding/json"
	"github.com/google/uuid"
	"github.com/gorilla/mux"
	"github.com/intel-secl/intel-secl/v3/pkg/hvs/constants"
	"github.com/intel-secl/intel-secl/v3/pkg/hvs/domain"
	"github.com/intel-secl/intel-secl/v3/pkg/hvs/domain/models"
	asset_tag "github.com/intel-secl/intel-secl/v3/pkg/lib/asset-tag"
	commErr "github.com/intel-secl/intel-secl/v3/pkg/lib/common/err"
	commLogMsg "github.com/intel-secl/intel-secl/v3/pkg/lib/common/log/message"
	"github.com/intel-secl/intel-secl/v3/pkg/lib/common/validation"
	"github.com/intel-secl/intel-secl/v3/pkg/lib/flavor/model"
	"github.com/intel-secl/intel-secl/v3/pkg/model/hvs"
	"github.com/pkg/errors"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"
)

// TagCertificateController contains logic for handling TagCertificate API requests
type TagCertificateController struct {
	// CertStore is required to source the Asset Tag Signing Key and Certificates
	CertStore *models.CertificateStore
	// Store is used to hold a reference to the backend store for the TagCertificates
	Store domain.TagCertificateStore
}

func NewTagCertificateController(certStore *models.CertificatesStore, store domain.TagCertificateStore) *TagCertificateController {

	// certStore should not be nil
	if certStore == nil {
		defaultLog.Errorf("controllers/tagcertificates_controller:NewTagCertificateController() %s : CertStore is not set", commLogMsg.AppRuntimeErr)
		return nil
	}

	// certStore should have an entry for Tag CA Cert
	if _, found := (*certStore)[models.CaCertTypesTagCa.String()]; !found {
		defaultLog.Errorf("controllers/tagcertificates_controller:NewTagCertificateController() %s : Tag Certificate KeyPair not found in CertStore", commLogMsg.AppRuntimeErr)
		return nil
	}

	// Tag CA cert entry should have certificates
	var tagCACert *x509.Certificate
	for _, cert := range (*certStore)[models.CaCertTypesTagCa.String()].Certificates {
		tagCACert = &cert
	}

	if tagCACert == nil {
		defaultLog.Errorf("controllers/tagcertificates_controller:NewTagCertificateController() %s : Tag CA Certificate not found in CertStore", commLogMsg.AppRuntimeErr)
		return nil
	}

	return &TagCertificateController{
		CertStore: (*certStore)[models.CaCertTypesTagCa.String()],
		Store:     store,
	}
}

// Create creates a new TagCertificate x509.Certificate entry into the database
// that can be used to provision an AssetTag on a desired host.
func (controller TagCertificateController) Create(w http.ResponseWriter, r *http.Request) (interface{}, int, error) {
	defaultLog.Trace("controllers/tagcertificate_controller:Create() Entering")
	defer defaultLog.Trace("controllers/tagcertificate_controller:Create() Leaving")

	if r.ContentLength == 0 {
		secLog.Warnf("controllers/tagcertificate_controller:Create() %s : The request body is not provided", commLogMsg.InvalidInputBadParam)
		return nil, http.StatusBadRequest, &commErr.ResourceError{Message: "The request body is not provided"}
	}

	var reqTCCriteria models.TagCertificateCreateCriteria

	// Decode incoming json data
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()

	err := dec.Decode(&reqTCCriteria)
	if err != nil {
		defaultLog.WithError(err).Warnf("controllers/tagcertificate_controller:Create() %s : Failed to decode request body as TagCertificateCreateCriteria", commLogMsg.InvalidInputBadParam)
		return nil, http.StatusBadRequest, &commErr.ResourceError{Message: "Unable to decode JSON request body"}
	}

	// validate Tag Certificate creation params
	if err := validateTagCertCreateCriteria(reqTCCriteria); err != nil {
		secLog.Warnf("controllers/tagcertificate_controller:Create() %s : Error during Tag Certificate creation: %s", commLogMsg.InvalidInputBadParam, err.Error())
		return nil, http.StatusBadRequest, &commErr.ResourceError{Message: err.Error()}
	}

	// get the Tag CA Cert from the certstore
	var tagCACert *x509.Certificate
	for _, cert := range controller.CertStore.Certificates {
		tagCACert = &cert
	}

	if tagCACert == nil {
		defaultLog.WithError(err).Warnf("controllers/tagcertificate_controller:Create() %s : Failed to source Tag CA Certificiate from CertStore", commLogMsg.AppRuntimeErr)
		return nil, http.StatusInternalServerError, &commErr.ResourceError{Message: "Tag Certificate Creation failure"}
	}

	// Initialize the TagCertConfig
	newTCConfig := asset_tag.TagCertConfig{
		SubjectUUID:       reqTCCriteria.HardwareUUID.String(),
		PrivateKey:        *controller.CertStore.Key,
		TagCACert:         tagCACert,
		TagAttributes:     reqTCCriteria.SelectionContent,
		ValidityInSeconds: constants.DefaultTagCertValiditySeconds,
	}

	// build the x509.Certificate
	atCreator := asset_tag.NewAssetTag()
	newTCBytes, err := atCreator.CreateAssetTag(newTCConfig)
	if err != nil {
		defaultLog.Warnf("controllers/tagcertificate_controller:Create() %s : Error during Tag Certificate creation: %s", commLogMsg.AppRuntimeErr, err.Error())
		return nil, http.StatusInternalServerError, &commErr.ResourceError{Message: "Tag Certificate Creation failure"}
	}

	newX509TC, err := x509.ParseCertificate(newTCBytes)
	if err != nil {
		defaultLog.Warnf("controllers/tagcertificate_controller:Create() %s : Error during Tag Certificate creation: %s", commLogMsg.AppRuntimeErr, err.Error())
		return nil, http.StatusInternalServerError, &commErr.ResourceError{Message: "Tag Certificate Creation failure"}
	}

	// put this in an X509AttributeCert to extract the properties easily
	tempX509AttrCert, err := model.NewX509AttributeCertificate(newX509TC)
	if err != nil {
		defaultLog.Warnf("controllers/tagcertificate_controller:Create() %s : Error during Tag Certificate creation: %s", commLogMsg.AppRuntimeErr, err.Error())
		return nil, http.StatusInternalServerError, &commErr.ResourceError{Message: "Tag Certificate Creation failure"}
	}

	// convert to a TagCertificate
	newTagCert := hvs.TagCertificate{
		Certificate:  newTCBytes,
		Subject:      tempX509AttrCert.Subject,
		Issuer:       tempX509AttrCert.Issuer,
		NotBefore:    newX509TC.NotBefore,
		NotAfter:     newX509TC.NotAfter,
		HardwareUUID: reqTCCriteria.HardwareUUID,
	}

	// persist to DB
	newTC, err := controller.Store.Create(&newTagCert)
	if err != nil {
		defaultLog.WithError(err).Warnf("controllers/tagcertificate_controller:Create() %s : TagCertificate Creation failed", commLogMsg.AppRuntimeErr)
		return nil, http.StatusInternalServerError, errors.Errorf("Error while persisting TagCertificate to DB")
	}
	secLog.WithField("Name", newTC.Subject).Infof("%s: TagCertificate created by: %s", commLogMsg.PrivilegeModified, r.RemoteAddr)
	return newTC, http.StatusCreated, nil
}

// Search returns a collection of TagCertificates based on TagCertificateFilterCriteria
func (controller TagCertificateController) Search(w http.ResponseWriter, r *http.Request) (interface{}, int, error) {
	defaultLog.Trace("controllers/tagcertificate_controller:Search() Entering")
	defer defaultLog.Trace("controllers/tagcertificate_controller:Search() Leaving")

	// get the TagCertificateFilterCriteria
	filter, err := getTCFilterCriteria(r.URL.Query())
	if err != nil {
		defaultLog.Warnf("controllers/tagcertificate_controller:Search() %s : %s", commLogMsg.InvalidInputBadParam, err.Error())
		return nil, http.StatusBadRequest, &commErr.ResourceError{Message: err.Error()}
	}
	/*
		for rows.Next() {
				hvsTC := hvs.TagCertificate{}
				if err := rows.Scan(&hvsTC.ID, &hvsTC.HardwareUUID, &hvsTC.Certificate, &hvsTC.Subject, &hvsTC.Issuer, &hvsTC.NotBefore, &hvsTC.NotAfter); err != nil {
					return nil, errors.Wrap(err, "postgres/tagcertificate_store:Search() failed to scan record")
				}
				tagCertCollection.TagCertificates = append(tagCertCollection.TagCertificates, &hvsTC)
			}
	*/

	tagCertResultSet, err := controller.Store.Search(filter)
	if err != nil {
		defaultLog.WithError(err).Errorf("controllers/tagcertificate_controller:Search() %s : TagCertificate search operation failed", commLogMsg.AppRuntimeErr)
		return nil, http.StatusInternalServerError, errors.Errorf("TagCertificate search operation failed")
	}

	tagCertCollection := hvs.TagCertificateCollection{TagCertificates: tagCertResultSet}

	secLog.Infof("%s: Return TagCertificate Search query to: %s", commLogMsg.AuthorizedAccess, r.RemoteAddr)
	return tagCertCollection, http.StatusOK, nil
}

// Delete deletes an existing TagCertificate from the backend by its unique ID
func (controller TagCertificateController) Delete(w http.ResponseWriter, r *http.Request) (interface{}, int, error) {
	defaultLog.Trace("controllers/tagcertificate_controller:Delete() Entering")
	defer defaultLog.Trace("controllers/tagcertificate_controller:Delete() Leaving")

	id, _ := uuid.Parse(mux.Vars(r)["id"])

	delTagCert, err := controller.Store.Retrieve(id)
	if err != nil {
		if strings.Contains(err.Error(), commErr.RowsNotFound) {
			secLog.WithError(err).WithField("id", id).Info(
				"controllers/tagcertificate_controller:Delete() TagCertificate with given ID does not exist")
			return nil, http.StatusNotFound, &commErr.ResourceError{Message: "TagCertificate with given ID does not exist"}
		} else {
			secLog.WithError(err).WithField("id", id).Info(
				"controllers/tagcertificate_controller:Delete() attempt to delete invalid TagCertificate")
			return nil, http.StatusInternalServerError, &commErr.ResourceError{Message: "Failed to delete TagCertificate"}
		}
	}

	if err := controller.Store.Delete(id); err != nil {
		defaultLog.WithError(err).WithField("id", id).Info(
			"controllers/tagcertificate_controller:Delete() failed to delete TagCertificate")
		return nil, http.StatusInternalServerError, &commErr.ResourceError{Message: "Failed to delete TagCertificate"}
	}
	secLog.WithField("subject", delTagCert.Subject).Infof("TagCertificate deleted by: %s", r.RemoteAddr)
	return nil, http.StatusNoContent, nil
}

// validateTagCertCreateCriteria validates the data from the Create TagCertificate request
func validateTagCertCreateCriteria(tcCreateCriteria models.TagCertificateCreateCriteria) error {
	defaultLog.Trace("controllers/tagcertificate_controller:validateTagCertCreateCriteria() Entering")
	defer defaultLog.Trace("controllers/tagcertificate_controller:validateTagCertCreateCriteria() Leaving")

	// validate hardware UUID
	if tcCreateCriteria.HardwareUUID == uuid.Nil {
		return errors.New("Hardware UUID must be specified")
	}

	// if Selection content is empty
	if tcCreateCriteria.SelectionContent == nil {
		return errors.New("Tag Selection Content must be specified")
	}

	return nil
}

//  getTCFilterCriteria checks for set filter params in the Search request and returns a valid TagCertificateFilterCriteria
func getTCFilterCriteria(params url.Values) (*models.TagCertificateFilterCriteria, error) {
	defaultLog.Trace("controllers/tagcertificate_controller:getTCFilterCriteria() Entering")
	defer defaultLog.Trace("controllers/tagcertificate_controller:getTCFilterCriteria() Leaving")

	tagCertFc := models.TagCertificateFilterCriteria{}

	// TagCertificate ID
	if param := strings.TrimSpace(params.Get("id")); param != "" {
		id, err := uuid.Parse(param)
		if err != nil {
			return nil, errors.New("Invalid UUID format of the TagCertificate Identifier specified")
		}
		tagCertFc.ID = id
	}

	// subjectEqualTo
	if param := strings.TrimSpace(params.Get("subjectEqualTo")); param != "" {
		if err := validation.ValidateStrings([]string{param}); err != nil {
			return nil, errors.New("Valid contents for subjectEqualTo must be specified")
		}
		tagCertFc.SubjectEqualTo = param
	}

	// subjectContains
	if param := strings.TrimSpace(params.Get("subjectContains")); param != "" {
		if err := validation.ValidateStrings([]string{param}); err != nil {
			return nil, errors.New("Valid contents for subjectContains must be specified")
		}
		tagCertFc.SubjectContains = param
	}

	issuerMatch := regexp.MustCompile(`(^[a-zA-Z0-9-_,.=#+?&;)( ]*$)`)
	// issuerEqualTo - TODO: use new issuer check in validation pkg
	param := strings.TrimSpace(params.Get("issuerEqualTo"))
	if param != "" {
		if issuerMatch.MatchString(param) {
			tagCertFc.IssuerEqualTo = param
		} else {
			return nil, errors.New("Valid contents for issuerEqualTo must be specified")
		}
	}

	// issuerContains - TODO: use new issuer check in validation pkg
	if param := strings.TrimSpace(params.Get("issuerContains")); param != "" {
		if issuerMatch.MatchString(param) {
			tagCertFc.IssuerContains = param
		} else {
			return nil, errors.New("Valid contents for issuerContains must be specified")
		}
	}

	// validOn
	if param := strings.TrimSpace(params.Get("validOn")); param != "" {
		pTime, err := time.Parse(constants.HVSParamDateFormat, param)
		if err != nil {
			return nil, errors.Wrap(err, "Valid date (YYYY-MM-DD hh:mm:ss) for validOn must be specified")
		}
		tagCertFc.ValidOn = pTime
	}

	// validBefore
	if param := strings.TrimSpace(params.Get("validBefore")); param != "" {
		pTime, err := time.Parse(constants.HVSParamDateFormat, param)
		if err != nil {
			return nil, errors.Wrap(err, "Valid date (YYYY-MM-DD hh:mm:ss) for ValidBefore must be specified")
		}
		tagCertFc.ValidBefore = pTime
	}

	// validAfter
	if param := strings.TrimSpace(params.Get("validAfter")); param != "" {
		pTime, err := time.Parse(constants.HVSParamDateFormat, param)
		if err != nil {
			return nil, errors.Wrap(err, "Valid date (YYYY-MM-DD hh:mm:ss) for ValidAfter must be specified")
		}
		tagCertFc.ValidAfter = pTime
	}

	// hardwareUuid
	if param := strings.TrimSpace(params.Get("hardwareUuid")); param != "" {
		hwUUID, err := uuid.Parse(param)
		if err != nil {
			return nil, errors.New("Invalid UUID format of the Host HardwareUUID specified")
		}
		tagCertFc.HardwareUUID = hwUUID
	}

	return &tagCertFc, nil
}
