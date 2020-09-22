/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package controllers

import (
	"net/http"

	"github.com/google/uuid"
	"github.com/gorilla/mux"
	"github.com/intel-secl/intel-secl/v3/pkg/kbs/domain"
	"github.com/intel-secl/intel-secl/v3/pkg/kbs/utils"
	commErr "github.com/intel-secl/intel-secl/v3/pkg/lib/common/err"
	commLogMsg "github.com/intel-secl/intel-secl/v3/pkg/lib/common/log/message"
	"github.com/intel-secl/intel-secl/v3/pkg/model/kbs"
)

type TpmIdentityCertController struct {
	store domain.CertificateStore
}

func NewTpmIdentityCertController(cs domain.CertificateStore) *TpmIdentityCertController {
	return &TpmIdentityCertController{store:cs}
}

//Import : Function to store the provided tpm-identity certificate in directory
func (tc TpmIdentityCertController) Import(responseWriter http.ResponseWriter, request *http.Request) (interface{}, int, error) {
	defaultLog.Trace("controllers/tpm_identity_certificate_controller:Import() Entering")
	defer defaultLog.Trace("controllers/tpm_identity_certificate_controller:Import() Leaving")

	certBytes, status, err := utils.GetCertificate(request)
	if err != nil {
		return nil, status, err
	}

	cert := &kbs.Certificate{
		Certificate: certBytes,
	}
	createdCert, err := tc.store.Create(cert)
	if err != nil {
		defaultLog.WithError(err).Error("controllers/tpm_identity_certificate_controller:Create() Certificate save failed")
		return nil, http.StatusInternalServerError, &commErr.ResourceError{Message:"Failed to save certificate"}
	}

	secLog.WithField("Id", createdCert.ID).Infof("controllers/tpm_identity_certificate_controller:Import() %s: Tpm-Identity Certificate imported by: %s", commLogMsg.PrivilegeModified, request.RemoteAddr)
	return createdCert, http.StatusOK, nil
}

//Retrieve : Function to retrieve tpm-identity certificate
func (tc TpmIdentityCertController) Retrieve(responseWriter http.ResponseWriter, request *http.Request) (interface{}, int, error) {
	defaultLog.Trace("controllers/tpm_identity_certificate_controller:Retrieve() Entering")
	defer defaultLog.Trace("controllers/tpm_identity_certificate_controller:Retrieve() Leaving")

	id := uuid.MustParse(mux.Vars(request)["id"])
	key, err := tc.store.Retrieve(id)
	if err != nil {
		if err.Error() == commErr.RecordNotFound {
			defaultLog.Error("controllers/tpm_identity_certificate_controller:Retrieve() Certificate with specified id could not be located")
			return nil, http.StatusNotFound, &commErr.ResourceError{Message:"Certificate with specified id does not exist"}
		} else {
			defaultLog.WithError(err).Error("controllers/tpm_identity_certificate_controller:Retrieve() Certificate retrieve failed")
			return nil, http.StatusInternalServerError, &commErr.ResourceError{Message:"Failed to retrieve certificate"}
		}
	}

	secLog.WithField("Id", id).Infof("controllers/tpm_identity_certificate_controller:Retrieve() Tpm-Identity Certificate retrieved by: %s", request.RemoteAddr)
	return key, http.StatusOK, nil
}

//Delete : Function to delete tpm-identity certificate
func (tc TpmIdentityCertController) Delete(responseWriter http.ResponseWriter, request *http.Request) (interface{}, int, error) {
	defaultLog.Trace("controllers/tpm_identity_certificate_controller:Delete() Entering")
	defer defaultLog.Trace("controllers/tpm_identity_certificate_controller:Delete() Leaving")

	id := uuid.MustParse(mux.Vars(request)["id"])
	err := tc.store.Delete(id)
	if err != nil {
		if err.Error() == commErr.RecordNotFound {
			defaultLog.Error("controllers/tpm_identity_certificate_controller:Delete() Certificate with specified id could not be located")
			return nil, http.StatusNotFound, &commErr.ResourceError{Message:"Certificate with specified id does not exist"}
		} else {
			defaultLog.WithError(err).Error("controllers/tpm_identity_certificate_controller:Delete() Certificate delete failed")
			return nil, http.StatusInternalServerError, &commErr.ResourceError{Message:"Failed to delete certificate"}
		}
	}

	secLog.WithField("Id", id).Infof("controllers/tpm_identity_certificate_controller:Delete() Tpm-Identity Certificate deleted by: %s", request.RemoteAddr)
	return nil, http.StatusNoContent, nil
}

//Search : Function to search tpm-identity certificates based on query parameter
func (tc TpmIdentityCertController) Search(responseWriter http.ResponseWriter, request *http.Request) (interface{}, int, error) {
	defaultLog.Trace("controllers/tpm_identity_certificate_controller:Search() Entering")
	defer defaultLog.Trace("controllers/tpm_identity_certificate_controller:Search() Leaving")

	// get the CertificateFilterCriteria
	criteria, err := utils.GetCertificateFilterCriteria(request.URL.Query())
	if err != nil {
		secLog.WithError(err).Errorf("controllers/tpm_identity_certificate_controller:Search() %s : Invalid filter criteria", commLogMsg.InvalidInputBadParam)
		return nil, http.StatusBadRequest, &commErr.ResourceError{Message: err.Error()}
	}

	// retrieve the certificates which matches with parameters requested
	certificates, err := tc.store.Search(criteria)
	if err != nil {
		defaultLog.WithError(err).Error("controllers/tpm_identity_certificate_controller:Search() Certificates search failed")
		return nil, http.StatusInternalServerError, &commErr.ResourceError{Message:"Failed to search certificates"}
	}

	secLog.Infof("controllers/tpm_identity_certificate_controller:Search() %s: Tpm-Identity Certificates searched by: %s", commLogMsg.AuthorizedAccess, request.RemoteAddr)
	return certificates, http.StatusOK, nil
}
