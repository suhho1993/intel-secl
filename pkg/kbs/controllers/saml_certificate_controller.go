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

type SamlCertController struct {
	store domain.CertificateStore
}

func NewSamlCertController(cs domain.CertificateStore) *SamlCertController {
	return &SamlCertController{store:cs}
}

//Import : Function to store the provided saml certificate in directory
func (sc SamlCertController) Import(responseWriter http.ResponseWriter, request *http.Request) (interface{}, int, error) {
	defaultLog.Trace("controllers/saml_certificate_controller:Import() Entering")
	defer defaultLog.Trace("controllers/saml_certificate_controller:Import() Leaving")

	certBytes, status, err := utils.GetCertificate(request)
	if err != nil {
		return nil, status, err
	}

	cert := &kbs.Certificate{
		Certificate: certBytes,
	}
	createdCert, err := sc.store.Create(cert)
	if err != nil {
		defaultLog.WithError(err).Error("controllers/saml_certificate_controller:Create() Certificate save failed")
		return nil, http.StatusInternalServerError, &commErr.ResourceError{Message:"Failed to save certificate"}
	}

	secLog.WithField("Id", createdCert.ID).Infof("controllers/saml_certificate_controller:Import() %s: Saml Certificate imported by: %s", commLogMsg.PrivilegeModified, request.RemoteAddr)
	return createdCert, http.StatusOK, nil
}

//Retrieve : Function to retrieve saml certificate
func (sc SamlCertController) Retrieve(responseWriter http.ResponseWriter, request *http.Request) (interface{}, int, error) {
	defaultLog.Trace("controllers/saml_certificate_controller:Retrieve() Entering")
	defer defaultLog.Trace("controllers/saml_certificate_controller:Retrieve() Leaving")

	id := uuid.MustParse(mux.Vars(request)["id"])
	key, err := sc.store.Retrieve(id)
	if err != nil {
		if err.Error() == commErr.RecordNotFound {
			defaultLog.Error("controllers/saml_certificate_controller:Retrieve() Certificate with specified id could not be located")
			return nil, http.StatusNotFound, &commErr.ResourceError{Message:"Certificate with specified id does not exist"}
		} else {
			defaultLog.WithError(err).Error("controllers/saml_certificate_controller:Retrieve() Certificate retrieve failed")
			return nil, http.StatusInternalServerError, &commErr.ResourceError{Message:"Failed to retrieve certificate"}
		}
	}

	secLog.WithField("Id", id).Infof("controllers/saml_certificate_controller:Retrieve() Saml Certificate retrieved by: %s", request.RemoteAddr)
	return key, http.StatusOK, nil
}

//Delete : Function to delete saml certificate
func (sc SamlCertController) Delete(responseWriter http.ResponseWriter, request *http.Request) (interface{}, int, error) {
	defaultLog.Trace("controllers/saml_certificate_controller:Delete() Entering")
	defer defaultLog.Trace("controllers/saml_certificate_controller:Delete() Leaving")

	id := uuid.MustParse(mux.Vars(request)["id"])
	err := sc.store.Delete(id)
	if err != nil {
		if err.Error() == commErr.RecordNotFound {
			defaultLog.Error("controllers/saml_certificate_controller:Delete() Certificate with specified id could not be located")
			return nil, http.StatusNotFound, &commErr.ResourceError{Message:"Certificate with specified id does not exist"}
		} else {
			defaultLog.WithError(err).Error("controllers/saml_certificate_controller:Delete() Certificate delete failed")
			return nil, http.StatusInternalServerError, &commErr.ResourceError{Message:"Failed to delete certificate"}
		}
	}

	secLog.WithField("Id", id).Infof("controllers/saml_certificate_controller:Delete() Saml Certificate deleted by: %s", request.RemoteAddr)
	return nil, http.StatusNoContent, nil
}

//Search : Function used to search saml certificates based on query parameter
func (sc SamlCertController) Search(responseWriter http.ResponseWriter, request *http.Request) (interface{}, int, error) {
	defaultLog.Trace("controllers/saml_certificate_controller:Search() Entering")
	defer defaultLog.Trace("controllers/saml_certificate_controller:Search() Leaving")

	// get the CertificateFilterCriteria
	criteria, err := utils.GetCertificateFilterCriteria(request.URL.Query())
	if err != nil {
		secLog.WithError(err).Errorf("controllers/saml_certificate_controller:Search() %s : Invalid filter criteria", commLogMsg.InvalidInputBadParam)
		return nil, http.StatusBadRequest, &commErr.ResourceError{Message: err.Error()}
	}

	// retrieve the certificates which matches with parameters requested
	certificates, err := sc.store.Search(criteria)
	if err != nil {
		defaultLog.WithError(err).Error("controllers/saml_certificate_controller:Search() Certificates search failed")
		return nil, http.StatusInternalServerError, &commErr.ResourceError{Message:"Failed to search certificates"}
	}

	secLog.Infof("controllers/saml_certificate_controller:Search() %s: Saml Certificates searched by: %s", commLogMsg.AuthorizedAccess, request.RemoteAddr)
	return certificates, http.StatusOK, nil
}
