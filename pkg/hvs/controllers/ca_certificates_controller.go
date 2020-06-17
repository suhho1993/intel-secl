/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package controllers

import (
	"crypto/x509"
	"encoding/json"
	"github.com/gorilla/mux"
	"github.com/intel-secl/intel-secl/v3/pkg/hvs/domain/models"
	"github.com/intel-secl/intel-secl/v3/pkg/lib/common/crypt"
	commErr "github.com/intel-secl/intel-secl/v3/pkg/lib/common/err"
	commLogMsg "github.com/intel-secl/intel-secl/v3/pkg/lib/common/log/message"
	"github.com/intel-secl/intel-secl/v3/pkg/model/hvs"
	"github.com/pkg/errors"
	"net/http"
	"strings"
)

// CaFileStore holds the file/directory locations for various types of certificates
type CaFileStore struct {
	rootCaDir         string
	privacyCaFile     string
	endorsementCaFile string
	samlCertFile      string
	tlsCertFile       string
}

// NewCAFileStore initializes new CaFileStore
func NewCAFileStore(rootCaDir, privacyCaFile, endorsementCaFile, samlCertFile, tlsCertFile string) *CaFileStore {
	return &CaFileStore{
		rootCaDir:         rootCaDir,
		privacyCaFile:     privacyCaFile,
		endorsementCaFile: endorsementCaFile,
		samlCertFile:      samlCertFile,
		tlsCertFile:       tlsCertFile,
	}
}

type CaCertificatesController struct {
	Store *CaFileStore
}

// Create stores new Ca certificate in the root certificates directory location
func (ca CaCertificatesController) Create(w http.ResponseWriter, r *http.Request) (interface{}, int, error) {
	defaultLog.Trace("controllers/ca_certificates_controller:Create() Entering")
	defer defaultLog.Trace("controllers/ca_certificates_controller:Create() Leaving")

	if r.ContentLength == 0 {
		secLog.Error("controllers/ca_certificates_controller:Create() The request body is not provided")
		return nil, http.StatusBadRequest, &commErr.ResourceError{Message: "The request body is not provided"}
	}

	var caCertificate hvs.CaCertificate
	// Decode the incoming json data to note struct
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()

	err := dec.Decode(&caCertificate)
	if err != nil {
		defaultLog.WithError(err).Errorf("controllers/ca_certificates_controller:Create() %s :  Failed to decode request body as CaCertificates", commLogMsg.AppRuntimeErr)
		return nil, http.StatusBadRequest, &commErr.ResourceError{Message: "Unable to decode JSON request body"}
	}

	err = validateCaCertificates(caCertificate)
	if err != nil {
		defaultLog.WithError(err).Errorf("controllers/ca_certificates_controller:Create() %s : Validation failed for certificate", commLogMsg.AppRuntimeErr)
		return nil, http.StatusBadRequest, &commErr.ResourceError{Message: err.Error()}
	}

	certPath := ca.Store.rootCaDir + strings.Replace(caCertificate.Name, " ", "", -1) +".pem"
	err = crypt.SavePemCert(caCertificate.Certificate, certPath)
	if err != nil {
		defaultLog.WithError(err).Errorf("controllers/ca_certificates_controller:Create() %s : Failed to store certificate", commLogMsg.AppRuntimeErr)
		return nil, http.StatusInternalServerError, &commErr.ResourceError{Message: "Failed to store certificate"}
	}
	secLog.WithField("Name", caCertificate.Name).Infof("%s: CA certificate created by: %s", commLogMsg.PrivilegeModified, r.RemoteAddr)
	return &caCertificate, http.StatusOK, nil
}

// Retrieve returns an existing Ca certificate from the stored location
func (ca CaCertificatesController) Retrieve(w http.ResponseWriter, r *http.Request) (interface{}, int, error) {
	defaultLog.Trace("controllers/ca_certificates_controller:Retrieve() Entering")
	defer defaultLog.Trace("controllers/ca_certificates_controller:Retrieve() Leaving")

	certType := mux.Vars(r)["certType"]
	if !models.IsValidCertType(certType) {
		secLog.Info(
			"controllers/ca_certificates_controller:Retrieve() Invalid Certificate Type provided")
		return nil, http.StatusBadRequest, &commErr.ResourceError{Message: "Invalid Certificate Type provided"}
	}

	var certificate *hvs.CaCertificate
	var err error
	if certType == models.CertTypesSaml.String() {
		certificate, err = ReadCertificate(ca.Store.samlCertFile)
		if err != nil {
			defaultLog.WithError(err).Errorf("%s not found", ca.Store.samlCertFile)
			return nil, http.StatusInternalServerError, &commErr.ResourceError{Message: "Unable to read Saml Certificate"}
		}
	} else if certType == models.CaCertTypesPrivacyCa.String() || certType == models.CaCertTypesAikCa.String() {
		certificate, err = ReadCertificate(ca.Store.privacyCaFile)
		if err != nil {
			defaultLog.WithError(err).Errorf("%s not found", ca.Store.privacyCaFile)
			return nil, http.StatusInternalServerError, &commErr.ResourceError{Message: "Unable to read Privacy CA Certificate"}
		}
	} else if certType == models.CaCertTypesEndorsementCa.String() || certType == models.CaCertTypesEkCa.String() {
		certificate, err = ReadCertificate(ca.Store.endorsementCaFile)
		if err != nil {
			defaultLog.WithError(err).Errorf("%s not found", ca.Store.endorsementCaFile)
			return nil, http.StatusInternalServerError, &commErr.ResourceError{Message: "Unable to read Endorsement CA Certificate"}
		}
	} else if certType == models.CertTypesTls.String() {
		certificate, err = ReadCertificate(ca.Store.tlsCertFile)
		if err != nil {
			defaultLog.WithError(err).Errorf("%s not found", ca.Store.tlsCertFile)
			return nil, http.StatusInternalServerError, &commErr.ResourceError{Message: "Unable to read TLS Certificate"}
		}
	}
	return certificate, http.StatusOK, nil
}

// Search returns a collection of Ca certificates based on domain
func (ca CaCertificatesController) Search(w http.ResponseWriter, r *http.Request) (interface{}, int, error) {
	defaultLog.Trace("controllers/ca_certificates_controller:Search() Entering")
	defer defaultLog.Trace("controllers/ca_certificates_controller:Search() Leaving")

	domain := r.URL.Query().Get("domain")

	if domain == "" || !(domain == models.CaCertTypesEkCa.String() || domain == models.CaCertTypesEndorsementCa.String() ||
		domain == models.CertTypesSaml.String()) {
		secLog.Info(
			"controllers/ca_certificates_controller:Search() Invalid domain/Certificate Type provided")
		return nil, http.StatusBadRequest, &commErr.ResourceError{Message: "Invalid domain/Certificate Type provided"}
	}

	var certificate *hvs.CaCertificateCollection
	var err error
	if domain == models.CertTypesSaml.String() {
		certificate, err = ReadCertificates(ca.Store.samlCertFile)
		if err != nil {
			defaultLog.WithError(err).Errorf("%s not found", ca.Store.samlCertFile)
			return nil, http.StatusInternalServerError, &commErr.ResourceError{Message: "Unable to read Saml Certificate"}
		}
	} else if domain == models.CaCertTypesEndorsementCa.String() || domain == models.CaCertTypesEkCa.String() {
		certificate, err = ReadCertificates(ca.Store.endorsementCaFile)
		if err != nil {
			defaultLog.WithError(err).Errorf("%s not found", ca.Store.endorsementCaFile)
			return nil, http.StatusInternalServerError, &commErr.ResourceError{Message: "Unable to read Endorsement CA Certificate"}
		}
	}
	return certificate, http.StatusOK, nil
}

// validateCaCertificates checks if input ca certificate is valid
func validateCaCertificates(caCertificate hvs.CaCertificate) error {
	defaultLog.Trace("controllers/ca_certificates_controller:validateCaCertificates() Entering")
	defer defaultLog.Trace("controllers/ca_certificates_controller:validateCaCertificates() Leaving")

	if models.CaCertTypesRootCa.String() != caCertificate.Type {
		return errors.Errorf("Invalid type, only root ca certificate can be added")
	}

	_, err := x509.ParseCertificate(caCertificate.Certificate)
	if err != nil {
		return errors.Wrap(err, "Unable to decode certificate present in the request body")
	}

	name := caCertificate.Name
	if name == "" {
		return errors.Errorf("Certificate Name must be specified")
	}
	return nil
}

// Read CaCertificates/certificate from the given certificate path
func ReadCertificates(certFile string) (*hvs.CaCertificateCollection, error) {
	defaultLog.Trace("controllers/ca_certificates_controller:ReadCertificates() Entering")
	defer defaultLog.Trace("controllers/ca_certificates_controller:ReadCertificates() Leaving")

	certsCollection := hvs.CaCertificateCollection{
		CaCerts: []*hvs.CaCertificate{},
	}

	certs, err := crypt.GetSubjectCertsMapFromPemFile(certFile)
	if err != nil {
		return nil, errors.Wrap(err, "controllers/ca_certificates_controller:ReadCertificates() Error while " +
			"reading certs from - " + certFile)
	}
	for _, cert := range certs {
		certificate := hvs.CaCertificate {
			Name:        cert.Issuer.CommonName,
			Certificate: cert.Raw,
		}
		certsCollection.CaCerts = append(certsCollection.CaCerts, &certificate)
	}
	return &certsCollection, nil
}

// Read CaCertificate/certificate from the given certificate path
func ReadCertificate(certFile string) (*hvs.CaCertificate, error) {
	defaultLog.Trace("controllers/ca_certificates_controller:ReadCertificate() Entering")
	defer defaultLog.Trace("controllers/ca_certificates_controller:ReadCertificate() Leaving")

	certCollection, err := ReadCertificates(certFile)
	if err != nil {
		return nil, errors.Wrap(err, "controllers/ca_certificates_controller:ReadCertificate() Error while reading" +
			" certs from - " + certFile)
	}

	if len(certCollection.CaCerts) > 0 {
		return certCollection.CaCerts[0], nil
	}
	return nil, errors.Wrap(err, "controllers/ca_certificates_controller:ReadCertificate() Certificate not found")
}
