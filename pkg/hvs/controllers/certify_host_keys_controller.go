/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */

package controllers

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	commErr "github.com/intel-secl/intel-secl/v3/pkg/lib/common/err"
	"github.com/intel-secl/intel-secl/v3/pkg/lib/privacyca"
	model "github.com/intel-secl/intel-secl/v3/pkg/model/wlagent"
	"github.com/pkg/errors"
	"strings"

	"encoding/json"
	"encoding/pem"
	consts "github.com/intel-secl/intel-secl/v3/pkg/hvs/constants"
	"github.com/intel-secl/intel-secl/v3/pkg/lib/common/crypt"
	"io/ioutil"

	"net/http"
)

type CertifyHostKeysController struct {
}

func (certifyHostKeysController *CertifyHostKeysController) CertifySigningKey(w http.ResponseWriter, r *http.Request) (interface{}, int, error) {
	defaultLog.Trace("controllers/certify_host_keys_controller:Certify_host_keys() Entering")
	defer defaultLog.Trace("controllers/certify_host_keys_controller:Certify_host_keys() Leaving")
	var regKeyInfo model.RegisterKeyInfo
	dec := json.NewDecoder(r.Body)
	defaultLog.Info(dec)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&regKeyInfo); err != nil {
		defaultLog.WithError(err).Error("controllers/certify_host_keys_controller:Certify_host_keys() Error while decoding request body")
		return nil, http.StatusBadRequest, &commErr.ResourceError{Message: "Error while decoding request body"}
	}

	certificate, err, httpStatus := generateCertificate(consts.HostSigningKeyCertificateCN, regKeyInfo)
	if err != nil{
		defaultLog.WithError(err).Error("controllers/certify_host_keys_controller:Certify_host_keys() Error while certifying Signing Key")
		return nil, httpStatus, &commErr.ResourceError{Message: "Error while certifying Signing Key"}
	}

	w.WriteHeader(http.StatusCreated)
	signingKeyCert := model.SigningKeyCert{
		SigningKeyCertificate: certificate,
	}
	return signingKeyCert, http.StatusCreated, nil
}

func (certifyHostKeysController *CertifyHostKeysController) CertifyBindingKey(w http.ResponseWriter, r *http.Request) (interface{}, int, error) {
	defaultLog.Trace("controllers/certify_host_keys_controller:CertifyBindingKey() Entering")
	defer defaultLog.Trace("controllers/certify_host_keys_controller:CertifyBindingKey() Leaving")
	var regKeyInfo model.RegisterKeyInfo
	dec := json.NewDecoder(r.Body)
	defaultLog.Info(dec)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&regKeyInfo); err != nil {
		defaultLog.WithError(err).Error("controllers/certify_host_keys_controller:CertifyBindingKey() Error while decoding request body")
		return nil, http.StatusBadRequest, &commErr.ResourceError{Message:"Error while decoding request body"}
	}

	certificate, err, httpStatus := generateCertificate(consts.HostBindingKeyCertificateCN, regKeyInfo)
	if err != nil{
		defaultLog.WithError(err).Error("controllers/certify_host_keys_controller:CertifyBindingKey() Error while certifying Binding Key")
		return nil, httpStatus, &commErr.ResourceError{Message: "Error while certifying Binding Key"}
	}
	bindingKeyCert := model.BindingKeyCert{
		BindingKeyCertificate: certificate,
	}
	return bindingKeyCert, http.StatusCreated, nil
}


func generateCertificate(commName string, regKeyInfo model.RegisterKeyInfo) ([]byte, error, int){
	defaultLog.Trace("controllers/certify_host_keys_controller:generateCertificate() Entering")
	defer defaultLog.Trace("controllers/certify_host_keys_controller:generateCertificate() Leaving")

	if regKeyInfo.PublicKeyModulus == nil || regKeyInfo.TpmCertifyKey == nil || regKeyInfo.TpmCertifyKeySignature == nil ||
		regKeyInfo.AikDerCertificate == nil || regKeyInfo.NameDigest == nil{
		return nil, errors.New("controllers/certify_host_keys_controller:generateCertificate() Invalid input specified or input value missing"), http.StatusBadRequest
	}

	//Currently supported only for linux systems
	if strings.ToLower(regKeyInfo.OsType) != "linux"{
		return nil, errors.New("controllers/certify_host_keys_controller:generateCertificate() Supported only for OS linux"), http.StatusBadRequest
	}

	aikCert, err := x509.ParseCertificate(regKeyInfo.AikDerCertificate)
	if err != nil {
		return nil, errors.Wrap(err, "controllers/certify_host_keys_controller:generateCertificate() Could not get aik certificate from aik der bytes"), http.StatusBadRequest
	}

	certifyKey20, err := privacyca.NewCertifyKey(regKeyInfo)

	if !certifyKey20.IsTpmGeneratedKey(){
		return nil, errors.New("controllers/certify_host_keys_controller:generateCertificate() Not a valid tpm generated key"), http.StatusBadRequest
	}

	// Need to verify if the AIK is signed by the trusted Privacy CA, which would also ensure that the EK is verified.
	if !isAikCertifiedByPrivacyCA(aikCert) {
		return nil, errors.New("controllers/certify_host_keys_controller:generateCertificate() Error verifying the AIK signature against the Privacy CA"), http.StatusBadRequest
	}
	
	rsaPubKey, err := certifyKey20.GetPublicKeyFromModulus()
	if err != nil{
		return nil, errors.Wrap(err, "controllers/certify_host_keys_controller:generateCertificate() Error while retrieving public key modulus"), http.StatusBadRequest
	}

	//TODO add support for windows when needed
	status, err:= certifyKey20.IsCertifiedKeySignatureValid(aikCert)
	if err != nil || !status{
		return nil, errors.Wrap(err, "controllers/certify_host_keys_controller:generateCertificate() Signature verification failed"), http.StatusBadRequest
	}
	defaultLog.Info("controllers/certify_host_keys_controller:generateCertificate() TpmCertifyKeySignature is validated successfully")

	//In TPM 2.0 need to validate TPM name given to each key
	if !certifyKey20.ValidatePublicKey(){
		return nil, errors.New("Binding Public Key digest does not match digest in the TCG binding certificate"), http.StatusBadRequest
	}
	defaultLog.Info("controllers/certify_host_keys_controller:generateCertificate() Validated TpmPublicKeyModulus successfully")

	err = certifyKey20.ValidateNameDigest()
	if err != nil {
		return nil, errors.Wrap(err,"TPM Key Name specified does not match name digest in the TCG binding certificate"), http.StatusBadRequest
	}
	defaultLog.Info("controllers/certify_host_keys_controller:generateCertificate() TpmNameDigest validated successfully")

	caCertPem, err := ioutil.ReadFile(consts.CertPath)
	if err != nil {
		return nil, errors.Wrap(err,"controllers/certify_host_keys_controller:generateCertificate() TPM Key Name specified does not match name digest in the TCG binding certificate"), http.StatusBadRequest
	}
	block, _ := pem.Decode(caCertPem)
	if block == nil {
		return nil, errors.New("controllers/certify_host_keys_controller:generateCertificate() Failed to parse certificate PEM"), http.StatusInternalServerError
	}
	caCert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, errors.Wrap(err,"controllers/certify_host_keys_controller:generateCertificate() TPM Key Name specified does not match name digest in the TCG binding certificate"), http.StatusBadRequest
	}
	privacyCAKeyBytes, err := ioutil.ReadFile(consts.KeyPath)
	if err != nil {
		return nil, errors.Wrapf(err, "controllers/certify_host_keys_controller:generateCertificate() Unable to read %s", consts.KeyPath), http.StatusInternalServerError
	}
	block, _ = pem.Decode(privacyCAKeyBytes)
	if block == nil {
		return nil, errors.New("controllers/certify_host_keys_controller:generateCertificate() Failed to parse certificate PEM"), http.StatusInternalServerError
	}
	caKey, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil{
		return nil, errors.Wrap(err, "controllers/certify_host_keys_controller:generateCertificate() Unable to parse privacyca key"), http.StatusInternalServerError
	}

	certificate, err := certifyKey20.CertifyKey(caCert, rsaPubKey, caKey.(*rsa.PrivateKey), commName)
	if err != nil {
		return nil, errors.Wrapf(err, "controllers/certify_host_keys_controller:generateCertificate() Error while Certifying key"), http.StatusInternalServerError
	}
	defaultLog.Infof("controllers/certify_host_keys_controller:generateCertificate() certificate created successfully")
	return certificate, nil, http.StatusCreated
}

func isAikCertifiedByPrivacyCA(aikCert *x509.Certificate) bool {
	defaultLog.Trace("controllers/certify_host_keys_controller:isAikCertifiedByPrivacyCA() Entering")
	defer defaultLog.Trace("controllers/certify_host_keys_controller:isAikCertifiedByPrivacyCA() Leaving")

	privacyCAPem, err := ioutil.ReadFile(consts.CertPath)
	if err != nil {
		defaultLog.WithError(err).Errorf("controllers/certify_host_keys_controller:isAikCertifiedByPrivacyCA() Error while reading %s", consts.CertPath)
		return false
	}

	pubKey, err := crypt.GetPublicKeyFromCertPem(privacyCAPem)
	if err != nil {
		defaultLog.WithError(err).Errorf("controllers/certify_host_keys_controller:isAikCertifiedByPrivacyCA() Could not get Public key from privacy ca certificate")
		return false
	}
	rsaPublicKey := pubKey.(*rsa.PublicKey)

	h := sha256.New()
	h.Write(aikCert.RawTBSCertificate)
	digest := h.Sum(nil)
	err = rsa.VerifyPKCS1v15(rsaPublicKey, crypto.SHA256, digest, aikCert.Signature)
	if err != nil {
		defaultLog.WithError(err).Error("controllers/certify_host_keys_controller:isAikCertifiedByPrivacyCA() Error while verifying the AIK signature against the Privacy CA")
		return false
	}

	return true
}
