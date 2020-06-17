/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */

package controllers

import (
	"bytes"
	"crypto"
	"crypto/aes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"encoding/json"
	"github.com/intel-secl/intel-secl/v3/pkg/hvs/constants"
	"github.com/intel-secl/intel-secl/v3/pkg/lib/common/crypt"
	commErr "github.com/intel-secl/intel-secl/v3/pkg/lib/common/err"
	"github.com/intel-secl/intel-secl/v3/pkg/lib/common/log/message"
	"github.com/intel-secl/intel-secl/v3/pkg/lib/privacyca"
	taModel "github.com/intel-secl/intel-secl/v3/pkg/model/ta"
	"github.com/pkg/errors"
	"io/ioutil"
	"math/big"
	"net/http"
	"os"
	"strings"
	"time"
)

type PrivacyCAFileStore struct {
	keyPath string
	certPath string
	eCACertPath string
	aikRequestsDirPath string
}

type CertifyHostAiksController struct {
	Store *PrivacyCAFileStore
}


func NewPrivacyCAFileStore(keyPath, certPath, eCAPath, aikRequestsDirPath string) *PrivacyCAFileStore {
	return &PrivacyCAFileStore{
		keyPath: keyPath,
		certPath: certPath,
		eCACertPath: eCAPath,
		aikRequestsDirPath: aikRequestsDirPath,
	}
}

func (certifyHostAiksController *CertifyHostAiksController) StoreEkCerts(identityRequestChallenge,  ekCertBytes []byte, identityChallengePayload taModel.IdentityChallengePayload) error{
	defaultLog.Trace("controllers/certify_host_aiks_controller:StoreEkCerts() Entering")
	defer defaultLog.Trace("controllers/certify_host_aiks_controller:StoreEkCerts() Leaving")

	if _, err := os.Stat(certifyHostAiksController.Store.aikRequestsDirPath); os.IsNotExist(err) {
		errDir := os.MkdirAll(certifyHostAiksController.Store.aikRequestsDirPath, 0700)
		if errDir != nil {
			return errors.Wrapf(err, "controllers/certify_host_aiks_controller:StoreEkCerts() could not create directory %s", certifyHostAiksController.Store.aikRequestsDirPath)
		}
	}

	idReqFileName := hex.EncodeToString(identityRequestChallenge)
	defaultLog.Debugf("controllers/certify_host_aiks_controller:StoreEkCerts() idReqFileName: %s", idReqFileName)
	optionsFileName := idReqFileName + ".opt"
	err := ioutil.WriteFile(certifyHostAiksController.Store.aikRequestsDirPath + idReqFileName, identityChallengePayload.IdentityRequest.AikModulus, 0400)
	if err != nil{
		return err
	}

	err = ioutil.WriteFile(certifyHostAiksController.Store.aikRequestsDirPath + optionsFileName, identityChallengePayload.IdentityRequest.AikName, 0400)
	if err != nil{
		return err
	}

	ekcertFilename := idReqFileName + ".ekcert"
	err = ioutil.WriteFile(certifyHostAiksController.Store.aikRequestsDirPath + ekcertFilename, ekCertBytes, 0400)
	if err != nil{
		return err
	}
	return nil
}

func (certifyHostAiksController *CertifyHostAiksController) GetEkCerts(decryptedIdentityRequestChallenge []byte) (*x509.Certificate, []byte, []byte, error) {
	defaultLog.Trace("controllers/certify_host_aiks_controller:GetEkCerts() Entering")
	defer defaultLog.Trace("controllers/certify_host_aiks_controller:GetEkCerts() Leaving")

	fileName := hex.EncodeToString(decryptedIdentityRequestChallenge)
	if _, err := os.Stat(certifyHostAiksController.Store.aikRequestsDirPath + fileName); os.IsNotExist(err) {
		return nil, nil, nil, errors.New("controllers/certify_host_aiks_controller:GetEkCerts() Invalid Challenge response")
	}
	defaultLog.Debugf("ek cert fileName: %s", fileName)
	ekcertFile := certifyHostAiksController.Store.aikRequestsDirPath + fileName + ".ekcert"
	ekCert, err := ioutil.ReadFile(ekcertFile)
	if err != nil {
		return nil, nil, nil, errors.Wrapf(err, "controllers/certify_host_aiks_controller:GetEkCerts() Unable to read file %s", ekcertFile)
	}

	ekx509Cert, err := x509.ParseCertificate(ekCert)
	if err != nil {
		return nil, nil, nil, errors.Wrap(err, "controllers/certify_host_aiks_controller:GetEkCerts() Unable to parse certificate")
	}

	optionsFile := certifyHostAiksController.Store.aikRequestsDirPath + fileName + ".opt"
	challengeFile := certifyHostAiksController.Store.aikRequestsDirPath + fileName

	modulus, err := ioutil.ReadFile(challengeFile)
	if err != nil{
		return nil, nil, nil, err
	}

	aikName, err := ioutil.ReadFile(optionsFile)
	if err != nil{
		return nil, nil, nil, err
	}

	return ekx509Cert, aikName, modulus, nil
}

func (certifyHostAiksController *CertifyHostAiksController) IdentityRequestGetChallenge(w http.ResponseWriter, r *http.Request) (interface{}, int, error) {
	defaultLog.Trace("controllers/certify_host_aiks_controller:IdentityRequestGetChallenge() Entering")
	defer defaultLog.Trace("controllers/certify_host_aiks_controller:IdentityRequestGetChallenge() Leaving")

	data, err := ioutil.ReadAll(r.Body)
	if err != nil {
		defaultLog.WithError(err).Errorf("controllers/certify_host_aiks_controller:IdentityRequestGetChallenge() %s - Error reading request body: %s for request %s", message.AppRuntimeErr, string(data), r.URL.Path)
		return nil, http.StatusBadRequest, &commErr.ResourceError{Message: "Error reading request body"}
	}
	var identityChallengePayload taModel.IdentityChallengePayload
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	err = dec.Decode(&identityChallengePayload)
	if err != nil {
		secLog.WithError(err).Errorf("controllers/certify_host_aiks_controller:identityRequestGetChallenge() %s - Error marshaling json data: %s", message.InvalidInputProtocolViolation, string(data))
		return nil, http.StatusBadRequest, &commErr.ResourceError{Message: "Error marshaling json data"}
	}
	proofReq, status, err := certifyHostAiksController.getIdentityProofRequest(identityChallengePayload)
	if err != nil {
		defaultLog.WithError(err).Errorf("controllers/certify_host_aiks_controller:identityRequestGetChallenge() Error while getting IdentityProofRequest")
		return nil, status, &commErr.ResourceError{Message: "Error while getting IdentityProofRequest"}
	}

	return proofReq, status, nil
}


func (certifyHostAiksController *CertifyHostAiksController) getIdentityProofRequest(identityChallengePayload taModel.IdentityChallengePayload) (taModel.IdentityProofRequest, int, error) {
	defaultLog.Trace("controllers/certify_host_aiks_controller:getIdentityProofRequest() Entering")
	defer defaultLog.Trace("controllers/certify_host_aiks_controller:getIdentityProofRequest() Leaving")

	privacycaKey, err := crypt.GetPrivateKeyFromPKCS8File(certifyHostAiksController.Store.keyPath)
	if err != nil{
		return taModel.IdentityProofRequest{}, http.StatusInternalServerError, errors.Wrapf(err, "controllers/certify_host_aiks_controller:getIdentityProofRequest() unable to parse privacyca key from file %s", certifyHostAiksController.Store.keyPath)
	}
	privacycaTpm2, err := privacyca.NewPrivacyCA(identityChallengePayload.IdentityRequest)
	if err != nil{
		return taModel.IdentityProofRequest{}, http.StatusBadRequest, err
	}
	ekCertBytes, err := privacycaTpm2.GetEkCert(identityChallengePayload, privacycaKey)
	if err != nil{
		return taModel.IdentityProofRequest{}, http.StatusBadRequest, errors.Wrap(err, "controllers/certify_host_aiks_controller:getIdentityProofRequest() unable to get ek cert bytes")
	}

	ekCert, err :=  x509.ParseCertificate(ekCertBytes)
	if err != nil{
		return taModel.IdentityProofRequest{}, http.StatusBadRequest, err
	}

	endorsementCerts, err := crypt.GetSubjectCertsMapFromPemFile(certifyHostAiksController.Store.eCACertPath)
	if err != nil{
		return taModel.IdentityProofRequest{}, http.StatusInternalServerError, errors.Wrap(err, "controllers/certify_host_aiks_controller:getIdentityProofRequest() Error while getting endorsement certs")
	}

	defaultLog.Debugf("controllers/certify_host_aiks_controller:getIdentityProofRequest() ekCert Issuer Name :%s", ekCert.Issuer.CommonName)
	endorsementCertsToVerify := endorsementCerts[strings.ReplaceAll(ekCert.Issuer.CommonName, "\\x00","")]

	if !certifyHostAiksController.isEkCertificateVerifiedByAuthority(ekCert, endorsementCertsToVerify) {
		secLog.Errorf("controllers/certify_host_aiks_controller:getIdentityProofRequest() EC is not trusted, Please verify Enorsement Authority certificate is present in %s file", constants.EndorsementCaCertFile)
		return taModel.IdentityProofRequest{}, http.StatusBadRequest, errors.Wrap(err, "controllers/certify_host_aiks_controller:getIdentityProofRequest() EC is not trusted")
	}

	identityRequestChallenge, err := crypt.GetRandomBytes(32)
	if err != nil{
		return taModel.IdentityProofRequest{}, http.StatusInternalServerError, err
	}

	err = certifyHostAiksController.StoreEkCerts(identityRequestChallenge, ekCertBytes, identityChallengePayload)
	if err != nil{
		return taModel.IdentityProofRequest{}, http.StatusInternalServerError, err
	}

	privacycaTpm2, err = privacyca.NewPrivacyCA(identityChallengePayload.IdentityRequest)
	if err != nil{
		return taModel.IdentityProofRequest{}, http.StatusBadRequest, err
	}

	proofReq, err := privacycaTpm2.ProcessIdentityRequest(identityChallengePayload.IdentityRequest, ekCert.PublicKey.(*rsa.PublicKey), identityRequestChallenge)
	if err != nil{
		defaultLog.WithError(err).Error("Unable to generate random bytes for identityRequestChallenge")
		return taModel.IdentityProofRequest{}, http.StatusInternalServerError, err
	}

	return proofReq, http.StatusCreated, nil
}


func (certifyHostAiksController *CertifyHostAiksController) isEkCertificateVerifiedByAuthority(cert *x509.Certificate, authority x509.Certificate) bool{
	defaultLog.Trace("controllers/certify_host_aiks_controller:isEkCertificateVerifiedByAuthority() Entering")
	defer defaultLog.Trace("controllers/certify_host_aiks_controller:isEkCertificateVerifiedByAuthority() Leaving")

	rsaPublicKey := authority.PublicKey.(*rsa.PublicKey)
	sigAlg := cert.SignatureAlgorithm
	switch sigAlg {
	case x509.SHA1WithRSA:
		h := sha1.New()
		h.Write(cert.RawTBSCertificate)
		digest := h.Sum(nil)
		err := rsa.VerifyPKCS1v15(rsaPublicKey, crypto.SHA1, digest, cert.Signature)

		if err != nil {
			defaultLog.Errorf("controllers/certify_host_aiks_controller:isEkCertificateVerifiedByAuthority() Error while verifying the ek cert signature against the Endorsement authority, Error: %v", err)
			return false
		}
		break
	case x509.SHA256WithRSA:
		h := sha256.New()
		h.Write(cert.RawTBSCertificate)
		digest := h.Sum(nil)
		err := rsa.VerifyPKCS1v15(rsaPublicKey, crypto.SHA256, digest, cert.Signature)

		if err != nil {
			defaultLog.Errorf("controllers/certify_host_aiks_controller:isEkCertificateVerifiedByAuthority() Error while verifying the ek cert signature against the Endorsement authority, Error: %v", err)
			return false
		}
		break
	case x509.SHA384WithRSA:
		h := sha512.New384()
		h.Write(cert.RawTBSCertificate)
		digest := h.Sum(nil)
		err := rsa.VerifyPKCS1v15(rsaPublicKey, crypto.SHA384, digest, cert.Signature)

		if err != nil {
			defaultLog.Errorf("controllers/certify_host_aiks_controller:isEkCertificateVerifiedByAuthority() Error while verifying the ek cert signature against the Endorsement authority, Error: %v", err)
			return false
		}
		break
	default:
		defaultLog.Errorf("controllers/certify_host_aiks_controller:isEkCertificateVerifiedByAuthority() Error while verifying the ek cert signature against the Endorsement authority, unsupported signature algorithm")
		return false
		break
	}

	return true
}

//TODO after implementation of TpmEndoresment database layer
/*func isEkCertificateRegistered() bool{
}*/

func (certifyHostAiksController *CertifyHostAiksController) IdentityRequestSubmitChallengeResponse(w http.ResponseWriter, r *http.Request) (interface{}, int, error) {
	defaultLog.Trace("controllers/certify_host_aiks_controller:IdentityRequestSubmitChallengeResponse() Entering")
	defer defaultLog.Trace("controllers/certify_host_aiks_controller:IdentityRequestSubmitChallengeResponse() Leaving")

		data, err := ioutil.ReadAll(r.Body)
		if err != nil {
			defaultLog.Errorf("controllers/certify_host_aiks_controller:IdentityRequestSubmitChallengeResponse() %s - Error reading request body: %s for request %s", message.AppRuntimeErr, string(data), r.URL.Path)
			return nil, http.StatusBadRequest, &commErr.ResourceError{Message: "Error reading request body"}
		}

		var identityChallengePayload taModel.IdentityChallengePayload
		dec := json.NewDecoder(bytes.NewReader(data))
		dec.DisallowUnknownFields()
		err = dec.Decode(&identityChallengePayload)
		if err != nil {
			secLog.WithError(err).Errorf("controllers/certify_host_aiks_controller:IdentityRequestSubmitChallengeResponse() %s - Error marshaling json data: %s", message.InvalidInputProtocolViolation, string(data))
			return nil, http.StatusBadRequest, &commErr.ResourceError{Message: "Error marshaling json data"}
		}

		proofReq, status, err := certifyHostAiksController.getIdentityProofRequestResponse(identityChallengePayload)
		if err != nil {
			defaultLog.WithError(err).Errorf("controllers/certify_host_aiks_controller:IdentityRequestSubmitChallengeResponse() Error while getting IdentityProofRequestResponse")
			return nil, status, &commErr.ResourceError{Message: "Error while getting IdentityProofRequestResponse"}
		}

		return proofReq, status, nil

}

func(certifyHostAiksController *CertifyHostAiksController) getIdentityProofRequestResponse(identityChallengePayload taModel.IdentityChallengePayload) (taModel.IdentityProofRequest, int, error) {
	defaultLog.Trace("controllers/certify_host_aiks_controller:getIdentityProofRequestResponse() Entering")
	defer defaultLog.Trace("controllers/certify_host_aiks_controller:getIdentityProofRequestResponse() Leaving")

	privacycaKey, err := crypt.GetPrivateKeyFromPKCS8File(certifyHostAiksController.Store.keyPath)
	if err != nil{
		return taModel.IdentityProofRequest{}, http.StatusInternalServerError, err
	}

	privacycaCert, err := crypt.GetCertFromPemFile(certifyHostAiksController.Store.certPath)
	if err != nil{
		return taModel.IdentityProofRequest{}, http.StatusInternalServerError, err
	}

	privacycaTpm2, err := privacyca.NewPrivacyCA(identityChallengePayload.IdentityRequest)
	if err != nil{
		return taModel.IdentityProofRequest{}, http.StatusBadRequest, errors.Wrap(err, "controllers/certify_host_aiks_controller:getIdentityProofRequestResponse() Unable to get new privacyca instance")
	}

	decryptedIdentityRequestChallenge, err := privacycaTpm2.GetEkCert(identityChallengePayload, privacycaKey)
	if err != nil{
		return taModel.IdentityProofRequest{}, http.StatusBadRequest, errors.Wrap(err, "controllers/certify_host_aiks_controller:getIdentityProofRequestResponse() unable to get ek cert bytes")
	}
	if _, err := os.Stat(certifyHostAiksController.Store.aikRequestsDirPath); os.IsNotExist(err) {
		errDir := os.MkdirAll(certifyHostAiksController.Store.aikRequestsDirPath, 0600)
		if errDir != nil {
			return taModel.IdentityProofRequest{}, http.StatusInternalServerError, errors.Wrapf(err, "controllers/certify_host_aiks_controller:getIdentityProofRequestResponse() could not create directory %s", certifyHostAiksController.Store.aikRequestsDirPath)
		}
	}

	ekx509Cert, modulus, aikName, err := certifyHostAiksController.GetEkCerts(decryptedIdentityRequestChallenge)
	if err != nil{
		return taModel.IdentityProofRequest{}, http.StatusBadRequest, err
	}

	privacycaTpm2, err = privacyca.NewPrivacyCA(identityChallengePayload.IdentityRequest)
	if err != nil{
		return taModel.IdentityProofRequest{}, http.StatusBadRequest, err
	}

	n := new(big.Int)
	n.SetBytes(modulus)

	aikPubKey := rsa.PublicKey{N: n, E: 65537}

	//TODO make PrivacyCA_ValidityDays as configurable??
	aikCert, err := certifyHostAiksController.CertifyAik(&aikPubKey, aikName, privacycaKey.(*rsa.PrivateKey), privacycaCert, constants.AIKCertValidity)
	if err != nil{
		return taModel.IdentityProofRequest{}, http.StatusInternalServerError, errors.Wrap(err, "controllers/certify_host_aiks_controller:getIdentityProofRequestResponse() Unable to Certify Aik")
	}

	//AES CBC Encryption fails with data that is not divisible aes.BlockSize, Adding padding to make the length of payload multiple of aes.Blocksize
	padding := aes.BlockSize - len(aikCert)%aes.BlockSize
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	withPadding := append(aikCert, padtext...)

	proofReq, err := privacycaTpm2.ProcessIdentityRequest(identityChallengePayload.IdentityRequest, ekx509Cert.PublicKey.(*rsa.PublicKey), withPadding)
	if err != nil{
		defaultLog.WithError(err).Error("")
		return taModel.IdentityProofRequest{}, http.StatusInternalServerError, errors.Wrap(err, "controllers/certify_host_aiks_controller:getIdentityProofRequestResponse() Error while generating identityProofRequest")
	}

	return proofReq, http.StatusCreated, nil
}

func (certifyHostAiksController *CertifyHostAiksController) CertifyAik(aikPubKey *rsa.PublicKey, aikName []byte, privacycaKey *rsa.PrivateKey, privacycaCert *x509.Certificate, validity int) ([]byte, error)  {
	defaultLog.Trace("controllers/certify_host_aiks_controller:CertifyAik() Entering")
	defer defaultLog.Trace("controllers/certify_host_aiks_controller:CertifyAik() Leaving")

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return nil, errors.Wrap(err, "Failed to generate serial number")
	}

	clientCRTTemplate := x509.Certificate{

		Issuer: pkix.Name{
			CommonName: privacycaCert.Issuer.CommonName,
		},
		SerialNumber: serialNumber,
		Subject:      pkix.Name{
			CommonName: "",
		},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().AddDate(validity, 0, 0),
	}

	extSubjectAltName := pkix.Extension{}
	// Oid "2.5.29.17" is for SubjectAlternativeName extension
	extSubjectAltName.Id = asn1.ObjectIdentifier{2, 5, 29, 17}
	extSubjectAltName.Critical = false
	extSubjectAltName.Value = aikName
	clientCRTTemplate.Extensions = []pkix.Extension{extSubjectAltName}

	aikCert, err := x509.CreateCertificate(rand.Reader, &clientCRTTemplate, privacycaCert, aikPubKey, privacycaKey)
	if err != nil{
		return nil, errors.Wrap(err, "Error while Signing and generation Aik Certificate")
	}
	return aikCert, nil
}
