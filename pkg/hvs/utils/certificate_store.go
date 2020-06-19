/*
* Copyright (C) 2020 Intel Corporation
* SPDX-License-Identifier: BSD-3-Clause
 */
package utils

import (
	"crypto"
	"crypto/x509"
	"github.com/intel-secl/intel-secl/v3/pkg/hvs/domain/models"
	"github.com/intel-secl/intel-secl/v3/pkg/lib/common/crypt"
	"io/ioutil"
)

func LoadCertificates(certificatePaths *models.CertificatesPathStore) *models.CertificatesStore {
	defaultLog.Trace("utils/certificate_store:LoadCertificates() Entering")
	defer defaultLog.Trace("utils/certificate_store:LoadCertificates() Leaving")

	certificateStore := make(models.CertificatesStore)
	for _, certType := range models.GetUniqueCertTypes()  {
		certloc := (*certificatePaths)[certType]
		if certType == models.CaCertTypesRootCa.String() || certType == models.CaCertTypesEndorsementCa.String() {
			certificateStore[certType] = loadCertificatesFromDir(&certloc)
		} else {
			certificateStore[certType] = loadCertificatesFromFile(&certloc)
		}
	}
	defaultLog.Debug("Loaded certificates")
	for _, certType := range models.GetUniqueCertTypes()  {
		defaultLog.Debugf("Certificates loaded for type - %s", certType)
		certStore := certificateStore[certType]
		for name, _ := range certStore.Certificates {
			defaultLog.Debugf("Certificate CN - %s", name)
		}
	}
	return &certificateStore
}

func loadCertificatesFromFile(certLocation *models.CertLocation) *models.CertificateStore {
	defaultLog.Trace("utils/certificate_store:loadCertificatesFromFile() Entering")
	defer defaultLog.Trace("utils/certificate_store:loadCertificatesFromFile() Leaving")

	certs, err := crypt.GetSubjectCertsMapFromPemFile(certLocation.CertPath)
	if err != nil {
		defaultLog.WithError(err).Errorf("utils/certificate_store:loadCertificatesFromFile() Error while reading certs from file - " + certLocation.CertPath)
	}

	key := loadKey(certLocation.KeyFile)
	return &models.CertificateStore{
		Key:          &key,
		CertPath:     certLocation.CertPath,
		Certificates: certs,
	}
}

func loadCertificatesFromDir(certLocation *models.CertLocation) *models.CertificateStore {
	defaultLog.Trace("utils/certificate_store:loadCertificatesFromDir() Entering")
	defer defaultLog.Trace("utils/certificate_store:loadCertificatesFromDir() Leaving")

	files, err := ioutil.ReadDir(certLocation.CertPath)
	if err != nil {
		defaultLog.WithError(err).Errorf("utils/certificate_store:loadCertificatesFromDir() Error while reading certs from dir - " + certLocation.CertPath)
		return nil
	}
	certificates := make(map[string]x509.Certificate)
	for _, certFile := range files {
		certFilePath := certLocation.CertPath + certFile.Name()
		certs, err := crypt.GetSubjectCertsMapFromPemFile(certFilePath)
		if err != nil {
			defaultLog.WithError(err).Errorf("utils/certificate_store:loadCertificatesFromDir() Error while reading certs from dir - " + certFilePath)
		}
		for k, v := range certs {
			certificates[k] = v
		}
	}

	key := loadKey(certLocation.KeyFile)
	return &models.CertificateStore{
		Key:          &key,
		CertPath:     certLocation.CertPath,
		Certificates: certificates,
	}
}

func loadKey(keyFile string) crypto.PrivateKey {
	defaultLog.Trace("utils/certificate_store:loadKey() Entering")
	defer defaultLog.Trace("utils/certificate_store:loadKey() Leaving")

	if keyFile == "" {
		return nil
	}
	key, err := crypt.GetPrivateKeyFromPKCS8File(keyFile)
	if err != nil {
		defaultLog.WithError(err).Errorf("utils/certificate_store:loadKey() Error while reading key from file - " + keyFile)
	}
	return &key
}