/*
* Copyright (C) 2020 Intel Corporation
* SPDX-License-Identifier: BSD-3-Clause
 */
package mocks

import (
	"github.com/intel-secl/intel-secl/v3/pkg/hvs/domain/models"
)

func NewFakeCertificatesPathStore() *models.CertificatesPathStore {
	// For ECA, to read list of certificates from directory
	ecCaPath := "../controllers/mocks/"
	// Mock path to create new certificate
	rootCaPath := "../controllers/mocks/"
	//Path for any certificate containing file, so instead of creating new use existing one
	caCertPath := "../controllers/mocks/EndorsementCA-external.pem"

	return &models.CertificatesPathStore{
		models.CaCertTypesRootCa.String(): models.CertLocation{
			CertPath: rootCaPath,
		},
		models.CaCertTypesEndorsementCa.String(): models.CertLocation{
			CertPath: ecCaPath,
		},
		models.CaCertTypesPrivacyCa.String(): models.CertLocation{
			CertPath: caCertPath,
		},
		models.CaCertTypesTagCa.String(): models.CertLocation{
			CertPath: caCertPath,
		},
		models.CertTypesSaml.String(): models.CertLocation{
			CertPath: caCertPath,
		},
		models.CertTypesTls.String(): models.CertLocation{
			CertPath: caCertPath,
		},
	}
}

func NewFakeCertificatesStore() *models.CertificatesStore {
	// For ECA, to read list of certificates from directory
	ecCaPath := "../controllers/mocks/"
	// Mock path to create new certificate
	rootCaPath := "../controllers/mocks/"
	//Path for any certificate containing file, so instead of creating new use existing one
	caCertPath := "../controllers/mocks/EndorsementCA-external.pem"

	return &models.CertificatesStore{
		models.CaCertTypesRootCa.String(): &models.CertificateStore{
			Key:          nil,
			CertPath:     rootCaPath,
			Certificates: nil,
		},
		models.CaCertTypesEndorsementCa.String(): &models.CertificateStore{
			Key:          nil,
			CertPath:     ecCaPath,
			Certificates: nil,
		},
		models.CaCertTypesPrivacyCa.String(): &models.CertificateStore{
			Key:          nil,
			CertPath:     caCertPath,
			Certificates: nil,
		},
		models.CaCertTypesTagCa.String(): &models.CertificateStore{
			Key:          nil,
			CertPath:     caCertPath,
			Certificates: nil,
		},
		models.CertTypesSaml.String(): &models.CertificateStore{
			Key:          nil,
			CertPath:     caCertPath,
			Certificates: nil,
		},
		models.CertTypesTls.String(): &models.CertificateStore{
			Key:          nil,
			CertPath:     caCertPath,
			Certificates: nil,
		},
	}
}
