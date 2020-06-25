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
	ecCaPath := "../dist/linux/"
	// Mock path to create new certificate
	rootCaPath := "../controllers/mocks/"
	//Path for any certificate containing file, so instead of creating new use existing one
	caCertPath := "../dist/linux/EndorsementCA-external.pem"

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

