/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */

package controllers

import (
	"encoding/pem"
	"github.com/intel-secl/intel-secl/v3/pkg/hvs/constants"
	"io/ioutil"
	"net/http"
)

type CaCertificatesController struct {
}

func (caCertificatesController CaCertificatesController) GetPrivacyCACert() http.HandlerFunc {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defaultLog.Trace("controllers/ca_certificates_controller:getPrivacyCACert() Entering")
		defer defaultLog.Trace("controllers/ca_certificates_controller:getPrivacyCACert() Leaving")

		privacyCACert, err := ioutil.ReadFile(constants.CertPath)
		if err != nil{
			defaultLog.WithError(err).Errorf("%s not found", constants.CertPath)
			w.WriteHeader(http.StatusNotFound)

		}

		encodedCert, _ := pem.Decode(privacyCACert)
		if encodedCert == nil{
			defaultLog.WithError(err).Error("Error while decoding Privacyca cert")
			w.WriteHeader(http.StatusInternalServerError)

		}

		w.Write(encodedCert.Bytes)
		w.WriteHeader(http.StatusOK)
		})
}