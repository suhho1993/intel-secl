/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */

package router

import (
	"github.com/gorilla/mux"
	"github.com/intel-secl/intel-secl/v3/pkg/hvs/constants"
	"github.com/intel-secl/intel-secl/v3/pkg/hvs/controllers"
)

func SetCaCertificatesRoutes(router *mux.Router) *mux.Router {
	defaultLog.Trace("router/ca_certificates:SetCaCertificatesRoutes() Entering")
	defer defaultLog.Trace("router/ca_certificates:SetCaCertificatesRoutes() Leaving")
	caFileStore := controllers.NewCAFileStore(
		constants.TrustedRootCACertsDir,
		constants.PrivacyCACertFile,
		constants.EndorsementCaCertFile,
		constants.SAMLCertFile,
		constants.DefaultTLSCertFile,
	)
	caCertController := controllers.CaCertificatesController{caFileStore}

	router.Handle("/ca-certificates", ErrorHandler(ResponseHandler(caCertController.Create))).Methods("POST")
	router.Handle("/ca-certificates/{certType}", ErrorHandler(ResponseHandler(caCertController.Retrieve))).Methods("GET")
	router.Handle("/ca-certificates", ErrorHandler(ResponseHandler(caCertController.Search))).Methods("GET")
	return router
}
