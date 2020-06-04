/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */

package router

import (
	"github.com/gorilla/mux"
	"github.com/intel-secl/intel-secl/v3/pkg/hvs/controllers"
)

func SetCaCertificatesRoutes(router *mux.Router) *mux.Router{
	defaultLog.Trace("router/ca_certificates:SetCaCertificatesRoutes() Entering")
	defer defaultLog.Trace("router/ca_certificates:SetCaCertificatesRoutes() Leaving")
	caCertController := controllers.CaCertificatesController{}

	router.Handle("/ca-certificates/privacy", (caCertController.GetPrivacyCACert())).Methods("GET")
	return router
}

