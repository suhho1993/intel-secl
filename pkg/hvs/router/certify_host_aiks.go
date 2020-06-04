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

func SetCertifyAiksRoutes(router *mux.Router) *mux.Router {
	defaultLog.Trace("router/certify_host_aiks:SetCertifyAiksRoutes() Entering")
	defer defaultLog.Trace("router/certify_host_aiks:SetCertifyAiksRoutes() Leaving")

	certifyHostAiksController := controllers.CertifyHostAiksController{}
	router.Handle("/privacyca/identity-challenge-request", ErrorHandler(permissionsHandler(ResponseHandler(certifyHostAiksController.IdentityRequestGetChallenge),
		[]string{constants.CertifyAik}))).Methods("POST")
	router.Handle("/privacyca/identity-challenge-response", ErrorHandler(permissionsHandler(ResponseHandler(certifyHostAiksController.IdentityRequestSubmitChallengeResponse),
		[]string{constants.CertifyAik}))).Methods("POST")
	return router
}
