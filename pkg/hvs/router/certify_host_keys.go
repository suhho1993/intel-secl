/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */

package router

import (
	"github.com/gorilla/mux"
	consts "github.com/intel-secl/intel-secl/v3/pkg/hvs/constants"
	"github.com/intel-secl/intel-secl/v3/pkg/hvs/controllers"
	"github.com/intel-secl/intel-secl/v3/pkg/hvs/postgres"
)

func SetCertifyHostKeysRoutes(router *mux.Router) *mux.Router {
	defaultLog.Trace("router/certify_host_keys:SetCertifyHostKeys() Entering")
	defer defaultLog.Trace("router/certify_host_keys:SetCertifyHostKeys() Leaving")

	fStore := controllers.NewPrivacyCAFileStore(consts.PrivacyCAKeyFile, consts.PrivacyCACertFile, consts.EndorsementCACertFile, consts.AikRequestsDir)
	certifyHostKeysController := controllers.CertifyHostKeysController{Store: fStore}

	router.HandleFunc("/rpc/certify-host-signing-key", ErrorHandler(permissionsHandler(ResponseHandler(certifyHostKeysController.CertifySigningKey), []string{consts.CertifyHostSigningKey}))).Methods("POST")
	router.HandleFunc("/rpc/certify-host-binding-key", ErrorHandler(permissionsHandler(ResponseHandler(certifyHostKeysController.CertifyBindingKey), []string{consts.CertifyHostSigningKey}))).Methods("POST")
	return router
}

func SetCertifyAiksRoutes(router *mux.Router, store *postgres.DataStore) *mux.Router {
	defaultLog.Trace("router/certify_host_aiks:SetCertifyAiksRoutes() Entering")
	defer defaultLog.Trace("router/certify_host_aiks:SetCertifyAiksRoutes() Leaving")

	tpmEndorsementStore := postgres.NewTpmEndorsementStore(store)
	fStore := controllers.NewPrivacyCAFileStore(consts.PrivacyCAKeyFile, consts.PrivacyCACertFile, consts.EndorsementCACertFile, consts.AikRequestsDir)

	certifyHostAiksController := controllers.NewCertifyHostAiksController(fStore, tpmEndorsementStore)
	router.Handle("/privacyca/identity-challenge-request", ErrorHandler(permissionsHandler(ResponseHandler(certifyHostAiksController.IdentityRequestGetChallenge),
		[]string{consts.CertifyAik}))).Methods("POST")
	router.Handle("/privacyca/identity-challenge-response", ErrorHandler(permissionsHandler(ResponseHandler(certifyHostAiksController.IdentityRequestSubmitChallengeResponse),
		[]string{consts.CertifyAik}))).Methods("POST")
	return router
}