/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package router

import (
	"fmt"
	"github.com/gorilla/mux"
	"github.com/intel-secl/intel-secl/v3/pkg/hvs/constants"
	"github.com/intel-secl/intel-secl/v3/pkg/hvs/controllers"
	"github.com/intel-secl/intel-secl/v3/pkg/hvs/postgres"
	"github.com/intel-secl/intel-secl/v3/pkg/lib/common/validation"
)

// SetHostRoutes registers routes for hosts
func SetHostRoutes(router *mux.Router, store *postgres.DataStore, dek []byte) *mux.Router {
	defaultLog.Trace("router/hosts:SetHostRoutes() Entering")
	defer defaultLog.Trace("router/hosts:SetHostRoutes() Leaving")

	hostStore := postgres.NewHostStore(store)
	reportStore := postgres.NewReportStore(store)
	hostStatusStore := postgres.NewHostStatusStore(store)
	flavorGroupStore := postgres.NewFlavorGroupStore(store)
	hostCredentialStore := postgres.NewHostCredentialStore(store, dek)
	hostController := controllers.NewHostController(hostStore, reportStore, hostStatusStore, flavorGroupStore, hostCredentialStore)

	hostIdExpr := fmt.Sprintf("%s%s", "/hosts/", validation.IdReg)

	router.Handle("/hosts", ErrorHandler(permissionsHandler(ResponseHandler(hostController.Create),
		[]string{constants.HostCreate}))).Methods("POST")
	router.Handle(hostIdExpr, ErrorHandler(permissionsHandler(ResponseHandler(hostController.Retrieve),
		[]string{constants.HostRetrieve}))).Methods("GET")
	router.Handle(hostIdExpr, ErrorHandler(permissionsHandler(ResponseHandler(hostController.Update),
		[]string{constants.HostUpdate}))).Methods("PUT")
	router.Handle(hostIdExpr, ErrorHandler(permissionsHandler(ResponseHandler(hostController.Delete),
		[]string{constants.HostDelete}))).Methods("DELETE")
	router.Handle("/hosts", ErrorHandler(permissionsHandler(ResponseHandler(hostController.Search),
		[]string{constants.HostSearch}))).Methods("GET")

	return router
}
