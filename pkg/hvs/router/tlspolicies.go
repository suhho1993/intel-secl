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

// SetTlsPolicyRoutes registers routes for tls policies
func SetTlsPolicyRoutes(router *mux.Router, store *postgres.DataStore) *mux.Router {
	defaultLog.Trace("router/tlspolicies:SetTlsPolicyRoutes() Entering")
	defer defaultLog.Trace("router/tlspolicies:SetTlsPolicyRoutes() Leaving")

	tlsPolicyStore := postgres.NewTlsPolicyStore(store)
	tlsPolicyController := controllers.TlsPolicyController{Store: tlsPolicyStore}

	tlsPolicyIdExpr := fmt.Sprintf("%s%s", "/tls-policies/", validation.IdReg)

	router.Handle("/tls-policies", ErrorHandler(permissionsHandler(ResponseHandler(tlsPolicyController.Create),
		[]string{constants.TlsPolicyCreate}))).Methods("POST")
	router.Handle(tlsPolicyIdExpr, ErrorHandler(permissionsHandler(ResponseHandler(tlsPolicyController.Retrieve),[]string{constants.TlsPolicyRetrieve}))).Methods("GET")
	router.Handle(tlsPolicyIdExpr, ErrorHandler(permissionsHandler(ResponseHandler(tlsPolicyController.Update),[]string{constants.TlsPolicyUpdate}))).Methods("PUT")
	router.Handle(tlsPolicyIdExpr, ErrorHandler(permissionsHandler(ResponseHandler(tlsPolicyController.Delete), []string{constants.TlsPolicyDelete}))).Methods("DELETE")
	router.Handle("/tls-policies", ErrorHandler(permissionsHandler(ResponseHandler(tlsPolicyController.Search),
		[]string{constants.TlsPolicySearch}))).Methods("GET")

	return router
}
