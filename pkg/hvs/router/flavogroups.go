/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package router

import (
	"github.com/gorilla/mux"
	"github.com/intel-secl/intel-secl/v3/pkg/hvs/constants"
	"github.com/intel-secl/intel-secl/v3/pkg/hvs/controllers"
	"github.com/intel-secl/intel-secl/v3/pkg/hvs/postgres"
)

// SetFlavorGroupRoutes registers routes for flavorgroups
func SetFlavorGroupRoutes(router *mux.Router, store *postgres.DataStore) *mux.Router {
	defaultLog.Trace("router/flavorgroups:SetFlavorGroupRoutes() Entering")
	defer defaultLog.Trace("router/flavorgroups:SetFlavorGroupRoutes() Leaving")

	flavorgroupStore := postgres.NewFlavorGroupStore(store)
	flavorgroupController := controllers.FlavorgroupController{Store: flavorgroupStore}

	router.Handle("/flavorgroups",
		ErrorHandler(permissionsHandler(ResponseHandler(flavorgroupController.Create),
			[]string{constants.FlavorGroupCreate}))).Methods("POST")

	router.Handle("/flavorgroups",
		ErrorHandler(permissionsHandler(ResponseHandler(flavorgroupController.Search),
			[]string{constants.FlavorGroupSearch}))).Methods("GET")

	//TODO: Add regex for validation
	router.Handle("/flavorgroups/{id}",
		ErrorHandler(permissionsHandler(ResponseHandler(flavorgroupController.Delete),
			[]string{constants.FlavorGroupDelete}))).Methods("DELETE")

	router.Handle("/flavorgroups/{id}",
		ErrorHandler(permissionsHandler(ResponseHandler(flavorgroupController.Retrieve),
			[]string{constants.FlavorGroupRetrieve}))).Methods("GET")

	return router
}
