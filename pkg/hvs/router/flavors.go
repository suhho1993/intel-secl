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

// SetFlavorRoutes registers routes for flavors
func SetFlavorRoutes(router *mux.Router, store *postgres.DataStore) *mux.Router {
	defaultLog.Trace("router/flavors:SetFlavorRoutes() Entering")
	defer defaultLog.Trace("router/flavors:SetFlavorRoutes() Leaving")

	flavorStore := postgres.NewFlavorStore(store)
	flavorController := controllers.FlavorController{Store: flavorStore}
	flavorIdExpr := fmt.Sprintf("%s%s", "/flavors/", validation.IdReg)

	router.Handle("/flavors",
		ErrorHandler(permissionsHandler(ResponseHandler(flavorController.Create),
			[]string{constants.FlavorCreate}))).Methods("POST")

	router.Handle("/flavors",
		ErrorHandler(permissionsHandler(ResponseHandler(flavorController.Search),
			[]string{constants.FlavorSearch}))).Methods("GET")

	router.Handle(flavorIdExpr,
		ErrorHandler(permissionsHandler(ResponseHandler(flavorController.Delete),
			[]string{constants.FlavorDelete}))).Methods("DELETE")

	router.Handle(flavorIdExpr,
		ErrorHandler(permissionsHandler(ResponseHandler(flavorController.Retrieve),
			[]string{constants.FlavorRetrieve}))).Methods("GET")

	return router
}
