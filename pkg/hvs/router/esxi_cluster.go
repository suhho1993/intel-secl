/*
 *  Copyright (C) 2020 Intel Corporation
 *  SPDX-License-Identifier: BSD-3-Clause
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

// SetESXiClusterRoutes registers routes for esxi cluster apis
func SetESXiClusterRoutes(router *mux.Router, store *postgres.DataStore) *mux.Router {
	defaultLog.Trace("router/esxi_cluster:SetESXiClusterRoutes() Entering")
	defer defaultLog.Trace("router/esxi_cluster:SetESXiClusterRoutes() Leaving")

	esxiClusterStore := postgres.NewESXiCLusterStore(store)
	esxiClusterController := controllers.NewESXiClusterController(esxiClusterStore)

	esxiClusterIdExpr := fmt.Sprintf("%s%s", "/esxi-cluster/", validation.IdReg)

	router.Handle("/esxi-cluster",
		ErrorHandler(permissionsHandler(ResponseHandler(esxiClusterController.Create),
			[]string{constants.ESXiClusterCreate}))).Methods("POST")

	router.Handle("/esxi-cluster",
		ErrorHandler(permissionsHandler(ResponseHandler(esxiClusterController.Search),
			[]string{constants.ESXiClusterSearch}))).Methods("GET")

	router.Handle(esxiClusterIdExpr,
		ErrorHandler(permissionsHandler(ResponseHandler(esxiClusterController.Delete),
			[]string{constants.ESXiClusterDelete}))).Methods("DELETE")

	router.Handle(esxiClusterIdExpr,
		ErrorHandler(permissionsHandler(ResponseHandler(esxiClusterController.Retrieve),
			[]string{constants.ESXiClusterRetrieve}))).Methods("GET")

	return router
}
