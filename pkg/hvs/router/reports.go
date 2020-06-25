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

// SetReportRoutes registers routes for reports
func SetReportRoutes(router *mux.Router, store *postgres.DataStore) *mux.Router {
	defaultLog.Trace("router/reports:SetReportRoutes() Entering")
	defer defaultLog.Trace("router/reports:SetReportRoutes() Leaving")

	reportStore := postgres.NewReportStore(store)
	reportController := controllers.NewReportController(reportStore)

	reportIdExpr := fmt.Sprintf("%s%s", "/reports/", validation.IdReg)
	router.Handle("/reports",
		ErrorHandler(permissionsHandler(ResponseHandler(reportController.Create),
			[]string{constants.ReportCreate}))).Methods("POST")

	router.Handle(reportIdExpr,
		ErrorHandler(permissionsHandler(ResponseHandler(reportController.Retrieve),
			[]string{constants.ReportRetrieve}))).Methods("GET")

	router.Handle("/reports",
		ErrorHandler(permissionsHandler(ResponseHandler(reportController.Search),
			[]string{constants.ReportSearch}))).Methods("GET")

	return router
}
