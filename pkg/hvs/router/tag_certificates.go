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
	"github.com/intel-secl/intel-secl/v3/pkg/hvs/domain/models"
	"github.com/intel-secl/intel-secl/v3/pkg/hvs/postgres"
	"github.com/intel-secl/intel-secl/v3/pkg/lib/common/validation"
)

const (
	TagCertificateEndpointPath = "/tag-certificates"
)

// SetTagCertificateRoutes registers routes for tag-certificates API
func SetTagCertificateRoutes(router *mux.Router, certStore *models.CertificatesStore, store *postgres.DataStore) *mux.Router {
	defaultLog.Trace("router/tag_certificates:SetTagCertificateRoutes() Entering")
	defer defaultLog.Trace("router/tag_certificates:SetTagCertificateRoutes() Leaving")

	tagCertificateStore := postgres.NewTagCertificateStore(store)
	tagCertificateController := controllers.NewTagCertificateController(certStore, tagCertificateStore)

	tagCertificateIdExpr := fmt.Sprintf("%s%s", TagCertificateEndpointPath+"/", validation.IdReg)
	router.Handle(TagCertificateEndpointPath,
		ErrorHandler(permissionsHandler(ResponseHandler(tagCertificateController.Create),
			[]string{constants.TagCertificateCreate}))).Methods("POST")

	router.Handle(TagCertificateEndpointPath,
		ErrorHandler(permissionsHandler(ResponseHandler(tagCertificateController.Search),
			[]string{constants.TagCertificateSearch}))).Methods("GET")

	router.Handle(tagCertificateIdExpr,
		ErrorHandler(permissionsHandler(ResponseHandler(tagCertificateController.Delete),
			[]string{constants.TagCertificateDelete}))).Methods("DELETE")

	return router
}
