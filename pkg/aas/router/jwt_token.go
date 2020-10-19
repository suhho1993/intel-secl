/*
 *  Copyright (C) 2020 Intel Corporation
 *  SPDX-License-Identifier: BSD-3-Clause
 */

package router

import (
	"github.com/gorilla/mux"
	"github.com/intel-secl/intel-secl/v3/pkg/aas/controllers"
	"github.com/intel-secl/intel-secl/v3/pkg/aas/domain"
	jwtauth "github.com/intel-secl/intel-secl/v3/pkg/lib/common/jwt"
)

func SetJwtTokenRoutes(r *mux.Router, db domain.AASDatabase, tokFactory *jwtauth.JwtFactory) *mux.Router {
	defaultLog.Trace("router/jwt_certificate:SetJwtCertificateRoutes() Entering")
	defer defaultLog.Trace("router/jwt_certificate:SetJwtCertificateRoutes() Leaving")

	controller := controllers.JwtTokenController{
		Database:     db,
		TokenFactory: tokFactory,
	}
	r.Handle("/token", ErrorHandler(ResponseHandler(controller.CreateJwtToken, "application/jwt"))).Methods("POST")
	return r
}
