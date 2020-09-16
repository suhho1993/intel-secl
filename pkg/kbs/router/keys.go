/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package router

import (
	"github.com/gorilla/mux"
	"github.com/intel-secl/intel-secl/v3/pkg/kbs/constants"
	"github.com/intel-secl/intel-secl/v3/pkg/kbs/controllers"
	"github.com/intel-secl/intel-secl/v3/pkg/kbs/directory"
	"github.com/intel-secl/intel-secl/v3/pkg/kbs/domain"
	"github.com/intel-secl/intel-secl/v3/pkg/kbs/keymanager"
	consts "github.com/intel-secl/intel-secl/v3/pkg/lib/common/constants"
	"github.com/intel-secl/intel-secl/v3/pkg/lib/common/validation"
)

//setKeyRoutes registers routes to perform Key CRUD operations
func setKeyRoutes(router *mux.Router, endpointUrl string, config domain.KeyControllerConfig, keyManager keymanager.KeyManager) *mux.Router {
	defaultLog.Trace("router/keys:setKeyRoutes() Entering")
	defer defaultLog.Trace("router/keys:setKeyRoutes() Leaving")

	keyStore := directory.NewKeyStore(constants.KeysDir)
	policyStore := directory.NewKeyTransferPolicyStore(constants.KeysTransferPolicyDir)
	remoteManager := keymanager.NewRemoteManager(keyStore, keyManager, endpointUrl)
	keyController := controllers.NewKeyController(remoteManager, policyStore, config)
	keyIdExpr := "/keys/" + validation.IdReg

	router.Handle("/keys",
		ErrorHandler(permissionsHandler(JsonResponseHandler(keyController.Create),
			[]string{constants.KeyCreate, constants.KeyRegister}))).Methods("POST")

	router.Handle(keyIdExpr,
		ErrorHandler(permissionsHandler(JsonResponseHandler(keyController.Retrieve),
			[]string{constants.KeyRetrieve}))).Methods("GET")

	router.Handle(keyIdExpr,
		ErrorHandler(permissionsHandler(JsonResponseHandler(keyController.Delete),
			[]string{constants.KeyDelete}))).Methods("DELETE")

	router.Handle("/keys",
		ErrorHandler(permissionsHandler(JsonResponseHandler(keyController.Search),
			[]string{constants.KeySearch}))).Methods("GET")

	router.Handle(keyIdExpr+"/transfer",
		ErrorHandler(permissionsHandler(JsonResponseHandler(keyController.Transfer),
			[]string{constants.KeyTransfer}))).Methods("POST")

	return router
}

//setKeyTransferRoutes registers routes to perform Key Transfer operations
func setKeyTransferRoutes(router *mux.Router, endpointUrl string, config domain.KeyControllerConfig, keyManager keymanager.KeyManager) *mux.Router {
	defaultLog.Trace("router/keys:setKeyTransferRoutes() Entering")
	defer defaultLog.Trace("router/keys:setKeyTransferRoutes() Leaving")

	keyStore := directory.NewKeyStore(constants.KeysDir)
	policyStore := directory.NewKeyTransferPolicyStore(constants.KeysTransferPolicyDir)
	remoteManager := keymanager.NewRemoteManager(keyStore, keyManager, endpointUrl)
	keyController := controllers.NewKeyController(remoteManager, policyStore, config)
	keyIdExpr := "/keys/" + validation.IdReg

	router.Handle(keyIdExpr+"/transfer",
		ErrorHandler(ResponseHandler(keyController.TransferWithSaml),
		)).Methods("POST").Headers("Accept", consts.HTTPMediaTypeOctetStream)

	return router
}

//setDhsm2KeyTransferRoutes registers routes to perform Dhsm2 Transfer operations
func setDhsm2KeyTransferRoutes(router *mux.Router) *mux.Router {
	defaultLog.Trace("router/keys:setDhsm2KeyTransferRoutes() Entering")
	defer defaultLog.Trace("router/keys:setDhsm2KeyTransferRoutes() Leaving")

	dhsm2Controller := controllers.NewDhsm2Controller()
	keyIdExpr := "/keys/" + validation.IdReg

	router.Handle(keyIdExpr+"/dhsm2-transfer",
		ErrorHandler(permissionsHandler(JsonResponseHandler(dhsm2Controller.TransferApplicationKey),
			[]string{constants.KeyTransfer}))).Methods("GET")

	return router
}
