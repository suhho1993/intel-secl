/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package controllers

import (
	"net/http"

	commErr "github.com/intel-secl/intel-secl/v3/pkg/lib/common/err"
	"github.com/pkg/errors"
)

type Dhsm2Controller struct {
}

func NewDhsm2Controller() *Dhsm2Controller {
	return &Dhsm2Controller{}
}

func (sc *Dhsm2Controller) TransferApplicationKey(responseWriter http.ResponseWriter, request *http.Request) (interface{}, int, error) {
	defaultLog.Trace("controllers/dhsm2_controller:TransferApplicationKey() Entering")
	defer defaultLog.Trace("controllers/dhsm2_controller:TransferApplicationKey() Leaving")

	err := validateKeyTransferRequest(request.Header)
	if err != nil {
		secLog.WithError(err).Error("controllers/dhsm2_controller:TransferApplicationKey() Invalid transfer request")
		return nil, http.StatusBadRequest, &commErr.ResourceError{Message: err.Error()}
	}

	// TODO: implement pending flows

	return nil, http.StatusOK, nil
}

func validateKeyTransferRequest(header http.Header) error {
	defaultLog.Trace("controllers/dhsm2_controller:validateKeyTransferRequest() Entering")
	defer defaultLog.Trace("controllers/dhsm2_controller:validateKeyTransferRequest() Leaving")

	acceptChallenge := header.Values("Accept-Challenge")
	if acceptChallenge == nil {
		return errors.New("Accept-Challenge header is missing in request")
	}

	if len(acceptChallenge) == 0 {
		return errors.New("Accept-Challenge cannot be empty")
	}

	sessionID := header.Values("Session-ID")
	if sessionID != nil && len(sessionID) == 0 {
		return errors.New("Session-ID cannot be empty")
	}

	// TODO: Add validation for input data

	return nil
}
