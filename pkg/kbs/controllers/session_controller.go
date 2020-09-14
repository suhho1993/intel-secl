/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package controllers

import (
	"encoding/json"
	"net/http"

	"github.com/intel-secl/intel-secl/v3/pkg/kbs/constants"
	commErr "github.com/intel-secl/intel-secl/v3/pkg/lib/common/err"
	commLogMsg "github.com/intel-secl/intel-secl/v3/pkg/lib/common/log/message"
	"github.com/intel-secl/intel-secl/v3/pkg/model/kbs"
	"github.com/pkg/errors"
)

type SessionController struct {
}

func NewSessionController() *SessionController {
	return &SessionController{}
}

func (sc *SessionController) Create(responseWriter http.ResponseWriter, request *http.Request) (interface{}, int, error) {
	defaultLog.Trace("controllers/session_controller:Create() Entering")
	defer defaultLog.Trace("controllers/session_controller:Create() Leaving")

	if request.Header.Get("Content-Type") != constants.HTTPMediaTypeJson {
		return nil, http.StatusUnsupportedMediaType, &commErr.ResourceError{Message: "Invalid Content-Type"}
	}

	if request.ContentLength == 0 {
		secLog.Error("controllers/session_controller:Create() The request body was not provided")
		return nil, http.StatusBadRequest, &commErr.ResourceError{Message: "The request body was not provided"}
	}

	var sessionRequest kbs.SessionManagementAttributes
	// Decode the incoming json data to note struct
	dec := json.NewDecoder(request.Body)
	dec.DisallowUnknownFields()

	err := dec.Decode(&sessionRequest)
	if err != nil {
		secLog.WithError(err).Errorf("controllers/session_controller:Create() %s : Failed to decode request body as SessionManagementAttributes", commLogMsg.InvalidInputBadEncoding)
		return nil, http.StatusBadRequest, &commErr.ResourceError{Message: "Unable to decode JSON request body"}
	}

	err = validateSessionCreateRequest(sessionRequest)
	if err != nil {
		defaultLog.WithError(err).Error("controllers/session_controller:Create() Invalid create request")
		return nil, http.StatusBadRequest, &commErr.ResourceError{Message: err.Error()}
	}

	// TODO: implement pending flows

	return nil, http.StatusCreated, nil
}

func validateSessionCreateRequest(sessionRequest kbs.SessionManagementAttributes) error {
	defaultLog.Trace("controllers/session_controller:validateSessionCreateRequest() Entering")
	defer defaultLog.Trace("controllers/session_controller:validateSessionCreateRequest() Leaving")

	if sessionRequest.ChallengeType == "" || sessionRequest.Challenge == "" || sessionRequest.Quote == "" {
		return errors.New("challenge_type/challenge/quote parameters are missing")
	}

	// TODO: Add validation for input data

	return nil
}
