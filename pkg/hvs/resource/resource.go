/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package resource

import (
	"fmt"
	constants "github.com/intel-secl/intel-secl/v3/pkg/hvs/constants"
	comctx "github.com/intel-secl/intel-secl/v3/pkg/lib/common/context"
	"github.com/intel-secl/intel-secl/v3/pkg/lib/common/log"
	"github.com/pkg/errors"

	"github.com/intel-secl/intel-secl/v3/pkg/lib/common/auth"
	ct "github.com/intel-secl/intel-secl/v3/pkg/lib/common/types/aas"
	"net/http"

	"github.com/jinzhu/gorm"

	commLogMsg "github.com/intel-secl/intel-secl/v3/pkg/lib/common/log/message"
)

var defaultLog = log.GetDefaultLogger()
var secLog = log.GetSecurityLogger()

type errorHandlerFunc func(w http.ResponseWriter, r *http.Request) error

func (ehf errorHandlerFunc) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	defaultLog.Trace("resource/resource:ServeHTTP() Entering")
	defer defaultLog.Trace("resource/resource:ServeHTTP() Leaving")

	if err := ehf(w, r); err != nil {
		secLog.WithError(err).Warning(commLogMsg.InvalidInputProtocolViolation)
		if gorm.IsRecordNotFoundError(err) {
			http.Error(w, err.Error(), http.StatusNotFound)
			return
		}
		switch t := err.(type) {
		case *resourceError:
			defaultLog.WithError(err).Warningf("resource error")
			http.Error(w, t.Message, t.StatusCode)
		case resourceError:
			defaultLog.WithError(err).Warningf("resource error")
			http.Error(w, t.Message, t.StatusCode)
		case *privilegeError:
			http.Error(w, t.Message, t.StatusCode)
		case privilegeError:
			http.Error(w, t.Message, t.StatusCode)
		default:
			defaultLog.WithError(err)
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
	}
}

type privilegeError struct {
	StatusCode int
	Message    string
}

func (e privilegeError) Error() string {
	defaultLog.Trace("resource/resource:Error() Entering")
	defer defaultLog.Trace("resource/resource:Error() Leaving")
	return fmt.Sprintf("%d: %s", e.StatusCode, e.Message)
}

type resourceError struct {
	StatusCode int
	Message    string
}

func (e resourceError) Error() string {
	defaultLog.Trace("resource/resource:Error() Entering")
	defer defaultLog.Trace("resource/resource:Error() Leaving")
	return fmt.Sprintf("%d: %s", e.StatusCode, e.Message)
}


type endpointError struct {
	Message    string
	StatusCode int
}
func (e endpointError) Error() string {
	defaultLog.Trace("resource/resource:Error() Entering")
	defer defaultLog.Trace("resource/resource:Error() Leaving")
	return fmt.Sprintf("%d: %s", e.StatusCode, e.Message)
}

func requiresPermission(eh endpointHandler, permissionNames []string) endpointHandler {
	defaultLog.Trace("resource/resource:requiresPermission() Entering")
	defer defaultLog.Trace("resource/resource:requiresPermission() Leaving")
	return func(w http.ResponseWriter, r *http.Request) error {
		privileges, err := comctx.GetUserPermissions(r)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte("Could not get user permissions from http context"))
			secLog.Errorf("resource/resource:requiresPermission() %s Permission: %v | Context: %v", commLogMsg.AuthenticationFailed, permissionNames, r.Context())
			return errors.Wrap(err, "resource/resource:requiresPermission() Could not get user permissions from http context")
		}
		reqPermissions := ct.PermissionInfo{Service: constants.ServiceName, Rules: permissionNames}

		_, foundMatchingPermission := auth.ValidatePermissionAndGetPermissionsContext(privileges, reqPermissions,
			true)
		if !foundMatchingPermission {
			w.WriteHeader(http.StatusUnauthorized)
			secLog.Error(commLogMsg.UnauthorizedAccess)
			secLog.Errorf("resource/resource:requiresPermission() %s Insufficient privileges to access %s", commLogMsg.UnauthorizedAccess, r.RequestURI)
			return &privilegeError{Message: "Insufficient privileges to access " + r.RequestURI, StatusCode: http.StatusUnauthorized}
		}
		secLog.Infof("resource/resource:requiresPermission() %s - %s", commLogMsg.AuthorizedAccess, r.RequestURI)
		return eh(w, r)
	}
}

// endpointHandler is the same as http.ResponseHandler, but returns an error that can be handled by a generic
// middleware handler
type endpointHandler func(w http.ResponseWriter, r *http.Request) error

func errorHandler(eh endpointHandler) http.HandlerFunc {
	defaultLog.Trace("resource/resource:errorHandler() Entering")
	defer defaultLog.Trace("resource/resource:errorHandler() Leaving")
	return func(w http.ResponseWriter, r *http.Request) {
		if err := eh(w, r); err != nil {
			if gorm.IsRecordNotFoundError(err) {
				http.Error(w, err.Error(), http.StatusNotFound)
				return
			}
			switch t := err.(type) {
			case *endpointError:
				http.Error(w, t.Message, t.StatusCode)
			case privilegeError:
				http.Error(w, t.Message, t.StatusCode)
			default:
				http.Error(w, err.Error(), http.StatusInternalServerError)
			}
		}
	}
}
