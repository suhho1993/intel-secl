/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package router

import (
	"encoding/json"
	"encoding/xml"
	"github.com/intel-secl/intel-secl/v3/pkg/hvs/constants"
	"github.com/intel-secl/intel-secl/v3/pkg/lib/common/auth"
	comctx "github.com/intel-secl/intel-secl/v3/pkg/lib/common/context"
	commErr "github.com/intel-secl/intel-secl/v3/pkg/lib/common/err"
	commLogMsg "github.com/intel-secl/intel-secl/v3/pkg/lib/common/log/message"
	ct "github.com/intel-secl/intel-secl/v3/pkg/lib/common/types/aas"
	"github.com/jinzhu/gorm"
	"github.com/pkg/errors"
	"net/http"
)

// endpointHandler is the same as http.ResponseHandler, but returns an error that can be handled by a generic
// middleware handler
type endpointHandler func(w http.ResponseWriter, r *http.Request) error

// Generic handler for writing response header and body for all handler functions
func ResponseHandler(h func(http.ResponseWriter, *http.Request) (interface{}, int, error)) endpointHandler {
	defaultLog.Trace("router/handlers:ResponseHandler() Entering")
	defer defaultLog.Trace("router/handlers:ResponseHandler() Leaving")

	return func(w http.ResponseWriter, r *http.Request) error {
		data, status, err := h(w, r) // execute application handler
		if err != nil {
			switch t := err.(type) {
			case *commErr.EndpointError:
				err = &commErr.HandledError{StatusCode: status, Message: t.Message}
			case *commErr.ResourceError:
				err = &commErr.HandledError{StatusCode: status, Message: t.Message}
			case *commErr.PrivilegeError:
				err = &commErr.HandledError{StatusCode: status, Message: t.Message}
			}
			return err
		}
		w.Header().Set("Content-Type", constants.HTTPMediaTypeJson)
		w.WriteHeader(status)
		if data != nil {
			// Send JSON response back to the client application
			err = json.NewEncoder(w).Encode(data)
			if err != nil {
				defaultLog.WithError(err).Errorf("Error from Handler: %s\n", err.Error())
				secLog.WithError(err).Errorf("Error from Handler: %s\n", err.Error())
			}
		}
		return nil
	}
}

// SamlAssertionResponseHandler handler for writing response header and body for all handler functions that produces saml assertion
func SamlAssertionResponseHandler(h func(http.ResponseWriter, *http.Request) (interface{}, int, error)) endpointHandler {
	defaultLog.Trace("router/handlers:SamlAssertionResponseHandler() Entering")
	defer defaultLog.Trace("router/handlers:SamlAssertionResponseHandler() Leaving")

	return func(w http.ResponseWriter, r *http.Request) error {
		data, status, err := h(w, r) // execute application handler
		if err != nil {
			switch t := err.(type) {
			case *commErr.EndpointError:
				err = &commErr.HandledError{StatusCode: status, Message: t.Message}
			case *commErr.ResourceError:
				err = &commErr.HandledError{StatusCode: status, Message: t.Message}
			case *commErr.PrivilegeError:
				err = &commErr.HandledError{StatusCode: status, Message: t.Message}
			}
			return err
		}
		w.Header().Set("Content-Type", constants.HTTPMediaTypeSaml)
		w.WriteHeader(status)
		if data != nil {
			// Send XML response back to the client application
			err = xml.NewEncoder(w).Encode(data)
			if err != nil {
				defaultLog.WithError(err).Errorf("Error from Handler: %s\n", err.Error())
				secLog.WithError(err).Errorf("Error from Handler: %s\n", err.Error())
			}
		}
		return nil
	}
}

func permissionsHandler(eh endpointHandler, permissionNames []string) endpointHandler {
	defaultLog.Trace("router/handlers:permissionsHandler() Entering")
	defer defaultLog.Trace("router/handlers:permissionsHandler() Leaving")

	return func(w http.ResponseWriter, r *http.Request) error {
		privileges, err := comctx.GetUserPermissions(r)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte("Could not get user permissions from http context"))
			secLog.Errorf("router/handlers:permissionsHandler() %s Permission: %v | Context: %v", commLogMsg.AuthenticationFailed, permissionNames, r.Context())
			return errors.Wrap(err, "router/handlers:permissionsHandler() Could not get user permissions from http context")
		}
		reqPermissions := ct.PermissionInfo{Service: constants.ServiceName, Rules: permissionNames}

		_, foundMatchingPermission := auth.ValidatePermissionAndGetPermissionsContext(privileges, reqPermissions,
			true)
		if !foundMatchingPermission {
			w.WriteHeader(http.StatusUnauthorized)
			secLog.Errorf("router/handlers:permissionsHandler() %s Insufficient privileges to access %s", commLogMsg.UnauthorizedAccess, r.RequestURI)
			return &commErr.PrivilegeError{Message: "Insufficient privileges to access " + r.RequestURI, StatusCode: http.StatusUnauthorized}
		}
		secLog.Infof("router/handlers:permissionsHandler() %s - %s", commLogMsg.AuthorizedAccess, r.RequestURI)
		return eh(w, r)
	}
}

func ErrorHandler(eh endpointHandler) http.HandlerFunc {
	defaultLog.Trace("router/handlers:ErrorHandler() Entering")
	defer defaultLog.Trace("router/handlers:ErrorHandler() Leaving")
	return func(w http.ResponseWriter, r *http.Request) {
		if err := eh(w, r); err != nil {
			if gorm.IsRecordNotFoundError(err) {
				http.Error(w, err.Error(), http.StatusNotFound)
				return
			}
			switch t := err.(type) {
			case *commErr.HandledError:
				http.Error(w, t.Message, t.StatusCode)
			case *commErr.PrivilegeError:
				http.Error(w, t.Message, t.StatusCode)
			default:
				http.Error(w, err.Error(), http.StatusInternalServerError)
			}
		}
	}
}
