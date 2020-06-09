/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package controllers

import (
	"encoding/json"
	"github.com/google/uuid"
	"github.com/gorilla/mux"
	"github.com/intel-secl/intel-secl/v3/pkg/hvs/domain"
	"github.com/intel-secl/intel-secl/v3/pkg/hvs/util"
	commErr "github.com/intel-secl/intel-secl/v3/pkg/lib/common/err"
	commLogMsg "github.com/intel-secl/intel-secl/v3/pkg/lib/common/log/message"
	"github.com/intel-secl/intel-secl/v3/pkg/lib/common/validation"
	"github.com/intel-secl/intel-secl/v3/pkg/model/hvs"
	"github.com/pkg/errors"
	"net/http"
	"strconv"
	"strings"
)

var tlsPolicyFilter util.TlsPolicyFilter

type TlsPolicyController struct {
	Store domain.TlsPolicyStore
}

func (controller TlsPolicyController) Create(w http.ResponseWriter, r *http.Request) (interface{}, int, error) {
	defaultLog.Trace("controllers/tlspolicy_controller:Create() Entering")
	defer defaultLog.Trace("controllers/tlspolicy_controller:Create() Leaving")

	if r.ContentLength == 0 {
		secLog.Error("controllers/tlspolicy_controller:Create() The request body was not provided")
		return nil, http.StatusBadRequest, &commErr.ResourceError{Message: "The request body was not provided"}
	}

	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()

	var reqTlsPolicy hvs.TlsPolicy
	err := dec.Decode(&reqTlsPolicy)
	if err != nil {
		defaultLog.WithError(err).Errorf("controllers/tlspolicy_controller:Create() %s :  Failed to decode request body as TlsPolicy", commLogMsg.AppRuntimeErr)
		return nil, http.StatusBadRequest, &commErr.ResourceError{Message: "Unable to decode JSON request body"}
	}

	if reqTlsPolicy.Name == "" {
		secLog.Error("controllers/tlspolicy_controller:Create()  Tls policy name must be specified")
		return nil, http.StatusBadRequest, &commErr.ResourceError{Message: "Tls policy name must be specified"}
	}

	// check if the TLS policy identifier is allowed
	if !tlsPolicyFilter.IsTlsPolicyAllowed(reqTlsPolicy.Descriptor.PolicyType) {
		secLog.WithField("PolicyType", reqTlsPolicy.Descriptor.PolicyType).Warningf("%s: Trying to create prohibited TlsPolicy from addr: %s", commLogMsg.InvalidInputBadParam, r.RemoteAddr)
		return nil, http.StatusBadRequest, &commErr.ResourceError{Message: "Specified policy type is not allowed"}
	}

	tlsPolicies, err := controller.Store.Search(&hvs.TlsPolicyFilterCriteria{
		NameEqualTo: reqTlsPolicy.Name,
	})
	if err != nil {
		secLog.WithError(err).Error("controllers/tlspolicy_controller:Create() TlsPolicy search failed")
		return nil, http.StatusInternalServerError, &commErr.ResourceError{Message: "Failed to create TlsPolicy"}
	}

	if tlsPolicies != nil && len(tlsPolicies.TlsPolicies) > 0 {
		secLog.WithField("Name", tlsPolicies.TlsPolicies[0].Name).Warningf("%s: Trying to create duplicate TlsPolicy from addr: %s", commLogMsg.InvalidInputBadParam, r.RemoteAddr)
		return nil, http.StatusBadRequest, &commErr.ResourceError{Message: "TlsPolicy with same name already exist"}
	}

	createdTlsPolicy, err := controller.Store.Create(&reqTlsPolicy)
	if err != nil {
		secLog.WithError(err).Error("controllers/tlspolicy_controller:Create() TlsPolicy create failed")
		return nil, http.StatusInternalServerError, &commErr.ResourceError{Message: "Failed to create TlsPolicy"}
	}

	secLog.WithField("tlspolicy", createdTlsPolicy).Infof("%s: TlsPolicy created by: %s", commLogMsg.PrivilegeModified, r.RemoteAddr)
	return createdTlsPolicy, http.StatusCreated, nil
}

func (controller TlsPolicyController) Retrieve(w http.ResponseWriter, r *http.Request) (interface{}, int, error) {
	defaultLog.Trace("controllers/tlspolicy_controller:Retrieve() Entering")
	defer defaultLog.Trace("controllers/tlspolicy_controller:Retrieve() Leaving")

	id := uuid.MustParse(mux.Vars(r)["id"])
	tlsPolicy, err := controller.Store.Retrieve(id)
	if err != nil {
		if strings.Contains(err.Error(), commErr.RowsNotFound) {
			secLog.WithError(err).WithField("id", id).Error("controllers/tlspolicy_controller:Retrieve()  TlsPolicy with specified id could not be located")
			return nil, http.StatusNotFound, &commErr.ResourceError{Message: "TlsPolicy with specified id does not exist"}
		} else {
			secLog.WithError(err).WithField("id", id).Error("TlsPolicy retrieve failed")
			return nil, http.StatusInternalServerError, &commErr.ResourceError{Message: "Failed to retrieve TlsPolicy"}
		}
	}

	secLog.WithField("tlspolicy", tlsPolicy).Infof("%s: TlsPolicy retrieved by: %s", commLogMsg.AuthorizedAccess, r.RemoteAddr)
	return tlsPolicy, http.StatusOK, nil
}

func (controller TlsPolicyController) Update(w http.ResponseWriter, r *http.Request) (interface{}, int, error) {
	defaultLog.Trace("controllers/tlspolicy_controller:Update() Entering")
	defer defaultLog.Trace("controllers/tlspolicy_controller:Update() Leaving")

	id := uuid.MustParse(mux.Vars(r)["id"])
	tlsPolicy, err := controller.Store.Retrieve(id)
	if err != nil {
		if strings.Contains(err.Error(), commErr.RowsNotFound) {
			secLog.WithError(err).WithField("id", id).Error("controllers/tlspolicy_controller:Update()  TlsPolicy with specified id could not be located")
			return nil, http.StatusNotFound, &commErr.ResourceError{Message: "TlsPolicy with specified id does not exist"}
		} else {
			defaultLog.WithError(err).WithField("id", id).Error("TlsPolicy retrieve failed")
			return nil, http.StatusInternalServerError, &commErr.ResourceError{Message: "Failed to update TlsPolicy"}
		}
	}

	if r.ContentLength == 0 {
		secLog.Error("controllers/tlspolicy_controller:Update() The request body was not provided")
		return nil, http.StatusBadRequest, &commErr.ResourceError{Message: "The request body was not provided"}
	}

	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()

	var reqTlsPolicy hvs.TlsPolicy
	err = dec.Decode(&reqTlsPolicy)
	if err != nil {
		defaultLog.WithError(err).Errorf("controllers/tlspolicy_controller:Update() %s :  Failed to decode request body as TlsPolicy", commLogMsg.AppRuntimeErr)
		return nil, http.StatusBadRequest, &commErr.ResourceError{Message: "Unable to decode JSON request body"}
	}

	if reqTlsPolicy.Name != "" {
		tlsPolicy.Name = reqTlsPolicy.Name
	}

	if reqTlsPolicy.PrivateScope {
		tlsPolicy.PrivateScope = reqTlsPolicy.PrivateScope
	}

	if reqTlsPolicy.Comment != "" {
		tlsPolicy.Comment = reqTlsPolicy.Comment
	}

	if reqTlsPolicy.Descriptor != nil {
		// check if the TLS policy identifier is allowed
		if !tlsPolicyFilter.IsTlsPolicyAllowed(reqTlsPolicy.Descriptor.PolicyType) {
			secLog.WithField("PolicyType", reqTlsPolicy.Descriptor.PolicyType).Warningf("%s: Trying to create prohibited TlsPolicy from addr: %s", commLogMsg.InvalidInputBadParam, r.RemoteAddr)
			return nil, http.StatusBadRequest, &commErr.ResourceError{Message: "Specified policy type is not allowed"}
		}
		tlsPolicy.Descriptor = reqTlsPolicy.Descriptor
	}

	updatedTlsPolicy, err := controller.Store.Update(tlsPolicy)
	if err != nil {
		secLog.WithError(err).Error("controllers/tlspolicy_controller:Update() TlsPolicy update failed")
		return nil, http.StatusInternalServerError, &commErr.ResourceError{Message: "Failed to update TlsPolicy"}
	}

	secLog.WithField("tlspolicy", updatedTlsPolicy).Infof("%s: TlsPolicy updated by: %s", commLogMsg.PrivilegeModified, r.RemoteAddr)
	return updatedTlsPolicy, http.StatusCreated, nil
}

func (controller TlsPolicyController) Delete(w http.ResponseWriter, r *http.Request) (interface{}, int, error) {
	defaultLog.Trace("controllers/tlspolicy_controller:Delete() Entering")
	defer defaultLog.Trace("controllers/tlspolicy_controller:Delete() Leaving")

	id := uuid.MustParse(mux.Vars(r)["id"])
	tlsPolicy, err := controller.Store.Retrieve(id)
	if err != nil {
		if strings.Contains(err.Error(), commErr.RowsNotFound) {
			secLog.WithError(err).WithField("id", id).Error("controllers/tlspolicy_controller:Delete()  TlsPolicy with specified id could not be located")
			return nil, http.StatusNotFound, &commErr.ResourceError{Message: "TlsPolicy with specified id does not exist"}
		} else {
			secLog.WithError(err).WithField("id", id).Error("TlsPolicy retrieve failed")
			return nil, http.StatusInternalServerError, &commErr.ResourceError{Message: "Failed to delete TlsPolicy"}
		}
	}

	//TODO: Check if the tls policy is associated with any host
	if err := controller.Store.Delete(id); err != nil {
		secLog.WithError(err).Error("controllers/tlspolicy_controller:Delete() TlsPolicy delete failed")
		return nil, http.StatusInternalServerError, &commErr.ResourceError{Message: "Failed to delete TlsPolicy"}
	}

	secLog.WithField("tlspolicy", tlsPolicy).Infof("TlsPolicy deleted by: %s", r.RemoteAddr)
	return nil, http.StatusNoContent, nil
}

func (controller TlsPolicyController) Search(w http.ResponseWriter, r *http.Request) (interface{}, int, error) {
	defaultLog.Trace("controllers/tlspolicy_controller:Search() Entering")
	defer defaultLog.Trace("controllers/tlspolicy_controller:Search() Leaving")

	// check for query parameters
	defaultLog.WithField("query", r.URL.Query()).Trace("query TlsPolicies")
	id := r.URL.Query().Get("id")
	hostId := r.URL.Query().Get("hostId")
	privateEqualTo := r.URL.Query().Get("privateEqualTo")
	nameEqualTo := r.URL.Query().Get("nameEqualTo")
	nameContains := r.URL.Query().Get("nameContains")
	commentEqualTo := r.URL.Query().Get("commentEqualTo")
	commentContains := r.URL.Query().Get("commentContains")

	var criteria *hvs.TlsPolicyFilterCriteria = nil
	if id != "" || hostId != "" || privateEqualTo != "" || nameEqualTo != "" || nameContains != "" || commentEqualTo != "" || commentContains != "" {
		criteria = &hvs.TlsPolicyFilterCriteria{
			Id:              id,
			HostId:          hostId,
			PrivateEqualTo:  privateEqualTo,
			NameEqualTo:     nameEqualTo,
			NameContains:    nameContains,
			CommentEqualTo:  commentEqualTo,
			CommentContains: commentContains,
		}

		if err := ValidateTlsPolicyFilterCriteria(criteria); err != nil {
			secLog.WithError(err).Error("controllers/tlspolicy_controller:Search() Invalid filter criteria")
			return nil, http.StatusBadRequest, &commErr.ResourceError{Message: err.Error()}
		}
	}

	tlsPolicies, err := controller.Store.Search(criteria)
	if err != nil {
		secLog.WithError(err).Error("controllers/tlspolicy_controller:Search() TlsPolicy search failed")
		return nil, http.StatusInternalServerError, &commErr.ResourceError{Message: "Failed to search TlsPolicies"}
	}

	secLog.Infof("%s: TlsPolicies searched by: %s", commLogMsg.AuthorizedAccess, r.RemoteAddr)
	return tlsPolicies, http.StatusOK, nil
}

func ValidateTlsPolicyFilterCriteria(criteria *hvs.TlsPolicyFilterCriteria) error {
	defaultLog.Trace("controllers/tlspolicy_controller:ValidateTlsPolicyFilterCriteria() Entering")
	defer defaultLog.Trace("controllers/tlspolicy_controller:ValidateTlsPolicyFilterCriteria() Leaving")

	if criteria.Id != "" {
		if _, err := uuid.Parse(criteria.Id); err != nil {
			return errors.New("Invalid id query param value, must be UUIDv4")
		}
	}
	if criteria.HostId != "" {
		if _, err := uuid.Parse(criteria.HostId); err != nil {
			return errors.New("Invalid hostId query param value, must be UUIDv4")
		}
	}
	if criteria.PrivateEqualTo != "" {
		if _, err := strconv.ParseBool(criteria.PrivateEqualTo); err != nil {
			return errors.New("Invalid privateEqualTo query param value, must be true or false")
		}
	}
	if criteria.NameEqualTo != "" {
		if err := validation.ValidateNameString(criteria.NameEqualTo); err != nil {
			return errors.Wrap(err, "Valid contents for nameEqualTo must be specified")
		}
	}
	if criteria.NameContains != "" {
		if err := validation.ValidateNameString(criteria.NameContains); err != nil {
			return errors.Wrap(err, "Valid contents for nameContains must be specified")
		}
	}
	if criteria.CommentEqualTo != "" {
		if err := validation.ValidateNameString(criteria.CommentEqualTo); err != nil {
			return errors.Wrap(err, "Valid contents for commentEqualTo must be specified")
		}
	}
	if criteria.CommentContains != "" {
		if err := validation.ValidateNameString(criteria.CommentContains); err != nil {
			return errors.Wrap(err, "Valid contents for commentContains must be specified")
		}
	}
	return nil
}
