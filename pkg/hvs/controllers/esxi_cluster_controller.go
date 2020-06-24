/*
 *  Copyright (C) 2020 Intel Corporation
 *  SPDX-License-Identifier: BSD-3-Clause
 */

package controllers

import (
	"encoding/json"
	"github.com/google/uuid"
	"github.com/gorilla/mux"
	"github.com/intel-secl/intel-secl/v3/pkg/hvs/domain"
	"github.com/intel-secl/intel-secl/v3/pkg/hvs/domain/models"
	commErr "github.com/intel-secl/intel-secl/v3/pkg/lib/common/err"
	commLogMsg "github.com/intel-secl/intel-secl/v3/pkg/lib/common/log/message"
	"github.com/intel-secl/intel-secl/v3/pkg/lib/common/validation"
	"github.com/intel-secl/intel-secl/v3/pkg/model/hvs"
	"github.com/pkg/errors"
	"net/http"
	"net/url"
	"strings"
)

type ESXiClusterController struct {
	ECStore domain.ESXiClusterStore
}

func NewESXiClusterController(ec domain.ESXiClusterStore) *ESXiClusterController {
	return &ESXiClusterController{
		ECStore: ec,
	}
}

func (controller ESXiClusterController) Create(w http.ResponseWriter, r *http.Request) (interface{}, int, error) {
	defaultLog.Trace("controllers/esxi_cluster_controller:Create() Entering")
	defer defaultLog.Trace("controllers/esxi_cluster_controller:Create() Leaving")

	if r.ContentLength == 0 {
		defaultLog.Error("controllers/esxi_cluster_controller:Create() The request body is not provided")
		return nil, http.StatusBadRequest, &commErr.ResourceError{Message: "The request body is not provided"}
	}

	var reqESXiCluster *hvs.ESXiCluster
	// Decode the incoming json data to note struct
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()

	err := dec.Decode(&reqESXiCluster)
	if err != nil {
		secLog.WithError(err).Errorf("controllers/esxi_cluster_controller:Create() %s :  Failed to decode"+
			" request body as ESXi cluster type", commLogMsg.AppRuntimeErr)
		return nil, http.StatusBadRequest, &commErr.ResourceError{Message: "Unable to decode JSON request body"}
	}

	if err := validateESXiClusterRequest(*reqESXiCluster); err != nil {
		secLog.Errorf("controllers/esxi_cluster_controller:Create()  %s", err.Error())
		return nil, http.StatusBadRequest, &commErr.ResourceError{Message: "Invalid request body provided"}
	}

	existingCluster, err := controller.ECStore.Search(&models.ESXiClusterFilterCriteria{
		ClusterName: reqESXiCluster.ClusterName,
	})
	if existingCluster != nil && len(existingCluster.ESXiCluster) > 0 {
		defaultLog.Warn("Trying to register duplicate ESXi cluster. Skipping the registration for this cluster")
		secLog.WithField("Cluster Name", existingCluster.ESXiCluster[0].ClusterName).Warningf("%s: Trying to "+
			"register duplicate Cluster from addr: %s", commLogMsg.InvalidInputBadParam, r.RemoteAddr)
		return nil, http.StatusBadRequest, &commErr.ResourceError{Message: "ESXi cluster with the same name already exists"}
	}
	//TODO Add validation to check if cluster exists

	newESXiCluster, err := controller.ECStore.Create(reqESXiCluster)
	if err != nil {
		secLog.WithError(err).Error("controllers/esxi_cluster_controller:Create() ESXi cluster registration failed")
		return nil, http.StatusInternalServerError, &commErr.ResourceError{Message: "Error while registering a new ESXi cluster"}
	}
	secLog.WithField("Cluster Name", newESXiCluster.ClusterName).Infof("%s: ESXi cluster registered by: %s",
		commLogMsg.PrivilegeModified, r.RemoteAddr)

	//TODO : Add hosts in the cluster to host table
	return newESXiCluster, http.StatusCreated, nil
}

func (controller ESXiClusterController) Search(w http.ResponseWriter, r *http.Request) (interface{}, int, error) {
	defaultLog.Trace("controllers/esxi_cluster_controller:Search() Entering")
	defer defaultLog.Trace("controllers/esxi_cluster_controller:Search() Leaving")

	var filter *models.ESXiClusterFilterCriteria = nil
	var err error

	// check for query parameters
	defaultLog.WithField("query", r.URL.Query()).Trace("Query ESXi cluster")

	if filter, err = getECCriteria(r.URL.Query()); err != nil {
		secLog.Errorf("controllers/esxi_cluster_controller:Search()  %s", err.Error())
		return nil, http.StatusBadRequest, &commErr.ResourceError{Message: "Invalid search criteria provided"}
	}

	esxiClusterCollection, err := controller.ECStore.Search(filter)
	if err != nil {
		defaultLog.WithError(err).Error("controllers/esxi_cluster_controller:Search() ESXi cluster search failed")
		return nil, http.StatusInternalServerError, &commErr.ResourceError{Message: "Unable to search ESXi cluster"}
	}

	//TODO : Get the list of hosts from host table

	secLog.Infof("%s: Return ESXi cluster query result to: %s", commLogMsg.AuthorizedAccess, r.RemoteAddr)
	return esxiClusterCollection, http.StatusOK, nil
}

func (controller ESXiClusterController) Delete(w http.ResponseWriter, r *http.Request) (interface{}, int, error) {
	defaultLog.Trace("controllers/esxi_cluster_controller:Delete() Entering")
	defer defaultLog.Trace("controllers/esxi_cluster_controller:Delete() Leaving")

	id := uuid.MustParse(mux.Vars(r)["id"])

	delESXiCluster, err := controller.ECStore.Retrieve(id)
	if err != nil {
		if strings.Contains(err.Error(), commErr.RowsNotFound) {
			defaultLog.WithError(err).WithField("id", id).Info(
				"controllers/esxi_cluster_controller:Delete() ESXi cluster with given ID does not exist")
			return nil, http.StatusNotFound, &commErr.ResourceError{Message: "ESXi cluster with given ID does not exist"}
		} else {
			defaultLog.WithError(err).WithField("id", id).Info(
				"controllers/esxi_cluster_controller:Delete() Attempt to delete invalid ESXi cluster")
			return nil, http.StatusInternalServerError, &commErr.ResourceError{Message: "Failed to delete ESXi cluster"}
		}
	}
	//TODO: Check if cluster is related to any host

	if err := controller.ECStore.Delete(id); err != nil {
		defaultLog.WithError(err).WithField("id", id).Error(
			"controllers/esxi_cluster_controller:Delete() Failed to delete ESXi cluster")
		return nil, http.StatusInternalServerError, &commErr.ResourceError{Message: "Failed to delete ESXi cluster"}
	}
	secLog.WithField("Cluster name", delESXiCluster.ClusterName).Infof("ESXi cluster deleted by: %s", r.RemoteAddr)
	return nil, http.StatusNoContent, nil
}

func (controller ESXiClusterController) Retrieve(w http.ResponseWriter, r *http.Request) (interface{}, int, error) {
	defaultLog.Trace("controllers/esxi_cluster_controller:Retrieve() Entering")
	defer defaultLog.Trace("controllers/esxi_cluster_controller:Retrieve() Leaving")

	id := uuid.MustParse(mux.Vars(r)["id"])

	esxiCluster, err := controller.ECStore.Retrieve(id)
	if err != nil {
		if strings.Contains(err.Error(), commErr.RowsNotFound) {
			defaultLog.WithError(err).WithField("id", id).Info(
				"controllers/esxi_cluster_controller:Retrieve() ESXi cluster with given ID does not exist")
			return nil, http.StatusNotFound, &commErr.ResourceError{Message: "ESXi cluster with given ID does not exist"}
		} else {
			defaultLog.WithError(err).WithField("id", id).Info(
				"controllers/esxi_cluster_controller:Retrieve() Failed to retrieve ESXi cluster")
			return nil, http.StatusInternalServerError, &commErr.ResourceError{Message: "Failed to retrieve ESXi cluster"}
		}
	}
	//TODO : Get the list of hosts from host table
	secLog.WithField("Cluster name", esxiCluster.ClusterName).Infof("ESXi cluster retrieved by: %s", r.RemoteAddr)
	return esxiCluster, http.StatusOK, nil
}

func validateESXiClusterRequest(esxiCluster hvs.ESXiCluster) error {
	defaultLog.Trace("controllers/esxi_cluster_controller:ValidateESXiClusterRequest() Entering")
	defer defaultLog.Trace("controllers/esxi_cluster_controller:ValidateESXiClusterRequest() Leaving")

	if esxiCluster.ClusterName != "" {
		if errs := validation.ValidateStrings([]string{esxiCluster.ClusterName}); errs != nil {
			return errors.Wrap(errs, "Valid ESXi Cluster Name must be specified")
		}
	} else {
		return errors.New("ESXi Cluster Name must be specified")
	}
	//TODO : Add validation for connection string
	return nil
}

func getECCriteria(params url.Values) (*models.ESXiClusterFilterCriteria, error) {
	defaultLog.Trace("controllers/esxi_cluster_controller:ValidateECCriteria() Entering")
	defer defaultLog.Trace("controllers/esxi_cluster_controller:ValidateECCriteria() Leaving")

	ecfc := models.ESXiClusterFilterCriteria{}

	if strings.TrimSpace(params.Get("id")) != "" {
		parsedId, err := uuid.Parse(params.Get("id"))
		if err != nil {
			secLog.WithError(err).Error("controllers/esxi_cluster_controller:Search() Invalid UUID provided " +
				"in search criteria")
			return nil, errors.Wrap(err, "Invalid UUID provided in search criteria")
		}
		ecfc.Id = parsedId
	} else if strings.TrimSpace(params.Get("clusterName")) != "" {
		if err := validation.ValidateStrings([]string{params.Get("clusterName")}); err != nil {
			return nil, errors.Wrap(err, "Valid contents for Cluster name must be specified")
		}
		ecfc.ClusterName = params.Get("clusterName")
	}

	return &ecfc, nil
}
