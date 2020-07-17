/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package controllers

import (
	"encoding/json"
	"github.com/google/uuid"
	"github.com/gorilla/mux"
	"github.com/intel-secl/intel-secl/v3/pkg/hvs/constants"
	"github.com/intel-secl/intel-secl/v3/pkg/hvs/domain"
	"github.com/intel-secl/intel-secl/v3/pkg/hvs/domain/models"
	commErr "github.com/intel-secl/intel-secl/v3/pkg/lib/common/err"
	commLogMsg "github.com/intel-secl/intel-secl/v3/pkg/lib/common/log/message"
	"github.com/intel-secl/intel-secl/v3/pkg/lib/common/validation"
	"github.com/intel-secl/intel-secl/v3/pkg/lib/flavor/common"
	"github.com/intel-secl/intel-secl/v3/pkg/model/hvs"
	"github.com/pkg/errors"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

type ReportController struct {
	reportStore     domain.ReportStore
	hostStore       domain.HostStore
	hostStatusStore domain.HostStatusStore
	HTManager 		domain.HostTrustManager
}

func NewReportController(rs domain.ReportStore, hs domain.HostStore, hsts domain.HostStatusStore, ht domain.HostTrustManager ) *ReportController {
	return &ReportController{rs, hs, hsts, ht}
}

func (controller ReportController) Create(w http.ResponseWriter, r *http.Request) (interface{}, int, error) {
	defaultLog.Trace("controllers/report_controller:Create() Entering")
	defer defaultLog.Trace("controllers/report_controller:Create() Leaving")

	if r.ContentLength == 0 {
		secLog.Error("controllers/report_controller:Create() The request body is not provided")
		return nil, http.StatusBadRequest, &commErr.ResourceError{Message:"The request body is not provided"}
	}

	var reqReportCreateCriteria hvs.ReportCreateCriteria
	// Decode the incoming json data to note struct
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()

	err := dec.Decode(&reqReportCreateCriteria)
	if err != nil {
		defaultLog.WithError(err).Errorf("controllers/report_controller:Create() %s :  Failed to decode request body as Report Create Criteria", commLogMsg.AppRuntimeErr)
		return nil, http.StatusBadRequest, &commErr.ResourceError{Message:"Unable to decode JSON request body"}
	}

	if err := validateReportCreateCriteria(reqReportCreateCriteria); err != nil {
		secLog.WithError(err).Errorf("%s controllers/report_controller:Create() Error validating report create criteria", commLogMsg.InvalidInputBadParam)
		return nil, http.StatusBadRequest, &commErr.ResourceError{Message: "Bad input given in input request"}
	}

	hvsReport, err := controller.createReport(reqReportCreateCriteria)
	if err != nil {
		defaultLog.WithError(err).Error("controllers/report_controller:Create() Error while creating report from Flavor verify queue")
		return nil, http.StatusBadRequest, &commErr.ResourceError{Message: "Error while creating report from Flavor verify queue"}
	}
	report := convertToReport(hvsReport)
	secLog.WithField("Name", report.HostInfo.HostName).Infof("%s: report created by: %s", commLogMsg.PrivilegeModified, r.RemoteAddr)
	return report, http.StatusCreated, nil
}

func (controller ReportController) createReport(rsCriteria hvs.ReportCreateCriteria) (*models.HVSReport, error) {
	defaultLog.Trace("controllers/report_controller:createReport() Entering")
	defer defaultLog.Trace("controllers/report_controller:createReport() Leaving")
	hsCriteria := getHostFilterCriteria(rsCriteria)
	hosts, err := controller.hostStore.Search(&hsCriteria)
	if err != nil{
		return nil, errors.Wrap(err, "controllers/report_controller:createReport() Error while searching host")
	}

	if hosts == nil{
		return nil, errors.Wrap(err, "controllers/report_controller:createReport() Host does not exist")
	}
	//Always only one record is returned for the particular criteria
	hostId := hosts[0].Id
	hostStatus, err := controller.hostStatusStore.Retrieve(hostId)
	if hostStatus.HostStatusInformation.HostState != hvs.HostStateConnected{
		return nil, errors.Wrap(err, "controllers/report_controller:createReport() Host is not in CONNECTED state")
	}

	hvsReport, err := controller.HTManager.VerifyHost(hostId, true, false)
	if err != nil {
		return nil, errors.Wrap(err, "controllers/report_controller:createReport() Failed to create a trust report, flavor verification failed")
	}

	return hvsReport, nil
}

func (controller ReportController) CreateSaml(w http.ResponseWriter, r *http.Request) (interface{}, int, error) {
	defaultLog.Trace("controllers/report_controller:CreateSaml() Entering")
	defer defaultLog.Trace("controllers/report_controller:CreateSaml() Leaving")

	if r.ContentLength == 0 {
		secLog.Error("controllers/report_controller:CreateSaml() The request body is not provided")
		return nil, http.StatusBadRequest, &commErr.ResourceError{Message:"The request body is not provided"}
	}

	var reqReportCreateCriteria hvs.ReportCreateCriteria
	// Decode the incoming json data to note struct
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()

	err := dec.Decode(&reqReportCreateCriteria)
	if err != nil {
		defaultLog.WithError(err).Errorf("controllers/report_controller:CreateSaml() %s :  Failed to decode request body as Report Create Criteria", commLogMsg.AppRuntimeErr)
		return nil, http.StatusBadRequest, &commErr.ResourceError{Message:"Unable to decode JSON request body"}
	}

	if err := validateReportCreateCriteria(reqReportCreateCriteria); err != nil {
		secLog.WithError(err).Errorf("controllers/report_controller:CreateSaml() %s : Error validating report create criteria", commLogMsg.InvalidInputBadParam)
		return nil, http.StatusBadRequest, &commErr.ResourceError{Message: "Bad input given in input request"}
	}

	hvsReport, err := controller.createReport(reqReportCreateCriteria)
	if err != nil {
		defaultLog.WithError(err).Error("controllers/report_controller:CreateSaml()  Error while creating report from Flavor verify queue")
		return nil, http.StatusBadRequest, &commErr.ResourceError{Message: "Error while creating report from Flavor verify queue"}
	}

	report := convertToReport(hvsReport)
	secLog.WithField("Name", report.HostInfo.HostName).Infof("%s: saml report created by: %s", commLogMsg.PrivilegeModified, r.RemoteAddr)
	return report.Saml, http.StatusCreated, nil
}

func (controller ReportController) Retrieve(w http.ResponseWriter, r *http.Request) (interface{}, int, error) {
	defaultLog.Trace("controllers/report_controller:Retrieve() Entering")
	defer defaultLog.Trace("controllers/report_controller:Retrieve() Leaving")

	id := uuid.MustParse(mux.Vars(r)["id"])

	hvsReport, err := controller.reportStore.Retrieve(id)
	if err != nil {
		if strings.Contains(err.Error(), commErr.RowsNotFound) {
			secLog.WithError(err).WithField("id", id).Info(
				"controllers/report_controller:Retrieve() Report with given ID does not exist")
			return nil, http.StatusNotFound, &commErr.ResourceError{Message:"Report with given ID does not exist"}
		} else {
			secLog.WithError(err).WithField("id", id).Info(
				"controllers/report_controller:Retrieve() failed to retrieve Report")
			return nil, http.StatusInternalServerError, &commErr.ResourceError{Message: "Failed to retrieve Report"}
		}
	}

	report := convertToReport(hvsReport)
	secLog.WithField("report", report).Infof("%s: Report retrieved by: %s", commLogMsg.AuthorizedAccess, r.RemoteAddr)
	return report, http.StatusOK, nil
}

func (controller ReportController) Search(w http.ResponseWriter, r *http.Request) (interface{}, int, error) {
	defaultLog.Trace("controllers/report_controller:Search() Entering")
	defer defaultLog.Trace("controllers/report_controller:Search() Leaving")

	
	// get the ReportFilterCriteria
	reportFilterCriteria, err := getReportFilterCriteria(r.URL.Query())
	if err != nil {
		secLog.WithError(err).Warnf("controllers/report_controller:Search() %s", commLogMsg.InvalidInputBadParam)
		return nil, http.StatusBadRequest, &commErr.ResourceError{Message: "Invalid Input given in request"}
	}

	hvsReportCollection, err := controller.reportStore.Search(reportFilterCriteria)
	if err != nil {
		defaultLog.WithError(err).Warnf("controllers/report_controller:Search() HVSReport search operation failed")
		return nil, http.StatusInternalServerError, errors.Errorf("HVSReport search operation failed")
	}

	var reportCollection hvs.ReportCollection
	for _, hvsReport := range hvsReportCollection{
		reportCollection.Reports = append(reportCollection.Reports, convertToReport(hvsReport))
	}
	secLog.Infof("%s: Reports searched by: %s", commLogMsg.AuthorizedAccess, r.RemoteAddr)
	return reportCollection, http.StatusOK, nil
}

func (controller ReportController) SearchSaml(w http.ResponseWriter, r *http.Request) (interface{}, int, error) {
	defaultLog.Trace("controllers/report_controller:SearchSaml() Entering")
	defer defaultLog.Trace("controllers/report_controller:SearchSaml() Leaving")

	// get the ReportFilterCriteria
	reportFilterCriteria, err := getReportFilterCriteria(r.URL.Query())
	if err != nil {
		secLog.WithError(err).Warnf("controllers/report_controller:Search() %s", commLogMsg.InvalidInputBadParam)
		return nil, http.StatusBadRequest, &commErr.ResourceError{Message: "Invalid Input given in request"}
	}

	hvsReportCollection, err := controller.reportStore.Search(reportFilterCriteria)
	if err != nil {
		defaultLog.WithError(err).Warnf("controllers/report_controller:SearchSaml() HVSReport search operation failed")
		return nil, http.StatusInternalServerError, errors.Errorf("HVSReport search operation failed")
	}

	var samlStruct hvs.Saml

	var samlCollection []hvs.Saml
	for _, hvsReport := range hvsReportCollection{
		samlStruct, err = hvsReport.GetSaml()
		if err != nil {
			defaultLog.WithError(err).Warnf("controllers/report_controller:SearchSaml() Error while retrieving saml from report")
		}
		samlCollection = append(samlCollection, samlStruct)
	}
	secLog.Infof("%s: SamlReports searched by: %s", commLogMsg.AuthorizedAccess, r.RemoteAddr)
	return samlCollection, http.StatusOK, nil
}

// getReportFilterCriteria checks for set filter params in the Search request and returns a valid ReportFilterCriteria
func getReportFilterCriteria(params url.Values) (*models.ReportFilterCriteria, error) {
	defaultLog.Trace("controllers/report_controller:getReportFilterCriteria() Entering")
	defer defaultLog.Trace("controllers/report_controller:getReportFilterCriteria() Leaving")

	rfc := models.ReportFilterCriteria{}

	// Report ID
	if strings.TrimSpace(params.Get("id")) != "" {
		id, err := uuid.Parse(strings.TrimSpace(params.Get("id")))
		if err != nil {
			return nil, errors.New("Invalid UUID format of the Report Identifier specified")
		}
		rfc.ID = id
	}

	//Host ID
	if strings.TrimSpace(params.Get("hostId")) != "" {
		hostId, err := uuid.Parse(strings.TrimSpace(params.Get("hostId")))
		if err != nil {
			return nil, errors.New("Invalid UUID format of the Host Identifier specified")
		}
		rfc.HostID = hostId
	}

	// Host Hardware UUID
	if strings.TrimSpace(params.Get("hostHardwareId")) != "" {
		hostHardwareId, err := uuid.Parse(strings.TrimSpace(params.Get("hostHardwareId")))
		if err != nil {
			return nil, errors.New("Invalid UUID format of the Host Hardware Identifier specified")
		}
		rfc.HostHardwareID = hostHardwareId
	}

	// Host Name
	hostName := strings.TrimSpace(params.Get("hostName"))
	if hostName != "" {
		if err := validation.ValidateHostname(hostName); err != nil {
			return nil, errors.Wrap(err, "Valid contents for HostName must be specified")
		}
		rfc.HostName = hostName
	}

	// Host State
	hostState := strings.TrimSpace(params.Get("hostStatus"))
	if hostState != "" {
		if hvs.GetHostState(hostState) == hvs.HostStateInvalid {
			return nil, errors.New("Valid contents for HostStatus must be specified")
		}
		rfc.HostStatus = hostState
	}

	// fromDate
	fromDate := strings.TrimSpace(params.Get("fromDate"))
	if fromDate != "" {
		pTime, err := time.Parse(constants.ParamDateFormat, fromDate)
		if err != nil {
			pTime, err = time.Parse(constants.ParamDateFormatUTC, fromDate)
			if err != nil {
				return nil, errors.Wrap(err, "Valid date (YYYY-MM-DD hh:mm:ss) for fromDate must be specified")
			}
		}
		rfc.FromDate = pTime
	}

	// toDate
	toDate := strings.TrimSpace(params.Get("toDate"))
	if toDate != "" {
		pTime, err := time.Parse(constants.ParamDateFormat, toDate)
		if err != nil {
			pTime, err = time.Parse(constants.ParamDateFormatUTC, toDate)
			if err != nil {
				return nil, errors.Wrap(err, "Valid date (YYYY-MM-DD hh:mm:ss) for ToDate must be specified")
			}
		}
		rfc.ToDate = pTime
	}

	// latestPerHost - defaults to true
	latestPerHost := strings.TrimSpace(strings.ToLower(params.Get("latestPerHost")))
	if latestPerHost != "" {
		lph, err := strconv.ParseBool(latestPerHost)
		if err != nil {
			return nil, errors.Wrap(err, "latestPerHost must be true or false")
		}
		rfc.LatestPerHost = lph
	} else {
		rfc.LatestPerHost = true
	}

	// numberOfDays - defaults to 0
	numberOfDays := strings.TrimSpace(params.Get("numberOfDays"))
	if numberOfDays != "" {
		numDays, err := strconv.Atoi(numberOfDays)
		if err != nil || numDays < 0 {
			return nil, errors.New("NumberOfDays must be an integer >= 0")
		}
		rfc.NumberOfDays = numDays
	}

	rowLimit := strings.TrimSpace(params.Get("limit"))
	if rowLimit != "" {
		rLimit, err := strconv.Atoi(rowLimit)
		if err != nil || rLimit <= 0 {
			return nil, errors.New("Limit must be an integer > 0")
		}
		rfc.Limit = rLimit
	} else {
		rfc.Limit = constants.DefaultSearchResultRowLimit
	}

	return &rfc, nil
}


func validateReportCreateCriteria(re hvs.ReportCreateCriteria) error {
	defaultLog.Trace("controllers/report_controller:validateReportCreateCriteria() Entering")
	defer defaultLog.Trace("controllers/report_controller:validateReportCreateCriteria() Leaving")

	if re.HostName == "" && re.HostID == uuid.Nil && re.HardwareUUID == uuid.Nil {
		return errors.New("hostName, hostId and hostHardwareUuid must be specified")
	}

	if re.HostName != "" {
		if err := validation.ValidateHostname(re.HostName); err != nil {
			return errors.Wrap(err, "hostName contains invalid characters")
		}
	}
	return nil
}

func convertToReport(hvsReport *models.HVSReport) *hvs.Report {
	trustInformation := buildTrustInformation(hvsReport.TrustReport)

	report := hvs.Report{
		ID: hvsReport.ID,
		HostID: hvsReport.HostID,
		CreatedAt: hvsReport.CreatedAt,
		Expiration: hvsReport.Expiration,
		TrustReport: hvsReport.TrustReport,
		TrustInformation: *trustInformation,
		HostInfo: hvsReport.TrustReport.HostManifest.HostInfo,
	}
	return &report
}

func buildTrustInformation(trustReport hvs.TrustReport) *hvs.TrustInformation {

	flavorParts := common.GetFlavorTypes()
	flavorsTrustStatus := make(map[common.FlavorPart]hvs.FlavorTrustStatus)
	tr := hvs.NewTrustReport(trustReport)
	for _, flavorPart := range flavorParts{
		if len(tr.GetResultsForMarker(flavorPart.String()))>0{
			flavorsTrustStatus[flavorPart] = hvs.FlavorTrustStatus{
				Trust: tr.IsTrustedForMarker(flavorPart.String()),
				RuleResultCollection: tr.GetResultsForMarker(flavorPart.String()),
			}
		}
	}
	return &hvs.TrustInformation{Overall: tr.IsTrusted(),  FlavorTrust: flavorsTrustStatus}
}

func getHostFilterCriteria(rsCriteria hvs.ReportCreateCriteria) models.HostFilterCriteria{
	var hsCriteria models.HostFilterCriteria
	if rsCriteria.HostName != ""{
		hsCriteria.NameEqualTo = rsCriteria.HostName
	}
	if rsCriteria.HostID != uuid.Nil{
		hsCriteria.Id = rsCriteria.HostID
	}
	if rsCriteria.HardwareUUID != uuid.Nil{
		hsCriteria.HostHardwareId = rsCriteria.HardwareUUID
	}
	return hsCriteria
}