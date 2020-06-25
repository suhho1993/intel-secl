/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */

package postgres

import (
	"github.com/google/uuid"
	"github.com/intel-secl/intel-secl/v3/pkg/hvs/domain/models"
	commErr "github.com/intel-secl/intel-secl/v3/pkg/lib/common/err"
	"github.com/jinzhu/gorm"
	"github.com/pkg/errors"
	"strings"
	"time"
)

type ReportStore struct {
	Store *DataStore
}

func NewReportStore(store *DataStore) *ReportStore {
	return &ReportStore{store}
}

// Retrieve method fetches report for a given Id
func (r *ReportStore) Retrieve(reportId uuid.UUID) (*models.HVSReport, error) {
	defaultLog.Trace("postgres/report_store:Retrieve() Entering")
	defer defaultLog.Trace("postgres/report_store:Retrieve() Leaving")

	re := models.HVSReport{}

	row := r.Store.Db.Model(&report{}).Where(&report{ID: reportId}).Row()
	if err := row.Scan(&re.ID, &re.HostID, (*PGTrustReport)(&re.TrustReport), &re.CreatedAt, &re.Expiration, &re.Saml); err != nil {
		return nil, errors.Wrap(err, "postgres/report_store:Retrieve() failed to scan record")
	}

	return &re, nil
}

// Update method is called after completion of flavor verification process by the flavor verify queue
func (r *ReportStore) Update(re *models.HVSReport) (*models.HVSReport, error) {
	defaultLog.Trace("postgres/report_store:Update() Entering")
	defer defaultLog.Trace("postgres/report_store:Update() Leaving")

	var refilter models.ReportFilterCriteria
	if re.HostID == uuid.Nil{
		return nil, errors.New("Host ID must be specified")
	} else {
		refilter = models.ReportFilterCriteria{
			HostID: re.HostID,
		}
	}

	hvsReports, err := r.Search(&refilter)
	if err != nil{
		return nil, errors.Wrap(err, "postgres/report_store:Update() Error while searching report")
	}
	vsReport := hvsReports[0]
	if strings.Contains(err.Error(), commErr.RowsNotFound) {
		vsReport, err = r.Create(re)
		if err != nil{
			return nil, errors.Wrap(err, "postgres/report_store:Update() Error while creating report")
		}
	}

	dbReport := report{}
	if vsReport.HostID != uuid.Nil {
		dbReport.HostID = vsReport.HostID
	}
	if !vsReport.CreatedAt.IsZero(){
		dbReport.CreatedAt = vsReport.CreatedAt
	}
	if !vsReport.Expiration.IsZero(){
		dbReport.Expiration = vsReport.Expiration
	}
	if vsReport.TrustReport.PolicyName != ""{
		dbReport.TrustReport = PGTrustReport(vsReport.TrustReport)
	}
	if vsReport.Saml != ""{
		dbReport.Saml = vsReport.Saml
	}

	if db := r.Store.Db.Model(&dbReport).Updates(&dbReport); db.Error != nil || db.RowsAffected != 1 {
		if db.Error != nil {
			return nil, errors.Wrap(db.Error, "postgres/report_store:Update() failed to update HVSReport  "+ dbReport.ID.String())
		} else {
			return nil, errors.New("postgres/report_store:Update() - rows affected with Id = %s" + dbReport.ID.String())
		}
	}

	return vsReport, nil
}


// Create method creates a new record in report table
func (r *ReportStore) Create(re *models.HVSReport) (*models.HVSReport, error) {
	defaultLog.Trace("postgres/report_store:Create() Entering")
	defer defaultLog.Trace("postgres/report_store:Create() Leaving")

	re.ID = uuid.New()
	dbReport := report{
		ID:          re.ID,
		HostID:      re.HostID,
		CreatedAt:   re.CreatedAt,
		Expiration:  re.Expiration,
		Saml:        re.Saml,
		TrustReport: PGTrustReport(re.TrustReport),
	}
	if err := r.Store.Db.Create(&dbReport).Error; err != nil {
		return nil, errors.Wrap(err, "postgres/report_store:Create() failed to create HVSReport")
	}

	return re, nil
}

// Search retrieves collection of HVSReport pertaining to a user-provided ReportFilterCriteria
func (r *ReportStore) Search(criteria *models.ReportFilterCriteria) ([]*models.HVSReport, error) {

	var reportID uuid.UUID
	var hostID uuid.UUID
	var hostName string
	var hostHardwareUUID uuid.UUID
	var hostStatus string
	var latestPerHost bool
	var toDate time.Time
	var fromDate time.Time

	if criteria.ID != uuid.Nil{
		reportID = criteria.ID
	}
	if criteria.HostID != uuid.Nil{
		hostID = criteria.HostID
	}
	if criteria.HostHardwareID != uuid.Nil{
		hostHardwareUUID = criteria.HostHardwareID
	}
	if criteria.HostStatus != ""{
		hostStatus = criteria.HostStatus
	}
	if criteria.HostName != ""{
		hostName = criteria.HostName
	}
	if !criteria.ToDate.IsZero(){
		toDate = criteria.ToDate
	}
	if !criteria.FromDate.IsZero(){
		fromDate = criteria.FromDate
	}
	latestPerHost = criteria.LatestPerHost

	if criteria.NumberOfDays != 0{
		toDate = time.Now()
		fromDate = toDate.AddDate(0, 0, -(criteria.NumberOfDays))
	}
	var tx *gorm.DB

	if criteria.FromDate.IsZero() && criteria.ToDate.IsZero() && criteria.LatestPerHost{
		tx = buildLatestReportSearchQuery(r.Store.Db, reportID, hostID, hostHardwareUUID, hostName, hostStatus, criteria.Limit)
	} else {
		tx = buildReportSearchQuery(r.Store.Db, reportID, hostID, hostHardwareUUID, hostName, hostStatus, fromDate, toDate, latestPerHost, criteria.Limit)
	}

	if tx == nil {
		return nil, errors.New("postgres/report_store:Search() Unexpected Error. Could not build" +
			" a gorm query object in HVSReport Search function.")
	}

	rows, err := tx.Rows()
	if err != nil {
		return nil, errors.Wrap(err, "postgres/report_store:Search() failed to retrieve records from db")
	}
	defer rows.Close()


	var reports []*models.HVSReport

	for rows.Next() {
		result := models.HVSReport{}

		if err := rows.Scan(&result.ID, &result.HostID, (*PGTrustReport)(&result.TrustReport), &result.CreatedAt, &result.Expiration, &result.Saml); err != nil {
			return nil, errors.Wrap(err, "postgres/report_store:Search() failed to scan record")
		}
		reports = append(reports, &result)
	}

	return reports, nil
}

// Delete method deletes report for a given Id
func (r *ReportStore) Delete(reportId uuid.UUID) error {
	defaultLog.Trace("postgres/report_store:Delete() Entering")
	defer defaultLog.Trace("postgres/report_store:Delete() Leaving")

	if err := r.Store.Db.Delete(&report{ID: reportId}).Error; err != nil {
		return errors.Wrap(err, "postgres/report_store:Delete() failed to delete Report")
	}
	return nil
}

// buildReportSearchQuery is a helper function to build the query object for a report search.
func buildReportSearchQuery(tx *gorm.DB, reportID, hostHardwareUUID, hostID uuid.UUID , hostName, hostState string, fromDate, toDate time.Time, latestPerHost bool, limit int) *gorm.DB {
	defaultLog.Trace("postgres/report_store:buildReportSearchQuery() Entering")
	defer defaultLog.Trace("postgres/report_store:buildReportSearchQuery() Leaving")
	//TODO Build query for audit log table
	return nil
}

// buildLatestReportSearchQuery is a helper function to build the query object for a latest report search.
func buildLatestReportSearchQuery(tx *gorm.DB, reportID, hostHardwareID, hostID uuid.UUID , hostName, hostState string, limit int) *gorm.DB {
	defaultLog.Trace("postgres/report_store:buildLatestReportSearchQuery() Entering")
	defer defaultLog.Trace("postgres/report_store:buildLatestReportSearchQuery() Leaving")

	if tx == nil {
		return nil
	}

	tx.LogMode(true)
	tx = tx.Model(&report{})

	// Since report id is unique and only one record can be returned by the query.
	if reportID != uuid.Nil {
		tx = tx.Where("id = '%s'", reportID.String())
		return tx
	}
	//TODO rename table names before final merge
	if hostName != "" || hostHardwareID != uuid.Nil{
		tx = tx.Joins("INNER JOIN host h on h.id = host_id")
	}

	if hostState != "" {
		tx = tx.Joins("INNER JOIN host_status hs on hs.host_id = report.host_id")
		tx = tx.Where(`hs.status ->> 'host_state'=?`, strings.ToUpper(hostState))
	}

	if hostName != "" {
		tx = tx.Where("h.name = ?", hostName)
	}

	if hostHardwareID != uuid.Nil {
		tx = tx.Where("h.hardware_uuid = ?", hostHardwareID.String())
	}

	if hostID != uuid.Nil {
		tx = tx.Where("host_id = ?", hostID.String())
	}

	tx = tx.Limit(limit)
	return tx
}