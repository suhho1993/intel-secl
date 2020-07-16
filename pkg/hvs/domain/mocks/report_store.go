/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package mocks

import (
	"encoding/json"
	"io/ioutil"
	"reflect"
	"time"

	"github.com/google/uuid"
	"github.com/intel-secl/intel-secl/v3/pkg/hvs/constants"
	"github.com/intel-secl/intel-secl/v3/pkg/hvs/domain"
	"github.com/intel-secl/intel-secl/v3/pkg/hvs/domain/models"
	commErr "github.com/intel-secl/intel-secl/v3/pkg/lib/common/err"
	"github.com/intel-secl/intel-secl/v3/pkg/model/hvs"
	"github.com/pkg/errors"
)

// MockReportStore provides a mocked implementation of interface postgres.ReportStore
type MockReportStore struct {
	reportStore map[uuid.UUID]models.HVSReport
}

// Create inserts a HVSReport
func (store *MockReportStore) Create(report *models.HVSReport) (*models.HVSReport, error) {
	report.ID = uuid.New()
	store.reportStore[report.ID] = *report
	return report, nil
}

func (store *MockReportStore) Update(*models.HVSReport) (*models.HVSReport, error) {
	return nil, errors.New("Update not implemented")
}

// Retrieve returns HVSReport
func (store *MockReportStore) Retrieve(id uuid.UUID) (*models.HVSReport, error) {
	if rs, found := store.reportStore[id]; found {
		return &rs, nil
	}
	return nil, errors.New(commErr.RowsNotFound)
}

// Delete deletes HVSReport
func (store *MockReportStore) Delete(id uuid.UUID) error {
	for _, t := range store.reportStore {
		if t.ID == id {
			delete(store.reportStore, id)
		}
	}
	return errors.New("record not found")
}

//Search returns a collection of HVSReports filtered as per ReportFilterCriteria
func (store *MockReportStore) Search(criteria *models.ReportFilterCriteria) ([]*models.HVSReport, error) {
	if criteria == nil || reflect.DeepEqual(*criteria, models.ReportFilterCriteria{}) {

		return nil, nil
	}
	hostStore := NewMockHostStore()
	hostStatusStore := NewFakeHostStatusStore()
	var reports []*models.HVSReport
	var hosts []*hvs.Host
	var hostStatuses []*hvs.HostStatus
	if criteria.ID != uuid.Nil {
		t, _ := store.Retrieve(criteria.ID)
		reports = append(reports, t)
	} else if criteria.HostHardwareID != uuid.Nil || criteria.HostName != "" {
		for _, t := range hostStore.hostStore {
			if criteria.HostHardwareID == t.HardwareUuid || criteria.HostName == t.HostName {
				hosts = append(hosts, t)
			}
			for _, h := range hosts {
				for _, r := range store.reportStore {
					if h.Id == r.HostID {
						reports = append(reports, &r)
					}
				}
			}
		}
	} else if criteria.HostID != uuid.Nil {
		for _, r := range store.reportStore {
			if criteria.HostID == r.HostID {
				reports = append(reports, &r)
			}
		}
	} else if criteria.HostStatus != "" {
		for _, t := range hostStatusStore.HostStatusStore {
			if hvs.GetHostState(criteria.HostStatus) == t.HostStatusInformation.HostState {
				hostStatuses = append(hostStatuses, &t)
			}
		}
		for _, h := range hostStatuses {
			for _, r := range store.reportStore {
				if h.HostID == r.HostID {
					reports = append(reports, &r)
				}
			}
		}
	} else if !criteria.ToDate.IsZero() {
		for _, r := range store.reportStore {
			if r.Expiration.Before(criteria.ToDate) {
				reports = append(reports, &r)
			}
		}
	}

	return reports, nil
}

func (store *MockReportStore) FindHostIdsFromExpiredReports(fromTime time.Time, toTime time.Time) ([]uuid.UUID, error) {
	hostIDs := []uuid.UUID{}

	for _, r := range store.reportStore {
		if r.Expiration.After(fromTime) && r.Expiration.Before(toTime) {
			hostIDs = append(hostIDs, r.HostID)
		}
	}

	return hostIDs, nil
}

// NewMockReportStore provides two dummy data for Reports
func NewMockReportStore() *MockReportStore {
	//TODO add more data
	store := &MockReportStore{}
	saml1text, _ := ioutil.ReadFile("../resources/saml_report")
	trustReportBytes, _ := ioutil.ReadFile("../resources/trust_report.json")
	var trustReport hvs.TrustReport
	json.Unmarshal(trustReportBytes, &trustReport)
	created, _ := time.Parse(constants.ParamDateFormat, "2020-06-21 07:18:00.57")
	expiration, _ := time.Parse(constants.ParamDateFormat, "2020-06-22 07:18:00.57")
	store.Create(&models.HVSReport{
		ID:          uuid.MustParse("15701f03-7b1d-49f9-ac62-6b9b0728bdb3"),
		HostID:      uuid.MustParse("ee37c360-7eae-4250-a677-6ee12adce8e2"),
		CreatedAt:   created,
		Expiration:  expiration,
		Saml:        string(saml1text),
		TrustReport: trustReport,
	})

	return store
}

func NewEmptyMockReportStore() domain.ReportStore {
	store := &MockReportStore{}
	store.reportStore = make(map[uuid.UUID]models.HVSReport)
	return store
}
