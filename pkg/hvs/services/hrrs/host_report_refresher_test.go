/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */

package hrrs

import (
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/intel-secl/intel-secl/v3/pkg/hvs/domain"
	"github.com/intel-secl/intel-secl/v3/pkg/hvs/domain/mocks"
	"github.com/intel-secl/intel-secl/v3/pkg/hvs/domain/models"
	"github.com/intel-secl/intel-secl/v3/pkg/model/hvs"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
)

var (
	tenSeconds, _      = time.ParseDuration("10s")
	oneMinute, _       = time.ParseDuration("1m")
	twentyFourHours, _ = time.ParseDuration("24h")
	testUUID           = uuid.New()
)

func TestHostReportRefresher(t *testing.T) {

	cfg := HRRSConfig{
		RefreshPeriod:    oneMinute,
		RefreshLookAhead: DefaultRefreshLookAhead,
	}

	// create a report that expires in the past
	expiredReport := models.HVSReport{
		ID:         uuid.New(),
		HostID:     testUUID,
		CreatedAt:  time.Now(),
		Expiration: time.Now().Add(-tenSeconds),
		TrustReport: hvs.TrustReport{
			Trusted: true,
		},
	}

	reportStore := mocks.NewEmptyMockReportStore()
	_, _ = reportStore.Create(&expiredReport)

	hostTrustManager := MockHostTrustManager{
		reportStore: reportStore,
	}

	// create a new HostReportRefresher, 'run' the backgound thread and then
	// sleep for ten seconds.  We expect the expired report to be updated
	// in the report store.
	refresher, err := NewHostReportRefresher(cfg, reportStore, hostTrustManager)
	assert.NoError(t, err)
	refresher.Run()

	time.Sleep(tenSeconds)

	t.Log("stopping")
	refresher.Stop()

	// now make sure there is a single report that has an expiration in the future
	criteria := models.ReportFilterCriteria{
		HostID: testUUID,
	}

	reports, err := reportStore.Search(&criteria)
	assert.NoError(t, err)

	assert.NotNil(t, reports)
	assert.Equal(t, len(reports), 1)
	assert.True(t, reports[0].Expiration.After(time.Now()))
}

//-------------------------------------------------------------------------------------------------
// M O C K   H O S T   T R U S T   M A N A G E R
//-------------------------------------------------------------------------------------------------
type MockHostTrustManager struct {
	reportStore domain.ReportStore
}

func (htm MockHostTrustManager) VerifyHost(hostId uuid.UUID, fetchHostData, preferHashMatch bool) (interface{}, error) {
	return nil, errors.New("VerifyHost is not implemented")
}

func (htm MockHostTrustManager) VerifyHostsAsync(hostIDs []uuid.UUID, fetchHostData, preferHashMatch bool) error {

	for _, hostID := range hostIDs {

		// simulate removing the old report and create a new one that
		// expires in 24 hours
		criteria := models.ReportFilterCriteria{
			HostID: hostID,
		}

		reportsToDelete, err := htm.reportStore.Search(&criteria)
		if err != nil {
			return errors.Wrap(err, "There was an error searching for the report by host id")
		}

		for _, reportToDelete := range reportsToDelete {
			htm.reportStore.Delete(reportToDelete.ID)
		}

		trustReport := models.HVSReport{
			ID:         uuid.New(),
			HostID:     testUUID,
			CreatedAt:  time.Now(),
			Expiration: time.Now().Add(twentyFourHours),
			TrustReport: hvs.TrustReport{
				Trusted: true,
			},
		}

		_, err = htm.reportStore.Create(&trustReport)
		if err != nil {
			return nil
		}
	}

	return nil
}
