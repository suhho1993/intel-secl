/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */

package hrrs

import (
	"context"
	"time"

	"github.com/google/uuid"
	"github.com/intel-secl/intel-secl/v3/pkg/hvs/domain"
	"github.com/intel-secl/intel-secl/v3/pkg/hvs/domain/models"
	commLog "github.com/intel-secl/intel-secl/v3/pkg/lib/common/log"

	"github.com/pkg/errors"
)

// HostReportRefresher runs in the background and periodically queries HVS'
// reports to see if they have been expired.  If so, they are passed to
// the HostTrustManager queue to be updated.
type HostReportRefresher interface {
	Run() error
	Stop() error
}

func NewHostReportRefresher(cfg HRRSConfig, reportStore domain.ReportStore, hostTrustManager domain.HostTrustManager) (HostReportRefresher, error) {
	return &hostReportRefresherImpl{
		reportStore:      reportStore,
		hostTrustManager: hostTrustManager,
		cfg:              cfg,
	}, nil
}

var (
	defaultLog = commLog.GetDefaultLogger()
	secLog     = commLog.GetSecurityLogger()
)

type hostReportRefresherImpl struct {
	reportStore      domain.ReportStore
	hostTrustManager domain.HostTrustManager
	cfg              HRRSConfig
	ctx              context.Context
}

func (refresher *hostReportRefresherImpl) Run() error {

	if refresher.cfg.RefreshPeriod == 0 {
		defaultLog.Info("The HRRS refresh period is zero.  HRRS will now exit")
		return nil
	}

	refresher.ctx = context.Background()

	go func() {
		for true {
			err := refresher.refreshReports()
			if err != nil {
				// log any errors, but do not stop trying to refresh reports
				defaultLog.Errorf("HRRS encountered an error while refreshing reports...\n%+v\n", err)
			}

			select {
			case <-time.After(refresher.cfg.RefreshPeriod):
				// continue with the loop and refresh reports again
			case <-refresher.ctx.Done():
				defaultLog.Info("The HRRS has been stopped and now exit")
			}
		}
	}()

	return nil
}

func (refresher *hostReportRefresherImpl) Stop() error {
	if refresher.ctx != nil {
		refresher.ctx.Done()
	} else {
		defaultLog.Debug("The HRRS is not running")
	}

	return nil
}

func (refresher *hostReportRefresherImpl) refreshReports() error {

	expirationDate := time.Now().Add(refresher.cfg.RefreshLookAhead)
	defaultLog.Debugf("HRRS is refreshing hosts that expiring before %s", expirationDate)

	criteria := models.ReportFilterCriteria{
		ToDate: expirationDate,
	}

	expiredReports, err := refresher.reportStore.Search(&criteria)
	if err != nil {
		return errors.Wrap(err, "HRRS encountered an error searching for expired reports")
	}

	defaultLog.Debugf("HRRS found %d expired reports", len(expiredReports))

	hostIDs := make([]uuid.UUID, len(expiredReports))
	for i, report := range expiredReports {
		hostIDs[i] = report.HostID
	}

	if len(hostIDs) > 0 {
		err = refresher.hostTrustManager.VerifyHostsAsync(hostIDs, true, false)
		if err != nil {
			return errors.Wrap(err, "HRRS encountered an error calling the host trust manager")
		}
	}

	defaultLog.Infof("HRRS queued %d hosts from reports that were expiring before %s", len(hostIDs), expirationDate)

	return nil
}
