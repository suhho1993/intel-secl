/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */

package hrrs

import (
	"context"
	"time"

	"github.com/intel-secl/intel-secl/v3/pkg/hvs/domain"
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
		fromTime:         time.Unix(0,0),	
	}, nil
}

var (
	defaultLog     = commLog.GetDefaultLogger()
	secLog         = commLog.GetSecurityLogger()
	overlapTime, _ = time.ParseDuration("1ms")
)

type hostReportRefresherImpl struct {
	reportStore      domain.ReportStore
	hostTrustManager domain.HostTrustManager
	cfg              HRRSConfig
	ctx              context.Context
	fromTime         time.Time
}

func (refresher *hostReportRefresherImpl) Run() error {

	defaultLog.Infof("HRRS is starting with refresh period '%s', look ahead '%s'", refresher.cfg.RefreshPeriod, refresher.cfg.RefreshLookAhead)

	if refresher.cfg.RefreshPeriod == 0 {
		defaultLog.Info("The HRRS refresh period is zero.  HRRS will now exit")
		return nil
	}

	refresher.ctx = context.Background()

	go func() {
		for {
			err := refresher.refreshReports()
			if err != nil {
				// log any errors, but do not stop trying to refresh reports
				defaultLog.Errorf("HRRS encountered an error while refreshing reports...\n%+v\n", err)
			}

			select {
			case <-time.After(refresher.cfg.RefreshPeriod):
				// continue with the loop and refresh reports again
			case <-refresher.ctx.Done():
				defaultLog.Info("The HRRS has been stopped and will now exit")
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

// Uses an 'expiration time window' to find expired reports.
//
// - On the first pass, the window is from the epoch to five minutes from now.
//   This will attempt to queue all hosts that have an expired report.
// - On subsequent calls, the window wll be the last time this function was called, 
//   less some overlap and five minutes from now.
//
// The intent of this logic is to avoid adding duplicate hosts to the
// HostTrustManage queue.
func (refresher *hostReportRefresherImpl) refreshReports() error {

	toTime := time.Now().Add(refresher.cfg.RefreshLookAhead)
	defaultLog.Debugf("HRRS is refreshing hosts that have expired reports between %s and %s", refresher.fromTime, toTime)
	
	hostIDs, err := refresher.reportStore.FindHostIdsFromExpiredReports(refresher.fromTime, toTime)
	refresher.fromTime = time.Now().Add(-overlapTime)

	if err != nil {
		return errors.Wrap(err, "An error occurred while HRRS searched for host ids")
	}

	defaultLog.Debugf("HRRS found %d hosts to refresh", len(hostIDs))

	if len(hostIDs) > 0 {
		err = refresher.hostTrustManager.VerifyHostsAsync(hostIDs, true, false)
		if err != nil {
			return errors.Wrap(err, "HRRS encountered an error calling the host trust manager")
		}
	}

	defaultLog.Infof("HRRS queued %d hosts from reports that were expiring between %s and %s", len(hostIDs), refresher.fromTime, toTime)

	return nil
}
