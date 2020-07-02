/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package hrrs

import "time"

var (
	// DefaultRefreshPeriod by default check for expired reports every two minutes
	DefaultRefreshPeriod, _ = time.ParseDuration("2m")

	// DefaultRefreshLookAhead by default look for reports that will expire in the next 5 minutes
	DefaultRefreshLookAhead, _ = time.ParseDuration("5m")
)

type HRRSConfig struct {
	// RefreshPeriod determines how frequently the HRRS checks for expired reports (defaults to
	// DefaultRefreshPeriod).
	RefreshPeriod time.Duration `yaml:"refresh-period" mapstructure:"refresh-period"`

	// RefreshLookAhead is used to filter reports that should be refreshed.  For example, any reports
	// that have an Expiration less than now and the next 5 minutes will be added to the queue for
	// refresh.
	RefreshLookAhead time.Duration `yaml:"refresh-look-ahead" mapstructure:"refresh-look-ahead"`
}
