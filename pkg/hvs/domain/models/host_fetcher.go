/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */

package models

import "github.com/intel-secl/intel-secl/v3/pkg/lib/host-connector"

type HostDataFetcherConfig struct {
	HostConnector host_connector.HostConnector
}
