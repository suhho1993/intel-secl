/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package hvs

import (
	"github.com/google/uuid"
	"github.com/intel-secl/intel-secl/v3/pkg/lib/host-connector/types"
	"time"
)

// HostStatusInformation holds the current connection state between the Host's Trust Agent and VS and the timestamp of the
// last successful connection
type HostStatusInformation struct {
	HostState         HostState `json:"host_state"`
	LastTimeConnected time.Time `json:"last_time_connected,omitempty"`
}

// HostStatus contains the response for the Host Status API for an individual host
type HostStatus struct {
	ID                    uuid.UUID             `json:"id"`
	HostID                uuid.UUID             `json:"host_id"`
	Created               time.Time             `json:"created"`
	HostStatusInformation HostStatusInformation `json:"status"`
	HostManifest          types.HostManifest    `json:"host_manifest"`
}

// HostStatusCollection holds a collection of HostStatus in response to an API query
type HostStatusCollection struct {
	HostStatuses []HostStatus `json:"host_status" xml:"host_status"`
}
