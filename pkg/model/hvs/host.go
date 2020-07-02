/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package hvs

import "github.com/google/uuid"

type HostCollection struct {
	Hosts []*Host `json:"hosts" xml:"host"`
}

type Host struct {
	Id               uuid.UUID `json:"id,omitempty"`
	HostName         string    `json:"host_name"`
	Description      string    `json:"description,omitempty"`
	ConnectionString string    `json:"connection_string"`
	HardwareUuid     uuid.UUID `json:"hardware_uuid,omitempty"`
	FlavorgroupNames []string  `json:"flavorgroup_names,omitempty"`
}

type HostFlavorgroupCollection struct {
	HostFlavorgroups []*HostFlavorgroup `json:"flavorgroup_host_links" xml:"flavorgroup_host_link"`
}

type HostFlavorgroup struct {
	HostId         uuid.UUID `json:"host_id,omitempty"`
	FlavorgroupId  uuid.UUID `json:"flavorgroup_id,omitempty"`
}
