/*
* Copyright (C) 2020 Intel Corporation
* SPDX-License-Identifier: BSD-3-Clause
*/
package default_flavorgroups

type DefaultFlavorGroups string

const (
	Automatic        DefaultFlavorGroups = "automatic"
	HostUnique       DefaultFlavorGroups = "host_unique"
	PlatformSoftware DefaultFlavorGroups = "platform_software"
	WorkloadSoftware DefaultFlavorGroups = "workload_software"
)

func (dfg DefaultFlavorGroups) String() string {
	return dfg.String()
}