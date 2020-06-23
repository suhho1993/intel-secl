/*
* Copyright (C) 2020 Intel Corporation
* SPDX-License-Identifier: BSD-3-Clause
*/
package models

type FlavorGroups string

const (
	FlavorGroupsAutomatic        FlavorGroups = "automatic"
	FlavorGroupsHostUnique       FlavorGroups = "host_unique"
	FlavorGroupsPlatformSoftware FlavorGroups = "platform_software"
	FlavorGroupsWorkloadSoftware FlavorGroups = "workload_software"
)

func (dfg FlavorGroups) String() string {
	return string(dfg)
}
