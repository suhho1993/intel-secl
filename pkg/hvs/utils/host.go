/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package utils

import (
	"github.com/intel-secl/intel-secl/v3/pkg/hvs/domain/models"
	"github.com/intel-secl/intel-secl/v3/pkg/lib/host-connector/types"
	model "github.com/intel-secl/intel-secl/v3/pkg/model/ta"
	"strings"
)

func IsLinuxHost(hostInfo *model.HostInfo) bool {
	defaultLog.Trace("utils/host:IsLinuxHost() Entering")
	defer defaultLog.Trace("utils/host:IsLinuxHost() Leaving")

	osName := strings.ToUpper(strings.TrimSpace(hostInfo.OSName))
	// true when running on a linux host that is not a docker container
	if osName != types.OsWindows.String() && osName != types.OsWindows2k16.String() &&
		osName != types.OsWindows2k16dc.String() && osName != types.OsVMware.String() &&
		!hostInfo.IsDockerEnvironment {
		return true
	}
	return false
}

func GetDefaultSoftwareFlavorGroups(components []string) []string {
	defaultLog.Trace("utils/host:GetDefaultSoftwareFlavorGroups() Entering")
	defer defaultLog.Trace("utils/host:GetDefaultSoftwareFlavorGroups() Leaving")

	var fgNames []string
	for _, component := range components {
		if component == types.HostComponentTagent.String() {
			fgNames = append(fgNames, models.FlavorGroupsPlatformSoftware.String())
		} else if component == types.HostComponentWlagent.String() {
			fgNames = append(fgNames, models.FlavorGroupsWorkloadSoftware.String())
		}
	}
	return fgNames
}
