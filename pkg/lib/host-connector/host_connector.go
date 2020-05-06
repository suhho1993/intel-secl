/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package host_connector

import (
	"intel-secl/v3/pkg/lib/host-connector/types"
	taModel "intel-secl/v3/pkg/model/ta"
)

type HostConnector interface {
	GetHostDetails() (taModel.HostInfo, error)
	GetHostManifest(string, []int, []string) (types.HostManifest, error)
	DeployAssetTag(string, string) error
	DeploySoftwareManifest(taModel.Manifest) error
	GetMeasurementFromManifest(taModel.Manifest) (taModel.Measurement, error)
}
