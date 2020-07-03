/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package host_connector

import (
	"github.com/intel-secl/intel-secl/v3/pkg/lib/host-connector/types"
	taModel "github.com/intel-secl/intel-secl/v3/pkg/model/ta"
)

type HostConnector interface {
	GetHostDetails() (taModel.HostInfo, error)
	GetHostManifest() (types.HostManifest, error)
	DeployAssetTag(string, string) error
	DeploySoftwareManifest(taModel.Manifest) error
	GetMeasurementFromManifest(taModel.Manifest) (taModel.Measurement, error)
}
