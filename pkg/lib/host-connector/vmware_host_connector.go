/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package host_connector

import (
	"github.com/pkg/errors"
	"intel-secl/v3/pkg/lib/host-connector/types"
	taModel "intel-secl/v3/pkg/model/ta"
)

type VmwareConnector struct {

}

func (vc *VmwareConnector) GetHostDetails() (taModel.HostInfo, error) {
	return taModel.HostInfo{}, nil
}

func (vc *VmwareConnector) GetHostManifest(nonce string, pcrList []int, pcrBankList []string) (types.HostManifest, error) {
	return types.HostManifest{}, nil
}

func (vc *VmwareConnector) DeployAssetTag(hardwareUUID, tag string) error {
	return errors.New("vmware_host_connector.go:DeployAssetTag() Operation not supported")
}

func (vc *VmwareConnector) DeploySoftwareManifest(manifest taModel.Manifest) error {
	return errors.New("vmware_host_connector.go:DeploySoftwareManifest() Operation not supported")
}

func (vc *VmwareConnector) GetMeasurementFromManifest(manifest taModel.Manifest) (taModel.Measurement, error) {
	return taModel.Measurement{}, errors.New("vmware_host_connector.go:GetMeasurementFromManifest() Operation not supported")
}
