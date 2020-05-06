/*
 *  Copyright (C) 2020 Intel Corporation
 *  SPDX-License-Identifier: BSD-3-Clause
 */
package types

import taModel "intel-secl/v3/pkg/model/ta"

type HostManifest struct {
	AIKCertificate        string           `json:"aikCertificate"`
	AssetTagDigest        string           `json:"assetTagDigest"`
	HostInfo              taModel.HostInfo `json:"hostInfo"`
	PcrManifest           PcrManifest      `json:"pcrManifest"`
	BindingKeyCertificate string           `json:"bindingKeyCertificate"`
	MeasurementXmls       []string         `json:"measurementXmls"`
}
