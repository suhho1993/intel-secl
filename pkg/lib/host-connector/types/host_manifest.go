/*
 *  Copyright (C) 2020 Intel Corporation
 *  SPDX-License-Identifier: BSD-3-Clause
 */
package types

import taModel "github.com/intel-secl/intel-secl/v3/pkg/model/ta"

type HostManifest struct {
	AIKCertificate        string           `json:"aik_certificate"`
	AssetTagDigest        string           `json:"asset_tag_digest"`
	HostInfo              taModel.HostInfo `json:"host_info"`
	PcrManifest           PcrManifest      `json:"pcr_manifest"`
	BindingKeyCertificate string           `json:"binding_key_certificate"`
	MeasurementXmls       []string         `json:"measurement_xmls"`
}
