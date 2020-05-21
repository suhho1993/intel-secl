/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package verifier

import (
	"github.com/intel-secl/intel-secl/v3/pkg/lib/host-connector/types"
)

//
// These are temporary models used to support development.
//

type SignedFlavor struct {
	Flavor Flavor
}

type Flavor struct {
	PcrManifest *types.PcrManifest `json:"pcrs,omitempty"`
	External *External
}

type External struct {
	AssetTag AssetTag
}

type AssetTag struct {
	TagCertificate TagCertificate
}

type TagCertificate struct {
	Encoded []byte
}
