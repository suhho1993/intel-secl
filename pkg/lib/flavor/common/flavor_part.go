/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package common

import (
	commLog "github.com/intel-secl/intel-secl/v3/pkg/lib/common/log"
)

var log = commLog.GetDefaultLogger()

/**
 *
 * @author mullas
 */

// FlavorPart
type FlavorPart string

const (
	FlavorPartPlatform   FlavorPart = "PLATFORM"
	FlavorPartOs         FlavorPart = "OS"
	FlavorPartHostUnique FlavorPart = "HOST_UNIQUE"
	FlavorPartSoftware   FlavorPart = "SOFTWARE"
	FlavorPartAssetTag   FlavorPart = "ASSET_TAG"
)

// GetFlavorTypes returns a list of flavor types as strings
func GetFlavorTypes() []FlavorPart {
	log.Trace("flavor/common/flavor_part:GetFlavorTypes() Entering")
	defer log.Trace("flavor/common/flavor_part:GetFlavorTypes() Leaving")

	return []FlavorPart{FlavorPartPlatform, FlavorPartOs, FlavorPartHostUnique, FlavorPartSoftware, FlavorPartAssetTag}
}

func (fp FlavorPart) String() string {
	log.Trace("flavor/common/flavor_part/FlavorPart:String() Entering")
	defer log.Trace("flavor/common/flavor_part/FlavorPart:String() Leaving")

	return string(fp)
}
