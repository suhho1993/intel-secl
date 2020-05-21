/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package common

/**
 *
 * @author mullas
 */

// FlavorPart
type FlavorPart string

const (
	Platform   FlavorPart = "PLATFORM"
	Os         FlavorPart = "OS"
	HostUnique FlavorPart = "HOST_UNIQUE"
	Software   FlavorPart = "SOFTWARE"
	AssetTag   FlavorPart = "ASSET_TAG"
)

// GetFlavorTypes returns a list of flavor types as strings
func GetFlavorTypes() []FlavorPart {
	return []FlavorPart{Platform, Os, HostUnique, Software, AssetTag}
}

func (fp FlavorPart) String() string {
	return string(fp)
}
