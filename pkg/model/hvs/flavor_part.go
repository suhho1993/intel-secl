/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package hvs
//TODO: Remove when flavor library gets merged to integration
type FlavorPart string

const (
	PLATFORM FlavorPart = "PLATFORM"
	OS                  = "OS"
	HOST_UNIQUE         = "HOST_UNIQUE"
	SOFTWARE            = "SOFTWARE"
	ASSET_TAG           = "ASSET_TAG"
)

func (fp FlavorPart) String() string {
	return fp.String()
}
