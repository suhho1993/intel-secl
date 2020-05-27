/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package domain

// NewFlavorGroup returns an instance of FlavorGroup by providing default values
func NewFlavorGroup() FlavorGroup {
	defaultLog.Trace("domain/factories:NewFlavorGroup() Entering")
	defer defaultLog.Trace("domain/factories:NewFlavorGroup() Leaving")

	var flavorGroup FlavorGroup
	// Provide all default values
	return flavorGroup
}
