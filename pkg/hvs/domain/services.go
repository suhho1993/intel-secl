/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package domain

import (
	"github.com/intel-secl/intel-secl/v3/pkg/lib/common/log"
	"github.com/pkg/errors"
)
var defaultLog = log.GetDefaultLogger()
var secLog = log.GetSecurityLogger()

// TODO: All domain services
func (fg FlavorGroup) Valid() (bool, error) {
	defaultLog.Trace("domain/services:Valid() Entering")
	defer defaultLog.Trace("domain/services:Valid() Leaving")

	var err error
	if fg.Name == "" {
		return false, errors.New("FlavorGroup Name cannot be empty")
	}
	if fg.FlavorTypeMatchPolicy == nil {
		return false, errors.New("Flavor Type Match Policy can not be empty")
	}
	// Do all validation logic here
	return true, err
}