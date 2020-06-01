/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package hvs

import (
	"github.com/google/uuid"
	defaultLog "github.com/intel-secl/intel-secl/v3/pkg/lib/common/log"
	"github.com/intel-secl/intel-secl/v3/pkg/lib/common/validation"
	"github.com/pkg/errors"
)

var log = defaultLog.GetDefaultLogger()

func (flavorGroup FlavorGroup) Valid() (bool, error) {
	log.Trace("hvs/services:Valid() Entering")
	defer log.Trace("hvs/services:Valid() Leaving")

	if flavorGroup.Name == "" {
		return false, errors.New("FlavorGroup Name must be specified")
	}
	if flavorGroup.Name != "" {
		if errs := validation.ValidateNameString(flavorGroup.Name); errs != nil {
			return false, errors.Wrap(errs, "Valid FlavorGroup Name must be specified")
		}
	}
	if flavorGroup.FlavorMatchPolicyCollection == nil || len(flavorGroup.FlavorMatchPolicyCollection.FlavorMatchPolicies) == 0  {
		return false, errors.New("Flavor Type Match Policy Collection must be specified")
	}
	return true, nil
}

func (fg FlavorGroupFilterCriteria) Valid() (bool, error) {
	log.Trace("hvs/services:Valid() Entering")
	defer log.Trace("hvs/services:Valid() Leaving")

	var err error
	if fg.Id != "" {
		if _, errs := uuid.Parse(fg.Id); errs != nil {
			return false, errors.New("Invalid UUID format of the Flavorgroup Identifier")
		}
	}
	if fg.NameEqualTo != "" {
		if errs := validation.ValidateNameString(fg.NameEqualTo); errs != nil {
			return false, errors.Wrap(errs, "Valid contents for NameEqualTo must be specified")
		}
	}
	if fg.NameContains != "" {
		if errs := validation.ValidateNameString(fg.NameContains); errs != nil {
			return false, errors.Wrap(errs, "Valid contents for NameContains must be specified")
		}
	}
	if fg.HostId != "" {
		if _, errs := uuid.Parse(fg.HostId); errs != nil {
			return false, errors.New("Invalid UUID format of the Host Identifier")
		}
	}
	return true, err
}