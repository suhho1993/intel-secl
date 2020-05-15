/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package repository

import (
	"github.com/intel-secl/intel-secl/v3/pkg/model/hvs"
)

type FlavorGroupRepository interface {
	Create(*hvs.FlavorGroup) (*hvs.FlavorGroup, error)
	Retrieve(string) (*hvs.FlavorGroup, error)
	RetrieveAll(*hvs.FlavorGroupFilterCriteria) (*hvs.FlavorgroupCollection, error)
	Delete(string) error
}
