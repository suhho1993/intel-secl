/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package domain

import "github.com/intel-secl/intel-secl/v3/pkg/model/hvs"

type (
	FlavorGroupStore interface {
		Create(*hvs.FlavorGroup) (*hvs.FlavorGroup, error)
		Retrieve(string) (*hvs.FlavorGroup, error)
		Search(*hvs.FlavorGroupFilterCriteria) (*hvs.FlavorgroupCollection, error)
		Delete(string) error
	}

	FlavorStore interface {
	}
	// TODO: Define all contract methods here
)
