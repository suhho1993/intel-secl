/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package repository

type HVSDatabase interface {
	Migrate() error
	FlavorGroupRepository() FlavorGroupRepository
	Close()
}
