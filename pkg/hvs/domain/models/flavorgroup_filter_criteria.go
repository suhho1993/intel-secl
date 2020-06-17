/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package models

type FlavorGroupFilterCriteria struct {
	Id           string
	NameEqualTo  string
	NameContains string
	HostId       string
}
