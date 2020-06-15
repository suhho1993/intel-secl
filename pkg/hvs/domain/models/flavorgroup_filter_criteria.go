/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package models

type FlavorGroupFilterCriteria struct {
	Id           string `json:"id"`
	NameEqualTo  string `json:"nameEqualTo"`
	NameContains string `json:"nameContains"`
	HostId       string `json:"hostId"`
}
