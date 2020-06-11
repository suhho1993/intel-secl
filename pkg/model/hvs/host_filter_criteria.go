/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package hvs

type HostFilterCriteria struct {
	Id               string `json:"id"`
	HostHardwareId   string `json:"hostHardwareId"`
	NameEqualTo      string `json:"nameEqualTo"`
	NameContains     string `json:"nameContains"`
	Key              string `json:"key"`
	Value            string `json:"value"`
}
