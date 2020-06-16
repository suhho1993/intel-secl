/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package models

type HostFilterCriteria struct {
	Id               string
	HostHardwareId   string
	NameEqualTo      string
	NameContains     string
	Key              string
	Value            string
}
