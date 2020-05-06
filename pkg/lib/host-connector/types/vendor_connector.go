/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package types

type VendorConnector struct {
	Vendor        string
	Url           string
	Configuration struct {
		Hostname string
		Username string
		Password string
	}
}
