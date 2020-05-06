/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package host_connector

import "intel-secl/v3/pkg/lib/host-connector/types"

type VendorHostConnectorFactory interface {
	GetHostConnector(vendorConnector types.VendorConnector, aasApiUrl, trustedCaCerts string) (HostConnector, error)
}
