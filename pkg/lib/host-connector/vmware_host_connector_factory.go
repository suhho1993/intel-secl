/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package host_connector

import "intel-secl/v3/pkg/lib/host-connector/types"

type VmwareConnectorFactory struct {

}

func (vcf *VmwareConnectorFactory) GetHostConnector(vendorConnector types.VendorConnector, aasApiUrl, trustedCaCerts string) (HostConnector, error) {
	return &VmwareConnector{}, nil
}
