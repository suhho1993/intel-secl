/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package host_connector

import (
	"errors"
	commLog"intel-secl/v3/pkg/lib/common/log"
	"intel-secl/v3/pkg/lib/host-connector/constants"
	"intel-secl/v3/pkg/lib/host-connector/util"
)

var log = commLog.GetDefaultLogger()
var secLog = commLog.GetSecurityLogger()

func NewHostConnector(connectionString, aasApiUrl, trustedCaCerts string) (HostConnector, error) {

	log.Trace("host_connector_factory:NewHostConnector() Entering")
	defer log.Trace("host_connector_factory:NewHostConnector() Leaving")
	var connectorFactory VendorHostConnectorFactory
	vendorConnector := util.GetConnectorDetails(connectionString)

	switch vendorConnector.Vendor {
	case constants.INTEL, constants.MICROSOFT:
		log.Debug("host_connector_factory:NewHostConnector() Connector type for provided connection string is INTEL")
		connectorFactory = &IntelConnectorFactory{}
	case constants.VMWARE:
		log.Debug("host_connector_factory:NewHostConnector() Connector type for provided connection string is VMWARE")
		connectorFactory = &VmwareConnectorFactory{}
	default:
		return nil, errors.New("host_connector_factory:NewHostConnector() Vendor not supported yet: " + vendorConnector.Vendor)
	}
	return connectorFactory.GetHostConnector(vendorConnector, aasApiUrl, trustedCaCerts)
}
