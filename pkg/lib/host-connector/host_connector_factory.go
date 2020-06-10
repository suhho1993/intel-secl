/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package host_connector

import (
	commLog "github.com/intel-secl/intel-secl/v3/pkg/lib/common/log"
	"github.com/intel-secl/intel-secl/v3/pkg/lib/host-connector/constants"
	"github.com/intel-secl/intel-secl/v3/pkg/lib/host-connector/util"
	"github.com/pkg/errors"
)

var log = commLog.GetDefaultLogger()
var secLog = commLog.GetSecurityLogger()

func NewHostConnector(connectionString, aasApiUrl, trustedCaCerts string) (HostConnector, error) {

	log.Trace("host_connector/host_connector_factory:NewHostConnector() Entering")
	defer log.Trace("host_connector/host_connector_factory:NewHostConnector() Leaving")
	var connectorFactory VendorHostConnectorFactory
	vendorConnector, err := util.GetConnectorDetails(connectionString)
	if err != nil {
		return nil, errors.Wrap(err, "host_connector/host_connector_factory:NewHostConnector() Error getting connector details")
	}

	switch vendorConnector.Vendor {
	case constants.INTEL, constants.MICROSOFT:
		log.Debug("host_connector/host_connector_factory:NewHostConnector() Connector type for provided connection string is INTEL")
		connectorFactory = &IntelConnectorFactory{}
	case constants.VMWARE:
		log.Debug("host_connector/host_connector_factory:NewHostConnector() Connector type for provided connection string is VMWARE")
		connectorFactory = &VmwareConnectorFactory{}
	default:
		return nil, errors.New("host_connector_factory:NewHostConnector() Vendor not supported yet: " + vendorConnector.Vendor)
	}
	return connectorFactory.GetHostConnector(vendorConnector, aasApiUrl, trustedCaCerts)
}
