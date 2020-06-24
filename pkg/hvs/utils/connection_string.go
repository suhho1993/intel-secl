/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package utils

import (
	"fmt"
	"strings"

	"github.com/intel-secl/intel-secl/v3/pkg/hvs/config"
	"github.com/intel-secl/intel-secl/v3/pkg/lib/common/validation"
	hcConstants "github.com/intel-secl/intel-secl/v3/pkg/lib/host-connector/constants"
	hcUtil "github.com/intel-secl/intel-secl/v3/pkg/lib/host-connector/util"
	"github.com/pkg/errors"
)

// GenerateConnectionString creates a formatted connection string. If the username and password are not specified, then it would retrieve it
// from the credential table and forms the complete connection string.
func GenerateConnectionString(cs string) (string, error) {
	defaultLog.Trace("utils/connection_string:GenerateConnectionString() Entering")
	defer defaultLog.Trace("utils/connection_string:GenerateConnectionString() Leaving")

	vc, err := hcUtil.GetConnectorDetails(cs)
	if err != nil {
		return "", errors.Wrap(err, "Could not get vendor details from connection string")
	}

	conf := config.Global()
	var username, password, credential string

	if vc.Vendor != hcConstants.VMWARE {
		username = "u=" + conf.HVS.Username
		password = "p=" + conf.HVS.Password
		credential = fmt.Sprintf("%s;%s", username, password)
	} else {
		//if credentials not specified in connection string, retrieve from credential table
		if !strings.Contains(cs, "u=") || !strings.Contains(cs, "p=") {
			var hostname string
			// If the connection string is for VMware, we would have this substring from which we need to extract
			// the host name. Otherwise we can extract the host name after the https:// in the connection string.
			if strings.Contains(cs, "h=") {
				hostname = vc.Configuration.Hostname
			} else {
				hostname = strings.Split(strings.Split(cs, "//")[1], ":")[0]
			}

			if hostname == "" {
				return "", errors.New("Host connection string is formatted incorrectly, cannot retrieve host name")
			}

			// TODO: Fetch credentials from db

		} else {
			username = vc.Configuration.Username
			password = vc.Configuration.Password
			credential = fmt.Sprintf("u=%s;p=%s", username, password)
		}
	}

	// validate credential information values are not null or empty
	if credential == "" {
		return "", errors.New("Credentials must be provided for the host connection string")
	}

	if username == "" {
		return "", errors.New("Username must be provided in the host connection string")
	}

	if password == "" {
		return "", errors.New("Password must be provided in the host connection string")
	}

	return fmt.Sprintf("%s;%s", cs, credential), nil
}

// GetConnectionStringWithoutCredentials remove the username and password from the connection string and returns it back. This
// would be stored in the host table and the credentials would be stored in the separate table.
func GetConnectionStringWithoutCredentials(cs string) string {
	defaultLog.Trace("utils/connection_string:GetConnectionStringWithoutCredentials() Entering")
	defer defaultLog.Trace("utils/connection_string:GetConnectionStringWithoutCredentials() Leaving")

	csParts := strings.Split(cs, ";")
	for i := 0; i < len(csParts); i++ {
		if strings.HasPrefix(csParts[i], "u=") || strings.HasPrefix(csParts[i], "p=") {
			csParts = append(csParts[:i], csParts[i+1:]...)
			i--
		}
	}
	return strings.Join(csParts, ";")
}

func ValidateConnectionString(cs string) error {
	defaultLog.Trace("util/connection_string:ValidateConnectionString() Entering")
	defer defaultLog.Trace("util/connection_string:ValidateConnectionString() Leaving")

	vc, err := hcUtil.GetConnectorDetails(cs)
	if err != nil {
		return errors.Wrap(err, "Invalid URL in connection string")
	}

	// TODO: Validate host and port in url
	// need to change the type to URL*
	// changes needed in host connector

	if vc.Configuration.Hostname != "" {
		if err := validation.ValidateHostname(vc.Configuration.Hostname); err != nil {
			return errors.Wrap(err, "Invalid hostname or IP address")
		}
	}
	if vc.Configuration.Password != "" {
		if err := validation.ValidatePasswordString(vc.Configuration.Password); err != nil {
			return errors.Wrap(err, "Invalid password")
		}
	}
	if vc.Configuration.Username != "" {
		if err := validation.ValidateUserNameString(vc.Configuration.Username); err != nil {
			return errors.Wrap(err, "Invalid username")
		}
	}
	return nil
}
