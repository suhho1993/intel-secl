/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package util

import (
	"intel-secl/v3/pkg/lib/host-connector/constants"
	"intel-secl/v3/pkg/lib/host-connector/types"
	"strings"
)

func GetConnectorDetails(connectionString string) types.VendorConnector {

	log.Trace("util/connection_string:GetConnectorDetails() Entering")
	defer log.Trace("util/connection_string:GetConnectorDetails() Leaving")
	var vendorConnector types.VendorConnector
	var vendorURL string
	vendor := GetVendorPrefix(connectionString)
	if vendor != "" {
		vendor = strings.ToUpper(vendor)
		vendorURL = connectionString[len(vendor)+1:]
	} else {
		vendor = GuessVendorFromURL(connectionString)
		vendorURL = connectionString
	}
	vendorConnector.Vendor = vendor
	vendorConnector.Url, vendorConnector.Configuration.Username, vendorConnector.Configuration.Password,
		vendorConnector.Configuration.Hostname = ParseConnectionString(vendorURL)
	return vendorConnector
}

func GuessVendorFromURL(connectionString string) string {

	log.Trace("util/connection_string:GuessVendorFromURL() Entering")
	defer log.Trace("util/connection_string:GuessVendorFromURL() Leaving")
	if strings.Contains(connectionString, "/sdk") {
		return constants.VMWARE
	} else {
		return constants.INTEL
	}
}

func GetVendorPrefix(connectionString string) string {

	log.Trace("util/connection_string:GetVendorPrefix() Entering")
	defer log.Trace("util/connection_string:GetVendorPrefix() Leaving")
	if strings.HasPrefix(strings.ToLower(connectionString), strings.ToLower(constants.INTEL+":")) {
		return constants.INTEL
	} else if strings.HasPrefix(strings.ToLower(connectionString), strings.ToLower(constants.VMWARE+":")) {
		return constants.VMWARE
	} else if strings.HasPrefix(strings.ToLower(connectionString), strings.ToLower(constants.MICROSOFT+":")) {
		return constants.MICROSOFT
	}
	return ""
}

func ParseConnectionString(vendorURL string) (string, string, string, string) {

	log.Trace("util/connection_string:ParseConnectionString() Entering")
	defer log.Trace("util/connection_string:ParseConnectionString() Leaving")
	urlEndIndex := strings.IndexAny(vendorURL, ";")
	var url string
	var hostname string
	var username string
	var password string
	if urlEndIndex != -1 {
		url = vendorURL[:urlEndIndex]
		username, password, hostname = parseCredentials(vendorURL[urlEndIndex:])
	} else {
		return vendorURL, "", "", ""
	}
	return url, username, password, hostname
}

func parseCredentials(credentials string) (string, string, string) {

	log.Trace("util/connection_string:parseCredentials() Entering")
	defer log.Trace("util/connection_string:parseCredentials() Leaving")
	splitCredentials := strings.Split(credentials, ";")
	var username string
	var password string
	var hostname string
	for _, credentials := range splitCredentials {
		if strings.Contains(credentials, "u=") {
			username = strings.Split(credentials, "=")[1]
		} else if strings.Contains(credentials, "p=") {
			password = strings.Split(credentials, "=")[1]
		} else if strings.Contains(credentials, "h=") {
			hostname = strings.Split(credentials, "=")[1]
		}
	}
	return username, password, hostname
}
