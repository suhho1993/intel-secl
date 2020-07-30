/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package constants

import (
	"encoding/json"
	"github.com/pkg/errors"
	"strings"
)

type Vendor int

const (
	VendorUnknown Vendor = iota
	VendorIntel
	VendorVMware
	VendorMicrosoft
)

func (vendor Vendor) String() string {
	return [...]string{"UNKNOWN", "INTEL", "VMWARE", "MICROSOFT"}[vendor]
}

func (vendor *Vendor) GetVendorFromOSName(osName string) error {

	var err error

	switch strings.ToUpper(osName) {
	case "WINDOWS", "MICROSOFT WINDOWS SERVER 2016 DATACENTER", "MICROSOFT WINDOWS SERVER 2016 STANDARD", "MICROSOFT":
		*vendor = VendorMicrosoft
	case "VMWARE", "VMWARE ESXI":
		*vendor = VendorVMware
	case "INTEL", "REDHATENTERPRISE", "REDHATENTERPRISESERVER":
		*vendor = VendorIntel
	default:
		*vendor = VendorUnknown
		err = errors.Errorf("Could not determine vendor name from OS name '%s'", osName)
	}

	return err
}

func (vendor *Vendor) UnmarshalJSON(b []byte) error {
	var jsonValue string
	if err := json.Unmarshal(b, &jsonValue); err != nil {
		return errors.Wrap(err, "Could not unmarshal Vendor from JSON")
	}
	var err error
	switch strings.ToUpper(jsonValue) {
	case "MICROSOFT":
		*vendor = VendorMicrosoft
	case "VMWARE":
		*vendor = VendorVMware
	case "INTEL":
		*vendor = VendorIntel
	default:
		*vendor = VendorUnknown
		err = errors.Errorf("Provided vendor is not supported. Vendor : '%s'", jsonValue)
	}
	return err
}

func (vendor Vendor) MarshalJSON() ([]byte, error) {
	return json.Marshal(vendor.String())
}
