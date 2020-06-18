/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package verifier

import (
	"strings"
	"github.com/intel-secl/intel-secl/v3/pkg/lib/host-connector/types"
	"github.com/intel-secl/intel-secl/v3/pkg/model/hvs"
	"github.com/pkg/errors"
)

type rule interface {
	Apply(hostManifest *types.HostManifest) (*RuleResult, error)
}

type policyBuilder interface {
	GetTrustRules() ([]rule, error)
	GetName() string
}

type VendorName string

const (
	VendorIntel     VendorName = "INTEL"
	VendorVMware    VendorName = "VMWARE"
	VendorMicrosoft VendorName = "MICROSOFT"
	VendorUnknown   VendorName = "UNKNOWN"
)

// FromString This function will take in a string and attempts to map
// it to a VendorName. It accepts values typically found in flavors 
// (i.e. Flavor.Meta.Vendor) and os names found in host manifests (i.e. 
// HostManifest.HostInfo.OSName).
func (vendorName *VendorName) FromString(vendorString string) error {

	vendor := VendorUnknown
	var err error 

	switch (strings.ToUpper(vendorString)) {
	case "WINDOWS":
	case "MICROSOFT WINDOWS SERVER 2016 DATACENTER":
	case "MICROSOFT WINDOWS SERVER 2016 STANDARD":
		vendor = VendorMicrosoft
	case "VMWARE ESXI":
		vendor = VendorVMware
	case "INTEL":
		vendor = VendorIntel
	default:
		// TODO:  The application manifest flavor (SOFTWARE) does not
		// have a vendor, but we know it's INTEL -- use that for now
		// to avoid errors (this should be fixed in HVS).  This should
		// be fixed in flavor conversion. 
		vendor = VendorIntel
  		//err = errors.Errorf("Could not determine vendor name from value '%s'", vendorString)
	}

	*vendorName = vendor
	return err
}

func getPolicyBuilder(verifierCertificates VerifierCertificates, hostManifest *types.HostManifest, signedFlavor *hvs.SignedFlavor) (policyBuilder, error) {

	var builder policyBuilder
	var vendor VendorName

	vendorString := signedFlavor.Flavor.Meta.Vendor
	if len(vendorString) == 0 {
		// if for some reason the vendor wasn't provided in the flavor,
		// get the osname from the manifest
		vendorString = hostManifest.HostInfo.OSName
	}

	err := (&vendor).FromString(vendorString)
	if err != nil {
		return nil, errors.Wrap(err, "The verifier could not determine the vendor")
	}

	switch(vendor) {
	case VendorIntel:
		builder, err = newPolicyBuilderIntelTpm20(verifierCertificates, hostManifest, signedFlavor)
		if err != nil {
			return nil, errors.Wrap(err, "There was an error creating the Intel verification policy")
		}
	default:
		return nil, errors.Errorf("Vendor '%s' is not currently supported", string(vendor)) 
	}

	return builder, nil
}
