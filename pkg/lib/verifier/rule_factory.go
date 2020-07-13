/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package verifier

import (
	"github.com/intel-secl/intel-secl/v3/pkg/lib/flavor/common"
	flavormodel "github.com/intel-secl/intel-secl/v3/pkg/lib/flavor/model"
	"github.com/intel-secl/intel-secl/v3/pkg/lib/host-connector/types"
	"github.com/intel-secl/intel-secl/v3/pkg/lib/verifier/rules"
	"github.com/intel-secl/intel-secl/v3/pkg/model/hvs"
	"github.com/pkg/errors"
	"reflect"
	"strings"
)

// A ruleBuilder creates flavor specific rules for a particular
// vendor (ex. intel TPM2.0 vs. vmware TPM1.2 vs. vmware TPM2.0)
type ruleBuilder interface {
	GetAssetTagRules() ([]rules.Rule, error)
	GetPlatformRules() ([]rules.Rule, error)
	GetOsRules() ([]rules.Rule, error)
	GetHostUniqueRules() ([]rules.Rule, error)
	GetSoftwareRules() ([]rules.Rule, error)
	GetName() string
}

// The ruleFactory uses flavor and manifest data to determine
// which vendor specific rule builder to use when creating rules
// in 'GetVerificationRules'.
type ruleFactory struct {
	verifierCertificates         VerifierCertificates
	hostManifest                 *types.HostManifest
	signedFlavor                 *hvs.SignedFlavor
	skipSignedFlavorVerification bool
}

func NewRuleFactory(verifierCertificates VerifierCertificates,
	hostManifest *types.HostManifest,
	signedFlavor *hvs.SignedFlavor,
	skipSignedFlavorVerification bool) *ruleFactory {

	return &ruleFactory{
		verifierCertificates:         verifierCertificates,
		hostManifest:                 hostManifest,
		signedFlavor:                 signedFlavor,
		skipSignedFlavorVerification: skipSignedFlavorVerification,
	}
}

func (factory *ruleFactory) GetVerificationRules() ([]rules.Rule, string, error) {

	var flavorPart common.FlavorPart
	var results []rules.Rule

	ruleBuilder, err := factory.getRuleBuilder()
	if err != nil {
		return nil, "", errors.Wrap(err, "Could not retrieve rule builder")
	}

	if reflect.DeepEqual(factory.signedFlavor.Flavor.Meta.Description, flavormodel.Description{}) {
		return nil, "", errors.New("The flavor's description cannot be nil")
	}

	err = (&flavorPart).Parse(factory.signedFlavor.Flavor.Meta.Description.FlavorPart)
	if err != nil {
		return nil, "", errors.Wrap(err, "Could not retrieve flavor part name")
	}

	switch flavorPart {
	case common.FlavorPartPlatform:
		results, err = ruleBuilder.GetPlatformRules()
	case common.FlavorPartAssetTag:
		results, err = ruleBuilder.GetAssetTagRules()
	case common.FlavorPartOs:
		results, err = ruleBuilder.GetOsRules()
	case common.FlavorPartHostUnique:
		results, err = ruleBuilder.GetHostUniqueRules()
	case common.FlavorPartSoftware:
		results, err = ruleBuilder.GetSoftwareRules()
	default:
		return nil, "", errors.Errorf("Cannot build rules for unknown flavor part %s", flavorPart)
	}

	if err != nil {
		return nil, "", errors.Wrapf(err, "Error creating trust rules for flavor '%s'", factory.signedFlavor.Flavor.Meta.ID)
	}

	// if skip flavor signing verification is enabled, add the FlavorTrusted.
	if !factory.skipSignedFlavorVerification {

		var flavorPart common.FlavorPart
		err := (&flavorPart).Parse(factory.signedFlavor.Flavor.Meta.Description.FlavorPart)
		if err != nil {
			return nil, "", errors.Wrap(err, "Could not retrieve flavor part name")
		}

		flavorTrusted, err := rules.NewFlavorTrusted(factory.signedFlavor,
			factory.verifierCertificates.FlavorSigningCertificate,
			factory.verifierCertificates.FlavorCACertificates,
			flavorPart)

		if err != nil {
			return nil, "", errors.Wrap(err, "Error creating the flavor trusted rule")
		}

		results = append(results, flavorTrusted)
	}

	return results, ruleBuilder.GetName(), nil
}

func (factory *ruleFactory) getRuleBuilder() (ruleBuilder, error) {

	var builder ruleBuilder
	var vendor VendorName

	vendorString := factory.signedFlavor.Flavor.Meta.Vendor
	if len(vendorString) == 0 {
		// if for some reason the vendor wasn't provided in the flavor,
		// get the osname from the manifest
		vendorString = factory.hostManifest.HostInfo.OSName
	}

	err := (&vendor).FromString(vendorString)
	if err != nil {
		return nil, errors.Wrap(err, "The verifier could not determine the vendor")
	}

	switch vendor {
	case VendorIntel:
		builder, err = newRuleBuilderIntelTpm20(factory.verifierCertificates, factory.hostManifest, factory.signedFlavor)
		if err != nil {
			return nil, errors.Wrap(err, "There was an error creating the Intel rule builder")
		}
	case VendorVMware:
		tpmVersionString := factory.signedFlavor.Flavor.Meta.Description.TpmVersion
		if len(tpmVersionString) == 0 {
			tpmVersionString = factory.hostManifest.HostInfo.HardwareFeatures.TPM.Meta.TPMVersion
		}

		if tpmVersionString == "1.2" {
			builder, err = newRuleBuilderVMWare12(factory.verifierCertificates, factory.hostManifest, factory.signedFlavor)
			if err != nil {
				return nil, errors.Wrap(err, "There was an error creating the VMWare 1.2 verification rule builder")
			}
		} else if tpmVersionString == "2.0" {
			builder, err = newRuleBuilderVMWare20(factory.verifierCertificates, factory.hostManifest, factory.signedFlavor)
			if err != nil {
				return nil, errors.Wrap(err, "There was an error creating the VMWare 1.2 verification rule builder")
			}
		} else {
			return nil, errors.Errorf("Unknown TPM version '%s'", tpmVersionString)
		}

	default:
		return nil, errors.Errorf("Vendor '%s' is not currently supported", string(vendor))
	}

	return builder, nil
}

// VendorName This should be moved to model/hvs and used by flavors/manifests
type VendorName string

const (
	VendorIntel     VendorName = "INTEL"
	VendorVMware    VendorName = "VMWARE"
	VendorMicrosoft VendorName = "MICROSOFT"
	VendorUnknown   VendorName = ""
)

// FromString This function will take in a string and attempts to map
// it to a VendorName. It accepts values typically found in flavors
// (i.e. Flavor.Meta.Vendor) and os names found in host manifests (i.e.
// HostManifest.HostInfo.OSName).
func (vendorName *VendorName) FromString(vendorString string) error {

	vendor := VendorUnknown
	var err error

	switch strings.ToUpper(vendorString) {
	case "WINDOWS", "MICROSOFT WINDOWS SERVER 2016 DATACENTER", "MICROSOFT WINDOWS SERVER 2016 STANDARD":
		vendor = VendorMicrosoft
	case "VMWARE", "VMWARE ESXI":
		vendor = VendorVMware
	case "INTEL", "REDHATENTERPRISE", "REDHATENTERPRISESERVER":
		vendor = VendorIntel
	case "":
		// TODO:  The application manifest flavor (SOFTWARE) does not
		// have a vendor, but we know it's INTEL -- use that for now
		// to avoid errors (this should be fixed in HVS).  This should
		// be fixed in flavor conversion.
		log.Debugf("Encountered empty vendor string, providing value 'INTEL'")
		vendor = VendorIntel
	default:
		err = errors.Errorf("Could not determine vendor name from value '%s'", vendorString)
	}

	*vendorName = vendor
	return err
}
