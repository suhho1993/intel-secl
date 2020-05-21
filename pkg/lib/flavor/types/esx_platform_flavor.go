/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package types

/**
 *
 * @author mullas
 */

import (
	"crypto/rsa"
	"encoding/hex"
	"fmt"
	"github.com/intel-secl/intel-secl/v3/pkg/lib/common/crypt"
	cf "github.com/intel-secl/intel-secl/v3/pkg/lib/flavor/common"
	"github.com/intel-secl/intel-secl/v3/pkg/lib/flavor/constants"
	cm "github.com/intel-secl/intel-secl/v3/pkg/lib/flavor/model"
	hcTypes "github.com/intel-secl/intel-secl/v3/pkg/lib/host-connector/types"
	"github.com/intel-secl/intel-secl/v3/pkg/model/hvs"
	taModel "github.com/intel-secl/intel-secl/v3/pkg/model/ta"
	"github.com/pkg/errors"
	"strings"
)

var (
	hostSpecificModules = []string{"commandLine.", "componentName.imgdb.tgz", "componentName.onetime.tgz"}
)

// ESXPlatformFlavor is used to generate various Flavors for a VMWare ESX-based host
type ESXPlatformFlavor struct {
	HostManifest   *hcTypes.HostManifest        `json:"host_manifest"`
	HostInfo       *taModel.HostInfo            `json:"host_info"`
	TagCertificate *cm.X509AttributeCertificate `json:"tag_certificate"`
}

// NewESXPlatformFlavor returns an instance of ESXPlaformFlavor
func NewESXPlatformFlavor(manifest *hcTypes.HostManifest, tagCertificate *cm.X509AttributeCertificate) PlatformFlavor {
	return ESXPlatformFlavor{
		HostManifest:   manifest,
		HostInfo:       &manifest.HostInfo,
		TagCertificate: tagCertificate,
	}
}

// GetFlavorPartRaw extracts the details of the flavor part requested by the
// caller from the host report used during the creation of the PlatformFlavor instance
func (esxpf ESXPlatformFlavor) GetFlavorPartRaw(name cf.FlavorPart) ([]string, error) {
	var returnThis []string
	switch name {
	case cf.Platform:
		return esxpf.getPlatformFlavor()
	case cf.Os:
		return esxpf.getOsFlavor()
	case cf.AssetTag:
		return esxpf.getAssetTagFlavor()
	case cf.HostUnique:
		return esxpf.getHostUniqueFlavor()
	}
	return returnThis, cf.UNKNOWN_FLAVOR_PART()
}

// GetFlavorPartNames retrieves the list of flavor parts that can be obtained using the GetFlavorPartRaw function
func (esxpf ESXPlatformFlavor) GetFlavorPartNames() ([]cf.FlavorPart, error) {
	flavorPartList := []cf.FlavorPart{cf.Platform, cf.Os, cf.HostUnique, cf.Software}
	var pcrDetails map[crypt.DigestAlgorithm]map[hcTypes.PcrIndex]cm.PcrEx

	// For each of the flavor parts, check what PCRs are required and if those required PCRs are present in the host report.
	for i := 0; i < len(flavorPartList); i++ {
		flavorPart := flavorPartList[i]
		pcrList := esxpf.getPcrList(esxpf.HostInfo.HardwareFeatures.TPM.Meta.TPMVersion, flavorPart)
		pcrExists := pfutil.PcrExists(esxpf.HostManifest.PcrManifest, pcrList)
		if !pcrExists {
			// remove the non-existent FlavorPart from list
			flavorPartList = append(flavorPartList[:i], flavorPartList[i+1:]...)
		}
	}

	// Check if the AssetTag flavor part is available by ascertaining if contents of PCR22 are set
	pcrDetails = pfutil.GetPcrDetails(esxpf.HostManifest.PcrManifest, []int{22}, false)
	if pcrDetails == nil {
		return []cf.FlavorPart{}, fmt.Errorf("Error fetching PCR22 Details")
	}

	// loop through till PCR22 is found and then check if it is unset
	for _, digestAlgEntry := range pcrDetails {
		for pcrIndexKey, pcrIndexValue := range digestAlgEntry {
			if pcrIndexKey == 22 && strings.ToLower(pcrIndexValue.Value) != strings.ToLower(string(crypt.SHA1().ZeroHash())) {
				flavorPartList = append(flavorPartList, cf.AssetTag)
				break
			}
		}
	}
	return flavorPartList, nil
}

// GetFlavorPart extracts the details of the flavor part requested by the caller from
// the host report used during the creation of the PlatformFlavor instance and it's corresponding signature.
func (esxpf ESXPlatformFlavor) GetFlavorPart(flavorPartName cf.FlavorPart, flavorSigningPrivateKey *rsa.PrivateKey) ([]hvs.SignedFlavor, error) {

	// validate private key
	if flavorSigningPrivateKey != nil {
		err := flavorSigningPrivateKey.Validate()
		if err != nil {
			return nil, errors.Wrap(err, "signing key validation failed")
		}
	}

	// fetch the flavor part
	fp, err := esxpf.GetFlavorPartRaw(flavorPartName)
	if err != nil {
		return nil, errors.Wrap(err, "Error fetching flavor part")
	}

	// add signature to the flavor
	fpwsign, err := pfutil.GetSignedFlavorList(fp, flavorSigningPrivateKey)
	if err != nil {
		return nil, errors.Wrap(err, "Error signing flavor")
	}

	return *fpwsign, nil
}

// GetPcrList Helper function to calculate the list of PCRs for the flavor part specified based
// on the version of the TPM hardware. TPM 2.0 support is available since ISecL v1.2
func (esxpf ESXPlatformFlavor) getPcrList(tpmVersion string, flavorPart cf.FlavorPart) []int {
	var pcrs []int
	var isTpm20 bool
	isTpm20 = tpmVersion == constants.TPMVersion2
	switch flavorPart {
	case cf.Platform:
		if isTpm20 {
			pcrs = append(pcrs, []int{0, 17, 18}...)
		} else {
			pcrs = append(pcrs, []int{0, 17}...)
		}
	case cf.Os:
		if isTpm20 {
			pcrs = append(pcrs, []int{19, 20, 21}...)
		} else {
			pcrs = append(pcrs, []int{18, 19, 20}...)
		}
	case cf.HostUnique:
		if isTpm20 {
			pcrs = append(pcrs, []int{20, 21}...)
		} else {
			pcrs = append(pcrs, []int{19}...)
		}

	case cf.AssetTag:
		pcrs = append(pcrs, []int{22}...)
	}
	return pcrs
}

// eventLogRequiredForEsx Helper function to determine if the event log associated with the PCR
// should be included in the flavor for the specified flavor part
func eventLogRequiredForEsx(tpmVersion string, flavorPartName cf.FlavorPart) bool {
	var eventLogRequired bool

	switch flavorPartName {
	case cf.Platform:
		if tpmVersion == constants.TPMVersion2 {
			eventLogRequired = true
		}
	case cf.Os:
		eventLogRequired = true
	case cf.HostUnique:
		eventLogRequired = true
	case cf.AssetTag:
		eventLogRequired = false
	case cf.Software:
		eventLogRequired = false
	}
	return eventLogRequired
}

// GetPlatformFlavor returns a json document having all the good known PCR values and
// corresponding event logs that can be used for evaluating the PLATFORM trust of a host
func (esxpf ESXPlatformFlavor) getPlatformFlavor() ([]string, error) {
	var errorMessage = "Error during creation of PLATFORM flavor"
	var platformFlavors []string
	var platformPcrs = esxpf.getPcrList(esxpf.HostInfo.HardwareFeatures.TPM.Meta.TPMVersion, cf.Platform)
	var includeEventLog = eventLogRequiredForEsx(esxpf.HostInfo.HardwareFeatures.TPM.Meta.TPMVersion, cf.Platform)
	var flavorPcrs = pfutil.GetPcrDetails(esxpf.HostManifest.PcrManifest, platformPcrs, includeEventLog)

	newMeta, err := pfutil.GetMetaSectionDetails(esxpf.HostInfo, esxpf.TagCertificate, "", cf.Platform, "")
	if err != nil {
		err = errors.Wrap(err, errorMessage+" Failure in Meta section details")
		return nil, err
	}
	newBios := pfutil.GetBiosSectionDetails(esxpf.HostInfo)
	if newBios == nil {
		return nil, fmt.Errorf(errorMessage + " - Failure in Bios section details")
	}
	newHW := pfutil.GetHardwareSectionDetails(esxpf.HostInfo)
	if newHW == nil {
		return nil, fmt.Errorf(errorMessage + " - Failure in Hardware section details")
	}

	// Assemble the Platform Flavor
	fj, err := hvs.NewFlavorToJson(newMeta, newBios, newHW, flavorPcrs, nil, nil, errorMessage)
	if err != nil {
		err = errors.Wrap(err, errorMessage+" JSON marshal failure")
		return nil, err
	}
	// return JSON
	platformFlavors = append(platformFlavors, fj)
	return platformFlavors, nil
}

// getOsFlavor Returns a json document having all the good known PCR values and
// corresponding event logs that can be used for evaluating the OS Trust of a host
func (esxpf ESXPlatformFlavor) getOsFlavor() ([]string, error) {
	var errorMessage = "Error during creation of OS flavor"
	var err error
	var modulesToExclude = hostSpecificModules[:]
	var osFlavors []string
	var osPcrs = esxpf.getPcrList(esxpf.HostInfo.HardwareFeatures.TPM.Meta.TPMVersion, cf.Os)
	var includeEventLog = eventLogRequiredForEsx(esxpf.HostInfo.HardwareFeatures.TPM.Meta.TPMVersion, cf.Os)

	pcrAllEventDetails := pfutil.GetPcrDetails(esxpf.HostManifest.PcrManifest, osPcrs, includeEventLog)

	var filteredPcrDetails map[crypt.DigestAlgorithm]map[hcTypes.PcrIndex]cm.PcrEx
	filteredPcrDetails = pfutil.ExcludeModulesFromEventLog(pcrAllEventDetails, modulesToExclude)

	if filteredPcrDetails == nil {
		err = fmt.Errorf(errorMessage + " Failure in filtering module logs from event log")
		return nil, err
	}
	newMeta, err := pfutil.GetMetaSectionDetails(esxpf.HostInfo, esxpf.TagCertificate, "", cf.Os, "")
	if err != nil {
		err = errors.Wrap(err, errorMessage+" Failure in Meta section details")
		return nil, err
	}
	newBios := pfutil.GetBiosSectionDetails(esxpf.HostInfo)
	if newBios == nil {
		err = fmt.Errorf(errorMessage + " Failure in Bios section details")
		return nil, err
	}

	// Assemble the OS Flavor
	fj, err := hvs.NewFlavorToJson(newMeta, newBios, nil, filteredPcrDetails, nil, nil, errorMessage)
	if err != nil {
		err = errors.Wrap(err, errorMessage+" JSON marshal failure")
		return nil, err
	}
	// return JSON
	osFlavors = append(osFlavors, fj)
	return osFlavors, nil
}

// getHostUniquesFlavor returns a json document having all the good known PCR values and
// corresponding event logs that can be used for evaluating the unique part
// of the PCR configurations of a host. These include PCRs/modules getting
// extended to PCRs that would vary from host to host.
func (esxpf ESXPlatformFlavor) getHostUniqueFlavor() ([]string, error) {
	var errorMessage = "Error during creation of HOST_UNIQUE flavor"
	var err error

	var hostUniqueFlavors []string
	var hostUniquePcrs = esxpf.getPcrList(esxpf.HostInfo.HardwareFeatures.TPM.Meta.TPMVersion, cf.HostUnique)
	var includeEventLog = eventLogRequiredForEsx(esxpf.HostInfo.HardwareFeatures.TPM.Meta.TPMVersion, cf.HostUnique)

	var pcrDetails = pfutil.GetPcrDetails(esxpf.HostManifest.PcrManifest, hostUniquePcrs, includeEventLog)
	var flavorPcrs = pfutil.IncludeModulesToEventLog(pcrDetails, hostSpecificModules)

	// Assemble Meta and Bios information for HOST_UNIQUE flavor
	newMeta, err := pfutil.GetMetaSectionDetails(esxpf.HostInfo, esxpf.TagCertificate, "", cf.HostUnique, "")
	if err != nil {
		err = errors.Wrap(err, errorMessage+" Failure in Meta section details")
		return nil, err
	}
	newBios := pfutil.GetBiosSectionDetails(esxpf.HostInfo)
	if newBios == nil {
		err = errors.Wrap(err, errorMessage+" Failure in Bios section details")
		return nil, err
	}

	// Assemble the HOST_UNIQUE Flavor
	fj, err := hvs.NewFlavorToJson(newMeta, newBios, nil, flavorPcrs, nil, nil, errorMessage)
	if err != nil {
		err = errors.Wrap(err, errorMessage+" JSON marshal failure")
		return nil, err
	}
	// return JSON
	hostUniqueFlavors = append(hostUniqueFlavors, fj)
	return hostUniqueFlavors, nil
}

// getAssetTagFlavor returns the asset tag part of the flavor including the certificate and
// all the key-value pairs that are part of the certificate.
func (esxpf ESXPlatformFlavor) getAssetTagFlavor() ([]string, error) {
	var errorMessage = "Error during creation of ASSET_TAG flavor"
	var err error
	var tagCertificateHash []byte
	var expectedPcrValue string

	var assetTagFlavors []string
	if esxpf.TagCertificate == nil {
		return nil, errors.Errorf("Tag certificate not specified")
	}

	// calculate the expected PCR 22 value based on tag certificate hash
	tagCertificateHash = crypt.SHA1().GetHash(esxpf.TagCertificate.Encoded)
	expectedPcrValue = hex.EncodeToString(crypt.SHA1().ExtendHash(crypt.SHA1().ZeroHash(), tagCertificateHash))

	// Add the expected PCR 22 value to respective hash maps
	var pcr22 = make(map[hcTypes.PcrIndex]cm.PcrEx)
	pcr22[hcTypes.PCR22] = *cm.NewPcrEx(expectedPcrValue, nil)
	var pcrDetails = make(map[crypt.DigestAlgorithm]map[hcTypes.PcrIndex]cm.PcrEx)
	pcrDetails[crypt.SHA1()] = pcr22

	// Assemble meta and bios details
	newMeta, err := pfutil.GetMetaSectionDetails(esxpf.HostInfo, esxpf.TagCertificate, "", cf.AssetTag, "")
	if err != nil {
		err = errors.Wrap(err, errorMessage+" Failure in Meta section details")
		return nil, err
	}
	newBios := pfutil.GetBiosSectionDetails(esxpf.HostInfo)
	if newBios == nil {
		err = fmt.Errorf("%s Failure in Bios section details", errorMessage)
		return nil, err
	}
	newExtConfig, err := pfutil.GetExternalConfigurationDetails(esxpf.TagCertificate)
	if err != nil {
		err = errors.Wrap(err, errorMessage+" Failure in External Configuration section details")
		return nil, err
	}

	// Assemble the ASSET_TAG Flavor
	fj, err := hvs.NewFlavorToJson(newMeta, newBios, nil, pcrDetails, newExtConfig, nil, errorMessage)
	if err != nil {
		err = errors.Wrap(err, errorMessage+" JSON marshal failure")
		return nil, err
	}
	// return JSON
	assetTagFlavors = append(assetTagFlavors, fj)
	return assetTagFlavors, nil
}
