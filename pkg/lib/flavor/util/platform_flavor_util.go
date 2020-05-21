/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package util

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"github.com/intel-secl/intel-secl/v3/pkg/lib/common/crypt"
	"github.com/intel-secl/intel-secl/v3/pkg/lib/flavor/common"
	"github.com/intel-secl/intel-secl/v3/pkg/lib/flavor/constants"
	cm "github.com/intel-secl/intel-secl/v3/pkg/lib/flavor/model"
	hcTypes "github.com/intel-secl/intel-secl/v3/pkg/lib/host-connector/types"
	"github.com/intel-secl/intel-secl/v3/pkg/model/hvs"
	taModel "github.com/intel-secl/intel-secl/v3/pkg/model/ta"
	"github.com/pkg/errors"
	"strconv"
	"strings"
	"time"
)

/**
 *
 * @author mullas
 */

// PlatformFlavorUtil is used to group a collection of utility functions dealing with PlatformFlavor
type PlatformFlavorUtil struct {
}

// GetMetaSectionDetails returns the Meta instance from the HostManifest
func (pfutil PlatformFlavorUtil) GetMetaSectionDetails(hostDetails *taModel.HostInfo, tagCertificate *cm.X509AttributeCertificate,
	xmlMeasurement string, flavorPartName common.FlavorPart, vendor string) (*cm.Meta, error) {
	var meta cm.Meta

	// Set UUID
	meta.ID = crypt.GenUUID("")

	// Set Vendor
	if strings.TrimSpace(vendor) == "" {
		meta.Vendor = pfutil.GetVendorName(hostDetails)
	} else {
		meta.Vendor = vendor
	}

	var biosName string
	var biosVersion string
	var osName string
	var osVersion string
	var vmmName string
	var vmmVersion string

	// Set Description
	var description cm.Description

	if hostDetails != nil {
		biosName = strings.TrimSpace(hostDetails.BiosName)
		biosVersion = strings.TrimSpace(hostDetails.BiosVersion)
		description.TbootInstalled = strconv.FormatBool(hostDetails.TbootInstalled)
		vmmName = strings.TrimSpace(hostDetails.VMMVersion)
		vmmVersion = strings.TrimSpace(hostDetails.VMMVersion)
		osName = strings.TrimSpace(hostDetails.OSName)
		osVersion = strings.TrimSpace(hostDetails.OSVersion)
		description.TpmVersion = strings.TrimSpace(hostDetails.HardwareFeatures.TPM.Meta.TPMVersion)
	}
	switch flavorPartName {
	case common.Platform:
		var features = pfutil.getSupportedHardwareFeatures(hostDetails)
		description.Label = pfutil.getLabelFromDetails(meta.Vendor, biosName,
			biosVersion, strings.Join(features, "_"), pfutil.getCurrentTimeStamp())
		description.BiosName = biosName
		description.BiosVersion = biosVersion
		description.FlavorPart = flavorPartName.String()
		if hostDetails != nil && hostDetails.HostName != "" {
			description.Source = strings.TrimSpace(hostDetails.HostName)
		}
	case common.Os:
		description.Label = pfutil.getLabelFromDetails(meta.Vendor, osName, osVersion,
			vmmName, vmmVersion, pfutil.getCurrentTimeStamp())
		description.OsName = osName
		description.OsVersion = osVersion
		description.FlavorPart = flavorPartName.String()
		if hostDetails != nil && hostDetails.HostName != "" {
			description.Source = strings.TrimSpace(hostDetails.HostName)
		}
		if vmmName != "" {
			description.VmmName = strings.TrimSpace(vmmName)
		}
		if vmmVersion != "" {
			description.VmmVersion = strings.TrimSpace(vmmVersion)
		}

	case common.Software:
		var measurements taModel.Measurement
		err := xml.Unmarshal([]byte(xmlMeasurement), &measurements)
		if err != nil {
			err = errors.Wrapf(err, "Failed to parse XML measurements in Software Flavor: %s", err.Error())
			return nil, err
		}
		description.Label = measurements.Label
		description.FlavorPart = flavorPartName.String()
		// set DigestAlgo to SHA384
		switch strings.ToUpper(measurements.DigestAlg) {
		case crypt.SHA384().Name:
			description.DigestAlgorithm = crypt.SHA384().Name
		default:
			err = fmt.Errorf("invalid Digest Algorithm in measurement XML")
			return nil, err
		}
		meta.ID = crypt.GenUUID(measurements.Uuid)
		meta.Schema = pfutil.getSchema()

	case common.AssetTag:
		description.FlavorPart = flavorPartName.String()
		if hostDetails != nil {
			if hostDetails.HardwareUUID != "" {
				description.HardwareUUID = strings.TrimSpace(hostDetails.HardwareUUID)
			}
			if hostDetails.HostName != "" {
				description.Source = strings.TrimSpace(hostDetails.HostName)
			}
		} else if tagCertificate != nil {
			description.HardwareUUID = strings.ToUpper(strings.TrimSpace(tagCertificate.Subject))
		}
		description.Label = pfutil.getLabelFromDetails(meta.Vendor, description.HardwareUUID, pfutil.getCurrentTimeStamp())
	case common.HostUnique:
		if hostDetails != nil {
			if hostDetails.HostName != "" {
				description.Source = strings.TrimSpace(hostDetails.HostName)
			}
			if hostDetails.HardwareUUID != "" {
				description.HardwareUUID = strings.TrimSpace(hostDetails.HardwareUUID)
			}
		}
		description.BiosName = biosName
		description.BiosVersion = biosVersion
		description.OsName = osName
		description.OsVersion = osVersion
		description.FlavorPart = flavorPartName.String()
		description.Label = pfutil.getLabelFromDetails(meta.Vendor, description.HardwareUUID, pfutil.getCurrentTimeStamp())
	default:
		return nil, fmt.Errorf("Error fetching Meta Section details: Invalid FlavorPart %s", flavorPartName.String())
	}
	meta.Description = &description

	return &meta, nil
}

// GetBiosSectionDetails populate the BIOS field details in Flavor
func (pfutil PlatformFlavorUtil) GetBiosSectionDetails(hostDetails *taModel.HostInfo) *cm.Bios {
	var bios cm.Bios
	if hostDetails != nil {
		bios.BiosName = strings.TrimSpace(hostDetails.BiosName)
		bios.BiosVersion = strings.TrimSpace(hostDetails.BiosVersion)
		return &bios
	}
	return nil
}

// getSchema sets the schema for the Meta struct in the flavor
func (pfutil PlatformFlavorUtil) getSchema() *cm.Schema {
	var schema cm.Schema
	schema.Uri = constants.IslMeasurementSchema
	return &schema
}

// getHardwareSectionDetails extracts the host Hardware details from the manifest
func (pfutil PlatformFlavorUtil) GetHardwareSectionDetails(hostInfo *taModel.HostInfo) *cm.Hardware {
	var hardware cm.Hardware
	var feature cm.Feature

	if hostInfo != nil {
		// Extract Processor Info
		hardware.ProcessorInfo = strings.TrimSpace(hostInfo.ProcessorInfo)
		hardware.ProcessorFlags = strings.TrimSpace(hostInfo.ProcessorFlags)

		// Set TPM Feature presence
		tpm := cm.TPM{}
		tpm.Enabled = hostInfo.HardwareFeatures.TPM.Enabled
		tpm.Enabled = hostInfo.HardwareFeatures.TPM.Enabled
		tpm.Version = hostInfo.HardwareFeatures.TPM.Meta.TPMVersion
		// split into list
		tpm.PcrBanks = strings.Split(hostInfo.HardwareFeatures.TPM.Meta.PCRBanks, constants.PCRBankSeparator)
		feature.TPM = &tpm

		txt := cm.TXT{}
		if hostInfo.HardwareFeatures.TXT != nil {
			// Set TXT Feature presence
			txt.Enabled = hostInfo.HardwareFeatures.TXT.Enabled
			feature.TXT = &txt
		}

		cbnt := cm.CBNT{}
		// set CBNT
		if hostInfo.HardwareFeatures.CBNT != nil {
			cbnt.Enabled = hostInfo.HardwareFeatures.CBNT.Enabled
			cbnt.Profile = hostInfo.HardwareFeatures.CBNT.Meta.Profile
			feature.CBNT = &cbnt
		}

		suefi := cm.SUEFI{}
		// and SUEFI state
		if hostInfo.HardwareFeatures.SUEFI != nil {
			suefi.Enabled = hostInfo.HardwareFeatures.SUEFI.Enabled
			feature.SUEFI = &suefi
		}

		hardware.Feature = &feature
	}
	return &hardware
}

// PcrExists checks if required list of PCRs are populated in the PCRManifest
func (pfutil PlatformFlavorUtil) PcrExists(pcrManifest hcTypes.PcrManifest, pcrList []int) bool {
	var pcrExists bool

	// check for empty pcrList
	if len(pcrList) == 0 {
		return pcrExists
	}

	for _, digestBank := range pcrManifest.GetPcrBanks() {
		var pcrExistsForDigestAlg bool

		for _, pcrIndex := range pcrList {
			// get PcrIndex
			pI := hcTypes.PcrIndex(pcrIndex)
			pcr, err := pcrManifest.GetPcrValue(digestBank, pI)

			if pcr != nil && err == nil {
				pcrExistsForDigestAlg = true
			}

			// This check ensures that even if PCRs exist for one supported algorithm, we
			// return back true.
			if pcrExistsForDigestAlg && !pcrExists {
				pcrExists = true
			}
		}
	}
	return pcrExists
}

// GetPcrDetails extracts Pcr values and Event Logs from the HostManifest/PcrManifest and  returns
// in a format suitable for inserting into the flavor
func (pfutil PlatformFlavorUtil) GetPcrDetails(pcrManifest hcTypes.PcrManifest, pcrList []int, includeEventLog bool) map[crypt.DigestAlgorithm]map[hcTypes.PcrIndex]cm.PcrEx {
	pcrsWithDigestAlgorithmForFlavor := make(map[crypt.DigestAlgorithm]map[hcTypes.PcrIndex]cm.PcrEx)

	for _, digestBank := range pcrManifest.GetPcrBanks() {
		pcrsForFlavor := make(map[hcTypes.PcrIndex]cm.PcrEx)
		var digestAlgorithm crypt.DigestAlgorithm
		switch digestBank {
		case hcTypes.SHA1:
			digestAlgorithm = crypt.SHA1()
		case hcTypes.SHA256:
			digestAlgorithm = crypt.SHA256()
		}

		// pull out the logs for the required PCRs from both banks
		for _, pcrIndex := range pcrList {
			pI := hcTypes.PcrIndex(pcrIndex)
			var pcrInfo *hcTypes.Pcr
			pcrInfo, _ = pcrManifest.GetPcrValue(digestBank, pI)

			if pcrInfo != nil {
				// build the PcrEx which will hold the PcrValue and EventLogs
				var currPcrEx cm.PcrEx

				// Populate Value
				currPcrEx.Value = pcrInfo.Value

				// Event logs if allowed
				if includeEventLog {
					manifestPcrEventLogs, err := pcrManifest.GetPcrEventLog(digestBank, pI)

					// check if returned logset from PCR is nil
					if manifestPcrEventLogs != nil && err == nil {
						// Convert EventLog to flavor format
						for _, manifestEventLog := range *manifestPcrEventLogs {
							var currPcrEvent hcTypes.EventLog
							currPcrEvent = manifestEventLog
							switch digestBank {
							case hcTypes.SHA1:
								currPcrEvent.DigestType = fmt.Sprintf(constants.MeasurementTypeClassNamePrefix+"%d", 1)
							case hcTypes.SHA256:
								currPcrEvent.DigestType = fmt.Sprintf(constants.MeasurementTypeClassNamePrefix+"%d", 256)
							}
							currPcrEx.Event = append(currPcrEx.Event, currPcrEvent)
						}
					}
				}

				// commit to sha-bank
				pcrsForFlavor[hcTypes.PcrIndex(pcrIndex)] = currPcrEx
			}
		}

		// commit pcr sha-bank to the overall map
		pcrsWithDigestAlgorithmForFlavor[digestAlgorithm] = pcrsForFlavor
	}
	// return map for flavor to use
	return pcrsWithDigestAlgorithmForFlavor
}

// GetExternalConfigurationDetails extracts the External field for the flavor from the HostManifest
func (pfutil PlatformFlavorUtil) GetExternalConfigurationDetails(tagCertificate *cm.X509AttributeCertificate) (*cm.External, error) {
	var externalconfiguration cm.External
	var assetTag cm.AssetTag
	var err error

	if tagCertificate == nil {
		err = fmt.Errorf("Specified tagcertificate is not valid")
		return nil, err
	}
	assetTag.TagCertificate = *tagCertificate
	externalconfiguration.AssetTag = assetTag
	return &externalconfiguration, nil
}

// GetVendorName sets the vendor name for the Flavor
func (pfutil PlatformFlavorUtil) GetVendorName(hostInfo *taModel.HostInfo) string {
	if hostInfo == nil {
		return ""
	}

	var vendor string
	switch strings.ToUpper(strings.TrimSpace(hostInfo.OSName)) {
	case "VMWARE ESXI":
		vendor = "VMWARE"
	default:
		vendor = "INTEL"
	}

	return vendor
}

// copyInstanceOfPcrDetails - returns a full-clone of the PCRManifest state from the HostManifest
func (pfutil PlatformFlavorUtil) copyInstanceOfPcrDetails(pcrDetails map[crypt.DigestAlgorithm]map[hcTypes.PcrIndex]cm.PcrEx) map[crypt.DigestAlgorithm]map[hcTypes.PcrIndex]cm.PcrEx {
	var pcrDetailsCopy = make(map[crypt.DigestAlgorithm]map[hcTypes.PcrIndex]cm.PcrEx)

	for digestAlgorithm, pcrBank := range pcrDetails {
		var newPcrIndexMap = make(map[hcTypes.PcrIndex]cm.PcrEx)
		for pI, pE := range pcrBank {
			newPcrIndexMap[pI] = pE
		}
		pcrDetailsCopy[digestAlgorithm] = newPcrIndexMap
	}
	return pcrDetailsCopy
}

// IncludeModulesToEventLog includes the event logs from HostManifest in the respective PCR event log
func (pfutil PlatformFlavorUtil) IncludeModulesToEventLog(pcrDetails map[crypt.DigestAlgorithm]map[hcTypes.PcrIndex]cm.PcrEx, modulesToInclude []string) map[crypt.DigestAlgorithm]map[hcTypes.PcrIndex]cm.PcrEx {
	filteredPcrDetails := pfutil.copyInstanceOfPcrDetails(pcrDetails)
	// loop across digest banks
	for digestAlgo, pcrMap := range filteredPcrDetails {
		// loop across pcrindex for each digestbank
		for pI, pE := range pcrMap {
			// include only the events that are needed since it's much harder to remove events
			// from a slice
			var eventsToInclude []hcTypes.EventLog

			// loop at the event log level
			for _, eIX := range pE.Event {
				eventName := eIX.Info["EventName"]
				componentName := eIX.Info["ComponentName"]
				packageName := eIX.Info["PackageName"]

				// inside event
				//  remove dynamic modules for VMWare by checking the PackageName field
				for _, mToInclude := range modulesToInclude {
					if componentName == mToInclude && !(strings.ToLower(eventName) ==
						strings.ToLower(constants.VMWareComponentName) &&
						strings.TrimSpace(packageName) != "") {

						eventsToInclude = append(eventsToInclude, eIX)
						break
					}
				}
			}
			// add ONLY included events to the list
			pE.Event = eventsToInclude
			filteredPcrDetails[digestAlgo][pI] = pE
		}
	}
	return filteredPcrDetails
}

// ExcludeModulesFromEventLog - excludes the event logs from HostManifest out of the respective PCR event log
func (pfutil PlatformFlavorUtil) ExcludeModulesFromEventLog(pcrDetails map[crypt.DigestAlgorithm]map[hcTypes.PcrIndex]cm.PcrEx, modulesToExclude []string) map[crypt.DigestAlgorithm]map[hcTypes.PcrIndex]cm.PcrEx {
	filteredPcrDetails := pfutil.copyInstanceOfPcrDetails(pcrDetails)
	// loop across digest banks
	for digestAlgo, pcrMap := range filteredPcrDetails {
		// loop across pcrindex for each digestbank
		for pI, pE := range pcrMap {
			// include only the events that are needed since it's much harder to remove events
			// from a slice
			var eventsToInclude []hcTypes.EventLog

			// loop at the event log level
			for _, eIX := range pE.Event {
				eventName := eIX.Info["EventName"]
				componentName := eIX.Info["ComponentName"]
				packageName := eIX.Info["PackageName"]

				//  remove dynamic modules for VMWare by checking the PackageName field
				for _, mToExclude := range modulesToExclude {
					if componentName != mToExclude && (strings.ToLower(eventName) ==
						strings.ToLower(constants.VMWareComponentName) &&
						strings.TrimSpace(packageName) != "") {
						eventsToInclude = append(eventsToInclude, eIX)
						break
					}
				}
			}
			// add ONLY included events to the list
			pE.Event = eventsToInclude
			filteredPcrDetails[digestAlgo][pI] = pE
		}
	}
	return filteredPcrDetails
}

// getSupportedHardwareFeatures returns a list of hardware features supported by the host from its HostInfo
func (pfutil PlatformFlavorUtil) getSupportedHardwareFeatures(hostDetails *taModel.HostInfo) []string {
	var features []string
	if hostDetails.HardwareFeatures.CBNT != nil && hostDetails.HardwareFeatures.CBNT.Enabled {
		features = append(features, constants.Cbnt)
		features = append(features, hostDetails.HardwareFeatures.CBNT.Meta.Profile)
	}

	if hostDetails.HardwareFeatures.TPM.Enabled {
		features = append(features, constants.Tpm)
	}

	if hostDetails.HardwareFeatures.TXT != nil && hostDetails.HardwareFeatures.TXT.Enabled {
		features = append(features, constants.Txt)
	}

	if hostDetails.HardwareFeatures.SUEFI != nil && hostDetails.HardwareFeatures.SUEFI.Enabled {
		features = append(features, constants.Suefi)
	}

	return features
}

// getLabelFromDetails generates a flavor label string by combining the details
//from separate fields into a single string separated by underscore
func (pfutil PlatformFlavorUtil) getLabelFromDetails(names ...string) string {
	var labels []string
	for _, s := range names {
		labels = append(labels, strings.Join(strings.Fields(s), ""))
	}
	return strings.Join(labels, "_")
}

// getCurrentTimeStamp generates the current time in the required format
func (pfutil PlatformFlavorUtil) getCurrentTimeStamp() string {
	// Use magical reference date to specify the format
	return time.Now().Format("01-02-2006_15-04-05")
}

// getSignedFlavorList performs a bulk signing of a list of flavor strings and returns a list of SignedFlavors
func (pfutil PlatformFlavorUtil) GetSignedFlavorList(flavors []string, flavorSigningPrivateKey *rsa.PrivateKey) (*[]hvs.SignedFlavor, error) {
	var signedFlavors []hvs.SignedFlavor

	// length for flavors list
	if flavors != nil {
		// loop through and sign each flavor
		for _, f := range flavors {
			var sf *hvs.SignedFlavor
			signedFlavor, err := pfutil.GetSignedFlavor(f, flavorSigningPrivateKey)
			if err != nil {
				err = fmt.Errorf("Error signing flavor collection: %s", err.Error())
				return nil, err
			}
			sf, _ = hvs.NewSignedFlavorFromJSON(signedFlavor)
			if sf == nil {
				err = errors.Wrapf(err, "Error signing flavor collection")
				return nil, err
			}
			signedFlavors = append(signedFlavors, *sf)
		}
	} else {
		return nil, fmt.Errorf("empty flavors list provided")
	}
	return &signedFlavors, nil
}

//GetSignedFlavor is used to sign the flavor
func (pfutil PlatformFlavorUtil) GetSignedFlavor(flavorString string, privateKey *rsa.PrivateKey) (string, error) {
	var flavorInterface hvs.Flavor
	var err error

	// validate private key
	if privateKey != nil {
		err := privateKey.Validate()
		if err != nil {
			return "", errors.Wrap(err, "signing key validation failed")
		}
	} else {
		return "", fmt.Errorf("GetSignedFlavor failed: signing key is missing")
	}

	// prepare the signer
	hashEntity := sha512.New384()
	hashEntity.Write([]byte(flavorString))
	signature, err := rsa.SignPKCS1v15(rand.Reader, privateKey, crypto.SHA384, hashEntity.Sum(nil))
	signatureString := base64.StdEncoding.EncodeToString(signature)

	// unmarshal the signed flavor
	err = json.Unmarshal([]byte(flavorString), &flavorInterface)
	if err != nil {
		err = errors.Wrapf(err, "Flavor unmarshal failures: %s", err.Error())
		return "", err
	}

	// pack into struct and return
	signedFlavor := &hvs.SignedFlavor{
		Flavor:    flavorInterface,
		Signature: signatureString,
	}

	signedFlavorJSON, err := json.Marshal(signedFlavor)
	if err != nil {
		return "", errors.Wrap(err, "Error while marshalling signed flavor")
	}

	return string(signedFlavorJSON), nil
}
