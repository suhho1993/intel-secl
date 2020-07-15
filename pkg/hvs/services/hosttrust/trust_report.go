package hosttrust

import (
	"github.com/google/uuid"
	"github.com/intel-secl/intel-secl/v3/pkg/hvs/domain/models"
	"github.com/intel-secl/intel-secl/v3/pkg/hvs/services/hosttrust/rules"
	cf "github.com/intel-secl/intel-secl/v3/pkg/lib/flavor/common"
	fConst "github.com/intel-secl/intel-secl/v3/pkg/lib/flavor/constants"
	"github.com/intel-secl/intel-secl/v3/pkg/lib/host-connector/types"
	"github.com/intel-secl/intel-secl/v3/pkg/model/hvs"
	taModel "github.com/intel-secl/intel-secl/v3/pkg/model/ta"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"reflect"
	"strconv"
	"strings"
	"encoding/xml"
)

// FlavorVerify.java: 529
// renamed to CreateFlavorGroupReport and made it a receiver function since we need certificates
// from the config
func (v *Verifier) CreateFlavorGroupReport(hostId uuid.UUID, reqs flvGrpHostTrustReqs,
	hostData *types.HostManifest,
	trustCache hostTrustCache) (hvs.TrustReport, error) {
	defaultLog.Trace("hosttrust/trust_report:CreateFlavorGroupReport() Entering")
	defer defaultLog.Trace("hosttrust/trust_report:CreateFlavorGroupReport() Leaving")

	reqAndDefFlavorTypes := reqs.DefinedAndRequiredFlavorTypes
	latestReqAndDefFlavorTypes := reqs.GetLatestFlavorTypeMap()

	if trustCache.isTrustCacheEmpty() {
		defaultLog.Trace("hosttrust/trust_report:CreateFlavorGroupReport() No results found in Trust Cache")
		return v.createTrustReport(hostId, hostData, reqs, trustCache, latestReqAndDefFlavorTypes)
	}

	missingRequiredFlavorPartsWithLatest := getMissingRequiredFlavorPartsWithLatest(hostId, reqs, reqAndDefFlavorTypes, trustCache.trustReport)
	if len(missingRequiredFlavorPartsWithLatest) != 0 {
		defaultLog.Trace("hosttrust/trust_report:CreateFlavorGroupReport() No results found for Required FlavorPartsWithLatest policy")
		return v.createTrustReport(hostId, hostData, reqs, trustCache, missingRequiredFlavorPartsWithLatest)
	}

	ruleAllOfFlavors := rules.AllOfFlavors{
		AllOfFlavors: reqs.AllOfFlavors,
		Markers:      reqs.getAllOfMarkers(),
	}
	if areAllOfFlavorsMissingInCachedTrustReport(trustCache.trustReport, ruleAllOfFlavors){
		defaultLog.Trace("hosttrust/trust_report:CreateFlavorGroupReport() All Of Flavors Missing In Cached TrustReport")
		return v.createTrustReport(hostId, hostData, reqs, trustCache, latestReqAndDefFlavorTypes)
	}

	return trustCache.trustReport, nil
}

func areAllOfFlavorsMissingInCachedTrustReport(cachedTrustReport hvs.TrustReport, ruleAllOfFlavors rules.AllOfFlavors) bool {
	return len(ruleAllOfFlavors.AllOfFlavors) != 0 && !ruleAllOfFlavors.CheckAllOfFlavorsExist(&cachedTrustReport)
}

func getMissingRequiredFlavorPartsWithLatest(hostId uuid.UUID, reqs flvGrpHostTrustReqs, reqAndDefFlavorTypes map[cf.FlavorPart]bool, cachedTrustReport hvs.TrustReport) map[cf.FlavorPart]bool {
	defaultLog.Trace("hosttrust/trust_report:getMissingRequiredFlavorPartsWithLatest() Entering")
	defer defaultLog.Trace("hosttrust/trust_report:getMissingRequiredFlavorPartsWithLatest() Leaving")
	var missingRequiredFlavorPartsWithLatest map[cf.FlavorPart]bool
	for flavorPart, _ := range reqAndDefFlavorTypes {
		defaultLog.Debugf("hosttrust/trust_report:getMissingRequiredFlavorPartsWithLatest() Checking if required flavor type %s for host %s is missing", flavorPart.String(), hostId.String())
		if areRequiredFlavorsMissing(cachedTrustReport, flavorPart) {
			defaultLog.Debugf("hosttrust/trust_report:getMissingRequiredFlavorPartsWithLatest() Required flavor type %s for host %s is missing", flavorPart.String(), hostId.String())
			matchPolicyMissing := getMatchPolicy(reqs.FlavorMatchPolicies, flavorPart)
			if matchPolicyMissing != nil && matchPolicyMissing.MatchType == hvs.MatchTypeLatest {
				missingRequiredFlavorPartsWithLatest[flavorPart] = true
			} else {
				missingRequiredFlavorPartsWithLatest[flavorPart] = false
			}
		}
	}
	return missingRequiredFlavorPartsWithLatest
}

func areRequiredFlavorsMissing(cachedTrustReport hvs.TrustReport, flavorPart cf.FlavorPart) bool {
	return cachedTrustReport.GetResultsForMarker(flavorPart.String()) == nil && len(cachedTrustReport.GetResultsForMarker(flavorPart.String())) == 0
}

// FlavorVerify.java: 529
func (v *Verifier) createTrustReport(hostId uuid.UUID, hostData *types.HostManifest, reqs flvGrpHostTrustReqs, trustCache hostTrustCache, latestReqAndDefFlavorTypes map[cf.FlavorPart]bool) (hvs.TrustReport, error) {
	defaultLog.Trace("hosttrust/trust_report:createTrustReport() Entering")
	defer defaultLog.Trace("hosttrust/trust_report:createTrustReport() Leaving")

	flavorParts := make([]cf.FlavorPart, len(latestReqAndDefFlavorTypes))
	for flavorPart, _ := range latestReqAndDefFlavorTypes {
		flavorParts = append(flavorParts, flavorPart)
	}

	hostManifestMap, err := getHostManifestMap(hostData, flavorParts)
	if err != nil {
		return hvs.TrustReport{}, errors.Wrap(err, "hosttrust/trust_report:createTrustReport() Error while creating host manifest map")
	}
	flavorsToVerify, err := v.findFlavors(reqs.FlavorGroupId, latestReqAndDefFlavorTypes, hostManifestMap)
	if err != nil {
		return hvs.TrustReport{}, errors.Wrap(err, "hosttrust/trust_report:createTrustReport() Error while finding flavors")
	}
	trustReport, err := v.verifyFlavors(hostId, flavorsToVerify, hostData, reqs)
	if err != nil {
		return hvs.TrustReport{}, errors.Wrap(err,"hosttrust/trust_report:createTrustReport() Error while verifying flavors" )
	}
	if !trustCache.isTrustCacheEmpty() {
		for _, ruleResult := range trustCache.trustReport.Results {
			trustReport.AddResult(ruleResult)
		}
	}

	for flavorPart, _ := range reqs.DefinedAndRequiredFlavorTypes {
		//To check only flavorpart=true?
		rule := rules.NewRequiredFlavorTypeExists(flavorPart)
		trustReport = rule.Apply(*trustReport)
	}

	ruleAllOfFlavors := rules.AllOfFlavors{
		AllOfFlavors: reqs.AllOfFlavors,
		Markers:      reqs.getAllOfMarkers(),
	}
	trustReport, err = ruleAllOfFlavors.AddFaults(v.FlavorVerifier.GetVerifierCerts(), trustReport)
	if err != nil {
		return hvs.TrustReport{}, errors.Wrap(err, "hosttrust/trust_report:createTrustReport() Error applying ruleAllOfFlavors")
	}
	return *trustReport, nil
}


func getMatchPolicy(flvMatchPolicies hvs.FlavorMatchPolicies, part cf.FlavorPart) *hvs.MatchPolicy {
	defaultLog.Trace("hosttrust/trust_report:getMatchPolicy() Entering")
	defer defaultLog.Trace("hosttrust/trust_report:getMatchPolicy() Leaving")

	for _, policy := range flvMatchPolicies {
		if policy.FlavorPart == part {
			return &policy.MatchPolicy
		}
	}
	return nil
}

// structure to hold the Flavor Report that is obtained from the verifier library
type flavorReport struct {
	id         uuid.UUID
	flavorPart cf.FlavorPart
	report     *hvs.TrustReport
	faultCount int
}

// FlavorVerify.java: 405
func (v *Verifier) verifyFlavors(hostID uuid.UUID, flavors []*hvs.SignedFlavor,
	hostData *types.HostManifest, hostTrustReqs flvGrpHostTrustReqs) (*hvs.TrustReport, error) {
	defaultLog.Trace("hosttrust/trust_report:verifyFlavors() Entering")
	defer defaultLog.Trace("hosttrust/trust_report:verifyFlavors() Leaving")

	collectiveTrustReport := hvs.TrustReport{}

	// need to create a map to hold all the untrusted individual reports and group them by the flavor part/type.
	untrusted := struct {
		report        hvs.TrustReport
		flavorPartMap map[cf.FlavorPart][]flavorReport
	}{
		report:        hvs.TrustReport{},
		flavorPartMap: make(map[cf.FlavorPart][]flavorReport),
	}

	newTrustCaches := make([]uuid.UUID, 0, len(flavors))

	for _, signedFlavor := range flavors {
		for _, flvMatchPolicy := range hostTrustReqs.FlavorMatchPolicies {
			// TODO
			// check nil pointer for Meta, Description
			// if these field are not changed to value type
			flvPart := signedFlavor.Flavor.Meta.Description.FlavorPart
			if flvPart == flvMatchPolicy.FlavorPart.String() {

				individualTrustReport, err := v.FlavorVerifier.Verify(hostData, signedFlavor, v.SkipFlavorSignatureVerification)
				if err != nil {
					return &hvs.TrustReport{}, errors.Wrap(err, "hosttrust/trust_report:verifyFlavors() Error verifying flavor")
				}
				if individualTrustReport.Trusted {
					collectiveTrustReport.Results = append(collectiveTrustReport.Results, individualTrustReport.Results...)
					newTrustCaches = append(newTrustCaches, signedFlavor.Flavor.Meta.ID)
				} else {
					// will need the fault count later on... just iterate through the results and determine the fault count
					faults := 0
					for _, result := range individualTrustReport.Results {
						faults += len(result.Faults)
						//TODO: do we need to log the faults here? Leave commented for now
						//for _, fault := range result.Faults{
						//	log.Debugf("Flavor [%s] did not match host [%s] due to fault: %s",
						//		signedFlavor.Flavor.Meta.ID, hostID, fault.Name )
						//}
					}
					untrusted.flavorPartMap[flvMatchPolicy.FlavorPart] =
						append(untrusted.flavorPartMap[flvMatchPolicy.FlavorPart], flavorReport{
							id:         signedFlavor.Flavor.Meta.ID,
							flavorPart: flvMatchPolicy.FlavorPart,
							report:     individualTrustReport,
							faultCount: faults,
						})

				}
			}
		}
	}

	for flavPart, flavPartReports := range untrusted.flavorPartMap {
		log.Debug("hosttrust/trust_report:verifyFlavors() Processing untrusted trust report for flavor part:", flavPart)
		if hostTrustReqs.DefinedAndRequiredFlavorTypes[flavPart] &&
			len(collectiveTrustReport.Results) == 0 || !collectiveTrustReport.IsTrustedForMarker(flavPart.String()) {
			if matchPolicy, matchPolicyExists := hostTrustReqs.FlavorPartMatchPolicy[flavPart]; matchPolicyExists && matchPolicy.MatchType == hvs.MatchTypeAllOf {
				log.Debug("hosttrust/trust_report:verifyFlavors() Flavor Part :", flavPart, " requires ALL_OF policy - each untrusted flavor needs to be added to collective report")
				for _, flavorReport := range flavPartReports {
					log.Debug("Adding untrusted trust report to collective report for ALL_OF flavor part", flavPart, " with flavor ID ", flavorReport.id)
					collectiveTrustReport.Results = append(collectiveTrustReport.Results, flavorReport.report.Results...)
					newTrustCaches = append(newTrustCaches, flavorReport.id)
				}

			} else if matchPolicy, matchPolicyExists := hostTrustReqs.FlavorPartMatchPolicy[flavPart]; matchPolicyExists && (matchPolicy.MatchType == hvs.MatchTypeAnyOf ||
				matchPolicy.MatchType == hvs.MatchTypeLatest) {
				log.Debug("hosttrust/trust_report:verifyFlavors() Flavor part requires ANY_OF policy, untrusted flavor report with least faults must be added to the collective report", flavPart)
				var leastFaultReport *flavorReport
				for _, flavorReport := range flavPartReports {

					//TODO: implement after GetFaults() is implemented
					if leastFaultReport == nil || flavorReport.faultCount < leastFaultReport.faultCount {
						leastFaultReport = &flavorReport
					}
				}
				if leastFaultReport != nil {
					log.Debug("hosttrust/trust_report:verifyFlavors() Adding untrusted trust report to collective report for ANY_OF flavor part, ",
						leastFaultReport.flavorPart, "with flavor ID ", leastFaultReport.id)
					collectiveTrustReport.Results = append(collectiveTrustReport.Results, leastFaultReport.report.Results...)
					newTrustCaches = append(newTrustCaches, leastFaultReport.id)
				}
			}
		}
	}
	if len(collectiveTrustReport.Results) == 0 {
		//TODO - check if we return an error here
		return &hvs.TrustReport{
			HostManifest: *hostData,
		}, nil
	}
	// save the trust cache // ignore error since it is just a cache.
	if _, err := v.HostStore.AddTrustCacheFlavors(hostID, newTrustCaches); err != nil {
		log.Error("hosttrust/trust_report:verifyFlavors() error while adding flavor trust cache to store for host id ", hostID, "error - ", err)
	}

	return &collectiveTrustReport, nil
}

// FlavorVerify.java: 684
//TODO find flavors by required key value
func (v *Verifier) findFlavors(flavorGroupID uuid.UUID, latestReqAndDefFlavorTypes map[cf.FlavorPart]bool, hostManifestMap map[cf.FlavorPart]map[string]interface{}) ([]*hvs.SignedFlavor, error) {
	defaultLog.Trace("hosttrust/trust_report:findFlavors() Entering")
	defer defaultLog.Trace("hosttrust/trust_report:findFlavors() Leaving")

	flavorPartsWithLatestMap := make(map[cf.FlavorPart]bool)
	for flavorPart, _ := range latestReqAndDefFlavorTypes {
		flavorPartsWithLatestMap[flavorPart] = true
	}

	flvrFilterCriteria := models.FlavorVerificationFC{
		FlavorFC: models.FlavorFilterCriteria{
			FlavorgroupID: flavorGroupID,
		},
		FlavorPartsWithLatest: flavorPartsWithLatestMap,
		FlavorMeta:            hostManifestMap,
	}

	signedFlavors, err := v.FlavorStore.Search(&flvrFilterCriteria)
	if err != nil {
		return nil, err
	}
	defaultLog.Debugf("%v from Flavorgroup %d Flavors retrieved for verification",  flavorGroupID, len(signedFlavors))
	return signedFlavors, nil
}

func getHostManifestMap(hostManifest *types.HostManifest, flavorParts []cf.FlavorPart) (map[cf.FlavorPart]map[string]interface{}, error) {
	defaultLog.Trace("hosttrust/trust_report:getHostManifestMap() Entering")
	defer defaultLog.Trace("hosttrust/trust_report:getHostManifestMap() Leaving")

	hostInfoMap := make(map[cf.FlavorPart]map[string]interface{})
	hostInfo := hostManifest.HostInfo
	if len(flavorParts) > 0 {
		for _, fp := range flavorParts {
			hostInfoValues := make(map[string]interface{})
			if fp == cf.FlavorPartPlatform {
				if hostInfo.BiosName != "" {
					hostInfoValues["bios_name"] = hostInfo.BiosName
				}
				if hostInfo.BiosVersion != "" {
					hostInfoValues["bios_version"] = hostInfo.BiosVersion
				}
				hostInfoValues["tboot_installed"] = hostInfo.TbootInstalled
				if !reflect.DeepEqual(hostInfo.HardwareFeatures, taModel.HardwareFeatures{}) {
					hostHwFeatures := make(map[string]string)
					if hostInfo.HardwareFeatures.CBNT != nil {
						hostHwFeatures[strings.ToUpper(fConst.Cbnt)] = strconv.FormatBool(hostInfo.HardwareFeatures.CBNT.Enabled)
						if hostInfo.HardwareFeatures.CBNT.Enabled {
							hostHwFeatures[strings.ToUpper(fConst.Cbnt)+"-profile"] = hostInfo.HardwareFeatures.CBNT.Meta.Profile
						}
					}
					if hostInfo.HardwareFeatures.SUEFI != nil {
						hostHwFeatures[strings.ToUpper(fConst.Suefi)] = strconv.FormatBool(hostInfo.HardwareFeatures.SUEFI.Enabled)
					}
					if hostInfo.HardwareFeatures.TPM.Enabled {
						hostHwFeatures[strings.ToUpper(fConst.Tpm)] = strconv.FormatBool(hostInfo.HardwareFeatures.TPM.Enabled)
					}
					if hostInfo.HardwareFeatures.TXT != nil {
						hostHwFeatures[strings.ToUpper(fConst.Txt)] = strconv.FormatBool(hostInfo.HardwareFeatures.TXT.Enabled)
					}
					hostInfoValues["hardware_features"] = hostHwFeatures
				}
			} else if fp == cf.FlavorPartOs {
				hostInfoValues["tboot_installed"] = hostInfo.TbootInstalled
				if hostInfo.OSName != "" {
					hostInfoValues["os_name"] = hostInfo.OSName
				}
				if hostInfo.OSVersion != "" {
					hostInfoValues["os_version"] = hostInfo.OSVersion
				}
				if hostInfo.VMMVersion != "" {
					hostInfoValues["vmm_version"] = hostInfo.VMMVersion
				}
				if hostInfo.VMMName != "" {
					hostInfoValues["vmm_name"] = hostInfo.VMMName
				}
			} else if fp == cf.FlavorPartHostUnique {
				hostInfoValues["tboot_installed"] = hostInfo.TbootInstalled
				if hostInfo.HardwareUUID != "" {
					hostInfoValues["hardware_uuid"] = strings.ToLower(hostInfo.HardwareUUID)
				}
			} else if fp == cf.FlavorPartAssetTag {
				if hostInfo.HardwareUUID != "" {
					hostInfoValues["hardware_uuid"] = strings.ToLower(hostInfo.HardwareUUID)
				}
			} else if fp == cf.FlavorPartSoftware {
				if !reflect.DeepEqual(&hostManifest.PcrManifest, types.PcrManifest{}) && len(hostManifest.MeasurementXmls) >= 1 {
					measurementLabels, err := getMeasurementLabels(hostManifest)
					if err != nil {
						return hostInfoMap, errors.Wrap(err, "error while getting labels from measurement XML")
					}
					hostInfoValues["measurementXML_labels"] = measurementLabels
				}
			} else {
				defaultLog.Errorf("Invalid flavor part - " + fp.String())
				//TODO: update to return error once trust_requirements:NewFlvGrpHostTrustReqs->getHostManifestMap is fixed
				//return nil, errors.New("Invalid flavor part - " + fp.String())
			}
			hostInfoMap[fp] = hostInfoValues
		}
	}
	return hostInfoMap, nil
}

// get software labels from the host manifest
func getMeasurementLabels(hostManifest *types.HostManifest) ([]string, error) {
	defaultLog.Trace("hosttrust/trust_report:getMeasurementLabels() Entering")
	defer defaultLog.Trace("hosttrust/trust_report:getMeasurementLabels() Leaving")

	var measurementLabels []string
	for _, measurementXml := range hostManifest.MeasurementXmls {
		var measurement taModel.Measurement
		err := xml.Unmarshal([]byte(measurementXml), &measurement)
		if err != nil {
			return nil, errors.Wrap(err, "An error occurred parsing measurement xml")
		}
		measurementLabels = append(measurementLabels, measurement.Label)
	}
	return measurementLabels, nil
}