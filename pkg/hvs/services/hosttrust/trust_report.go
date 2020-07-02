package hosttrust

import (
	"github.com/google/uuid"
	"github.com/intel-secl/intel-secl/v3/pkg/hvs/domain/models"
	cf "github.com/intel-secl/intel-secl/v3/pkg/lib/flavor/common"
	"github.com/intel-secl/intel-secl/v3/pkg/lib/host-connector/types"
	"github.com/intel-secl/intel-secl/v3/pkg/lib/saml"
	"github.com/intel-secl/intel-secl/v3/pkg/model/hvs"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	// why is this package named "model"...?
	ta "github.com/intel-secl/intel-secl/v3/pkg/model/ta"
)

// FlavorVerify.java: 529
// renamed to createFlavorGroupReport and made it a receiver function since we need certificates
// from the config
func (v *verifier) createFlavorGroupReport(reqs flvGrpHostTrustReqs,
	hostData *types.HostManifest,
	cache hostTrustCache) hvs.TrustReport {
	//TODO: implement
	return hvs.TrustReport{}

}

// structure to hold the Flavor Report that is obtained from the verifier library
type flavorReport struct {
	id         uuid.UUID
	flavorPart cf.FlavorPart
	report     *hvs.TrustReport
	faultCount int
}

// FlavorVerify.java: 405
func verify(v *verifier, hostID uuid.UUID, flavors []hvs.SignedFlavor,
	hostData *types.HostManifest, hostTrustReqs flvGrpHostTrustReqs) (*hvs.TrustReport, error) {
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
				// TODO
				// skipFlavorSignatureVerification needs real values
				individualTrustReport, err := v.flavorVerifier.Verify(hostData, &signedFlavor, false)
				if err != nil {
					return &hvs.TrustReport{}, errors.Wrap(err, "Error verifying flavor")
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
		log.Debug("Processing untrusted trust report for flavor part:", flavPart)
		if hostTrustReqs.DefinedAndRequiredFlavorTypes[flavPart] &&
			len(collectiveTrustReport.Results) == 0 || !collectiveTrustReport.IsTrustedForMarker(flavPart.String()) {
			if matchPolicy, matchPolicyExists := hostTrustReqs.FlavorPartMatchPolicy[flavPart]; matchPolicyExists && matchPolicy.MatchType == hvs.MatchTypeAllOf {
				log.Debug("Flavor Part :", flavPart, " requires ALL_OF policy - each untrusted flavor needs to be added to collective report")
				for _, flavorReport := range flavPartReports {
					log.Debug("Adding untrusted trust report to collective report for ALL_OF flavor part", flavPart, " with flavor ID ", flavorReport.id)
					collectiveTrustReport.Results = append(collectiveTrustReport.Results, flavorReport.report.Results...)
					newTrustCaches = append(newTrustCaches, flavorReport.id)
				}

			} else if matchPolicy, matchPolicyExists := hostTrustReqs.FlavorPartMatchPolicy[flavPart]; matchPolicyExists && (matchPolicy.MatchType == hvs.MatchTypeAnyOf ||
				matchPolicy.MatchType == hvs.MatchTypeLatest) {
				log.Debug("Flavor part requires ANY_OF policy, untrusted flavor report with least faults must be added to the collective report", flavPart)
				var leastFaultReport *flavorReport
				for _, flavorReport := range flavPartReports {

					//TODO: implement after GetFaults() is implemented
					if leastFaultReport == nil || flavorReport.faultCount < leastFaultReport.faultCount {
						leastFaultReport = &flavorReport
					}
				}
				if leastFaultReport != nil {
					log.Debug("Adding untrusted trust report to collective report for ANY_OF flavor part, ",
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
	if _, err := v.hostStore.AddTrustCacheFlavors(hostID, newTrustCaches); err != nil {
		log.Error("error while adding flavor trust cache to store for host id ", hostID, "error - ", err)
	}

	log.Debugf("hosttrust/trust_report:verify() Generating new SAML for host: %s", hostID)
	samlReportGen := NewSamlReportGenerator(&v.tagIssuer)
	samlReport := samlReportGen.generateSamlReport(&collectiveTrustReport)

	log.Debugf("hosttrust/trust_report:verify() Saving new report for host: %s", hostID)
	storeTrustReport(v, hostID, &collectiveTrustReport, &samlReport)

	return &collectiveTrustReport, nil
}

func storeTrustReport(v *verifier, hostID uuid.UUID, trustReport *hvs.TrustReport, samlReport *saml.SamlAssertion) {
	defaultLog.Trace("hosttrust/trust_report:storeTrustReport() Entering")
	defer defaultLog.Trace("hosttrust/trust_report:storeTrustReport() Leaving")

	log.Debugf("hosttrust/trust_report:storeTrustReport() flavorverify host: %s SAML Report: %s", hostID, samlReport.Assertion)
	hvsReport := models.HVSReport{
		HostID:      hostID,
		TrustReport: *trustReport,
		CreatedAt:   samlReport.CreatedTime,
		Expiration:  samlReport.ExpiryTime,
		Saml:        samlReport.Assertion,
	}
	_, err := v.reportStore.Create(&hvsReport)
	if err != nil {
		log.WithError(err).Errorf("Failed to store Report")
	}
}

// FlavorVerify.java: 684
func findFlavors(flavorGroupID uuid.UUID, hostManifest ta.Manifest,
	latestReqAndDefFlavorTypes map[string]bool) (hvs.SignedFlavorCollection, error) {

	return hvs.SignedFlavorCollection{}, nil
}
