package hosttrust

import (
	"github.com/google/uuid"
	"github.com/intel-secl/intel-secl/v3/pkg/hvs/domain"
	"github.com/intel-secl/intel-secl/v3/pkg/hvs/domain/models"
	"github.com/intel-secl/intel-secl/v3/pkg/hvs/services/hosttrust/rules"
	cf "github.com/intel-secl/intel-secl/v3/pkg/lib/flavor/common"
	"github.com/intel-secl/intel-secl/v3/pkg/model/hvs"
	"github.com/pkg/errors"
	"reflect"
)

type flvGrpHostTrustReqs struct {
	HostId                        uuid.UUID
	FlavorGroupId                 uuid.UUID
	FlavorMatchPolicies           hvs.FlavorMatchPolicies
	MatchTypeFlavorParts          map[hvs.MatchType][]cf.FlavorPart
	AllOfFlavors                  []*hvs.SignedFlavor
	DefinedAndRequiredFlavorTypes map[cf.FlavorPart]bool
	FlavorPartMatchPolicy         map[cf.FlavorPart]hvs.MatchPolicy
}

func NewFlvGrpHostTrustReqs(hostId uuid.UUID, hwUUID uuid.UUID, fg hvs.FlavorGroup, fs domain.FlavorStore) (*flvGrpHostTrustReqs, error) {
	defaultLog.Trace("hosttrust/trust_requirements:NewFlvGrpHostTrustReqs() Entering")
	defer defaultLog.Trace("hosttrust/trust_requirements:NewFlvGrpHostTrustReqs() Leaving")

	reqs := flvGrpHostTrustReqs{
		HostId: hostId,
		FlavorGroupId:       fg.ID,
		FlavorMatchPolicies: fg.MatchPolicies,
	}

	var fgRequirePolicyMap map[hvs.FlavorRequiredPolicy][]cf.FlavorPart

	reqs.FlavorPartMatchPolicy, reqs.MatchTypeFlavorParts, fgRequirePolicyMap = fg.GetMatchPolicyMaps()

	if len(reqs.MatchTypeFlavorParts[hvs.MatchTypeAllOf]) > 0 {
		// TODO: this should really be a search on the flavorgroup store which should be able to retrieve a list
		// of flavor ids in the flavorgroup and then call the flavor store with a list of ids. Right now, it only
		// support one flavor id
		reqs.AllOfFlavors, _ = fs.Search(&models.FlavorFilterCriteria{
			// Flavor Parts of the Search Criteria takes a []cf.FlavorPart - but we have a map.
			// So dump keys of the map into a slice.
			FlavorGroupID: fg.ID,
			FlavorParts:   reqs.MatchTypeFlavorParts[hvs.MatchTypeAllOf],
		})
	}

	reqPartsMap := fgRequirePolicyMap[hvs.FlavorRequired]
	reqIfdefPartsMap := fgRequirePolicyMap[hvs.FlavorRequiredIfDefined]

	definedUniqueFlavorParts, err := fs.GetUniqueFlavorTypesThatExistForHost(hwUUID)
	if err != nil {
		return nil, errors.Wrap(err, "error gettting unique flavor types that exist for hardware id "+hwUUID.String())
	}

	for part, _ := range definedUniqueFlavorParts {
		if policy, exists := reqs.FlavorPartMatchPolicy[part]; !exists ||
			(exists && policy.Required != hvs.FlavorRequiredIfDefined && policy.Required != hvs.FlavorRequired) {
			delete(definedUniqueFlavorParts, part)
		}
	}

	// since the required if defined flavor part is a map and the function expect a slice,
	// convert from a map to a slice and call the GetFlavorTypesInFlavorgroup method
	// of FlavorRepository

	definedAutomaticFlavorParts, err := fs.GetFlavorTypesInFlavorgroup(fg.ID, reqIfdefPartsMap)

	// create the host defined and required falvorTypes by joining the map
	for _, part := range reqPartsMap {
		reqs.DefinedAndRequiredFlavorTypes[part] = true
	}
	// now add defined automatic flavor parts
	for part, _ := range definedAutomaticFlavorParts {
		reqs.DefinedAndRequiredFlavorTypes[part] = true
	}
	// add the host unique flavor parts
	for part, _ := range definedUniqueFlavorParts {
		reqs.DefinedAndRequiredFlavorTypes[part] = true
	}

	return &reqs, nil
}

func (r *flvGrpHostTrustReqs) GetLatestFlavorTypeMap() map[cf.FlavorPart]bool {
	defaultLog.Trace("hosttrust/trust_requirements:NewFlvGrpHostTrustReqs() Entering")
	defer defaultLog.Trace("hosttrust/trust_requirements:NewFlvGrpHostTrustReqs() Leaving")

	result := make(map[cf.FlavorPart]bool)
	for part, _ := range r.DefinedAndRequiredFlavorTypes {
		if r.FlavorPartMatchPolicy[part].MatchType == hvs.MatchTypeLatest {
			result[part] = true
		} else {
			result[part] = false
		}
	}
	return result
}

func (r *flvGrpHostTrustReqs) MeetsFlavorGroupReqs(trustCache hostTrustCache) bool {
	defaultLog.Trace("hosttrust/trust_requirements:MeetsFlavorGroupReqs() Entering")
	defer defaultLog.Trace("hosttrust/trust_requirements:MeetsFlavorGroupReqs() Leaving")

	if trustCache.isTrustCacheEmpty(){
		defaultLog.Debugf("No results found in trust cache for host: %s", r.HostId.String())
		return false
	}

	reqAndDefFlavorTypes := r.DefinedAndRequiredFlavorTypes
	missingRequiredFlavorPartsWithLatest := getMissingRequiredFlavorPartsWithLatest(r.HostId, *r, reqAndDefFlavorTypes, trustCache.trustReport)
	if len(missingRequiredFlavorPartsWithLatest) > 0{
		defaultLog.Debugf("Host %s has missing required and defined flavor parts: %s", r.HostId.String(), reflect.ValueOf(missingRequiredFlavorPartsWithLatest).MapKeys())
		return false
	}

	ruleAllOfFlavors := rules.AllOfFlavors{
		AllOfFlavors: r.AllOfFlavors,
		Markers:      r.getAllOfMarkers(),
	}

	if areAllOfFlavorsMissingInCachedTrustReport(trustCache.trustReport, ruleAllOfFlavors) {
		defaultLog.Debugf("All of flavors exist in policy for host: %s", r.HostId.String());
		defaultLog.Debugf("Some all of flavors do not match what is in the trust cache for host: %s", r.HostId.String())
		return false
	}
	defaultLog.Debugf("Trust cache valid for host: %s", r.HostId.String())
	return true
}

// According to verification-service: RuleAllOfFlavors.java
// the protected 'marker' variable inherited from lib-verifier: BaseRule.java
// does not at all effect the behavior of methods implemented in RuleAllOfFlavors
func (r *flvGrpHostTrustReqs) getAllOfMarkers() []cf.FlavorPart {
	defaultLog.Trace("hosttrust/trust_requirements:getAllOfMarkers() Entering")
	defer defaultLog.Trace("hosttrust/trust_requirements:getAllOfMarkers() Leaving")
	markers := make([]cf.FlavorPart, len(r.MatchTypeFlavorParts[hvs.MatchTypeAllOf]))
	for _, flavorPart := range r.MatchTypeFlavorParts[hvs.MatchTypeAllOf]{
		markers = append(markers, flavorPart)
	}
	return markers
}
