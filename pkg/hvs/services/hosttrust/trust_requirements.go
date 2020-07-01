package hosttrust

import (
	"github.com/google/uuid"
	"github.com/intel-secl/intel-secl/v3/pkg/hvs/domain"
	"github.com/intel-secl/intel-secl/v3/pkg/hvs/domain/models"
	cf "github.com/intel-secl/intel-secl/v3/pkg/lib/flavor/common"
	"github.com/intel-secl/intel-secl/v3/pkg/model/hvs"
	"github.com/pkg/errors"
)

type flvGrpHostTrustReqs struct {
	FlavorGroupId                 uuid.UUID
	FlavorMatchPolicies           hvs.FlavorMatchPolicies
	AllOfFlavorTypes              map[cf.FlavorPart]bool
	AllOfFlavors                  []*hvs.SignedFlavor
	DefinedAndRequiredFlavorTypes map[cf.FlavorPart]bool
	FlavorPartMatchPolicy         map[cf.FlavorPart]hvs.MatchPolicy
}

func NewFlvGrpHostTrustReqs(hostId uuid.UUID, hwUUID uuid.UUID, fg hvs.FlavorGroup, fs domain.FlavorStore) (*flvGrpHostTrustReqs, error) {

	reqs := flvGrpHostTrustReqs{
		FlavorGroupId:       fg.ID,
		FlavorMatchPolicies: fg.MatchPolicies,
	}

	var fgMatchTypeMap map[hvs.MatchType]map[cf.FlavorPart]bool
	var fgRequirePolicyMap map[hvs.FlavorRequiredPolicy]map[cf.FlavorPart]bool

	reqs.FlavorPartMatchPolicy, fgMatchTypeMap, fgRequirePolicyMap = fg.GetMatchPolicyMaps()

	reqs.AllOfFlavorTypes = fgMatchTypeMap[hvs.MatchTypeAllOf]
	if len(reqs.AllOfFlavorTypes) > 0 {
		reqs.AllOfFlavors, _ = fs.Search(&models.FlavorFilterCriteria{
			// Flavor Parts of the Search Criteria takes a []cf.FlavorPart - but we have a map.
			// So dump keys of the map into a slice.
			FlavorParts: func(mp map[cf.FlavorPart]bool) []cf.FlavorPart {
				ret := []cf.FlavorPart{}
				for part, _ := range mp {
					ret = append(ret, part)
				}
				return ret
			}(reqs.AllOfFlavorTypes),
		})
	}

	reqPartsMap := fgRequirePolicyMap[hvs.FlavorRequired]
	reqIfdefPartsMap := fgRequirePolicyMap[hvs.FlavorRequiredIfDefined]

	definedUniqueFlavorParts, err := fs.GetUniqueFlavorTypesThatExistForHost(hwUUID)
	if err != nil {
		return nil, errors.Wrap(err, "Database error")
	}

	for part, _ := range definedUniqueFlavorParts {
		if _, exists := reqIfdefPartsMap[part]; !exists {
			if _, exists := reqPartsMap[part]; !exists {
				delete(definedUniqueFlavorParts, part)
			}
		}
	}

	// since the required if defined flavor part is a map and the function expect a slice,
	// convert from a map to a slice and call the GetFlavorTypesInFlavorgroup method
	// of FlavorRepository

	definedAutomaticFlavorParts, err := fs.GetFlavorTypesInFlavorgroup(fg.ID, reqIfdefPartsMap)

	// create the host defined and required falvorTypes by joining the map

	reqs.DefinedAndRequiredFlavorTypes = reqPartsMap
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

func (r *flvGrpHostTrustReqs) MeetsFlavorGroupReqs(cache hostTrustCache) bool {
	//TODO: implement
	return true
}
