package hosttrust

import (
	"github.com/intel-secl/intel-secl/v3/pkg/model/hvs"

	"github.com/google/uuid"
)

type hostTrustCache struct {
	hostID         uuid.UUID
	trustedFlavors []hvs.Flavor
	// TODO: consider using a map here rather than traversing through the list when we need to remove flavors
	trustReport hvs.TrustReport
}

// TODO:
// These functions should have been implemented in
// "github.com/intel-secl/intel-secl/v3/pkg/model/hvs"
// for the structure hvs.FlavorCollection
func (htc *hostTrustCache) addTrustedFlavors(f *hvs.Flavor) {
	htc.trustedFlavors = append(htc.trustedFlavors, *f)
}

func (htc *hostTrustCache) removeTrustedFlavors(fIn *hvs.Flavor) {
	if fIn == nil {
		return
	}
	targetID := fIn.Meta.ID
	for i, f := range htc.trustedFlavors {
		if f.Meta.ID == targetID {
			htc.trustedFlavors = append(htc.trustedFlavors[:i], htc.trustedFlavors[i+1:]...)
		}
	}
}
