/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */

package hosttrust

import (
	"errors"
	"fmt"
	"github.com/google/uuid"
	"github.com/intel-secl/intel-secl/v3/pkg/hvs/domain"
	"github.com/intel-secl/intel-secl/v3/pkg/hvs/domain/models"
	"github.com/intel-secl/intel-secl/v3/pkg/lib/host-connector/types"
	flavorVerifier "github.com/intel-secl/intel-secl/v3/pkg/lib/verifier"
	"github.com/intel-secl/intel-secl/v3/pkg/model/hvs"
	log "github.com/sirupsen/logrus"
)

var ErrInvalidHostManiFest = errors.New("invalid host data")
var ErrManifestMissingHwUUID = errors.New("host data missing hardware uuid")
var ErrMissingHostId = errors.New("host id ")

type verifier struct {
	flavorStore      domain.FlavorStore
	flavorGroupStore domain.FlavorGroupStore
	hostStore        domain.HostStore
	flavorVerifier   flavorVerifier.Verifier
	certsStore       models.CertificatesStore
}

func NewVerifier(cfg domain.HostTrustVerifierConfig) domain.HostTrustVerifier {
	return &verifier{
		flavorStore:      cfg.FlavorStore,
		flavorGroupStore: cfg.FlavorGroupStore,
		hostStore:        cfg.HostStore,
		flavorVerifier:   cfg.FlavorVerifier,
		certsStore:       cfg.CertsStore,
	}

}

func (v *verifier) Verify(hostId uuid.UUID, hostData *types.HostManifest, newData bool) error {

	if hostData == nil {
		return ErrInvalidHostManiFest
	}
	//TODO: Fix HardwareUUID has to be uuid
	hwUuid, err := uuid.Parse(hostData.HostInfo.HardwareUUID)
	if err != nil || hwUuid == uuid.Nil {
		return ErrManifestMissingHwUUID
	}

	// TODO : remove this when we remove the intermediate collection
	var flvGroups []*hvs.FlavorGroup
	if flvGroupColl, err := v.flavorGroupStore.Search(&models.FlavorGroupFilterCriteria{HostId: hostId.String()}); err != nil {
		return errors.New("Store access error")
	} else {
		flvGroups = (*flvGroupColl).Flavorgroups
	}

	// start with the presumption that final trust report would be true. It as some point, we get an invalid report,
	// the Overall trust status would be negative
	var finalReportValid = true // This is the final trust report - initialize
	// create an empty trust report with the host manifest
	finalTrustReport := hvs.TrustReport{HostManifest: *hostData}

	for _, fg := range flvGroups {
		//TODO - handle errors in case of DB transaction
		fgTrustReqs, _ := NewFlvGrpHostTrustReqs(hostId, hwUuid, *fg, v.flavorStore)
		fgCachedFlavors, _ := v.getCachedFlavors(hostId, (*fg).ID)
		if len(fgCachedFlavors) > 0 {
			fgTrustCache, _ := v.validateCachedFlavors(hostId, hostData, fgCachedFlavors)
			fgTrustReport := fgTrustCache.trustReport
			if !fgTrustReqs.MeetsFlavorGroupReqs(fgTrustCache) {
				finalReportValid = false
				fgTrustReport = v.createFlavorGroupReport(*fgTrustReqs, hostData, fgTrustCache)

			}
			log.Debug("Trust status for host id", hostId, "for flavorgroup ", fg.ID, "is", fgTrustReport.Trusted)
			// append the results
			finalTrustReport.Results = append(finalTrustReport.Results, fgTrustReport.Results...)
		}
	}
	// create a new report if we actually have any results and either the Final Report is untrusted or
	// we have new Data from the host and therefore need to update based on the new report.
	if len(finalTrustReport.Results) > 0 && !finalReportValid || newData {
		log.Debug("Saving new report for host ", hostId)

	}

	return nil
}

func (v *verifier) getCachedFlavors(hostId uuid.UUID, flavGrpId uuid.UUID) ([]hvs.SignedFlavor, error) {

	// retrieve the IDs of the trusted flavors from the host store
	if flIds, err := v.hostStore.RetrieveTrustCacheFlavors(hostId, flavGrpId); err != nil {
		return nil, fmt.Errorf("store err : %v", err)
	} else {
		result := make([]hvs.SignedFlavor, 0, len(flIds))
		for _, flvId := range flIds {
			if flv, err := v.flavorStore.Retrieve(flvId); err == nil {
				result = append(result, *flv)
			}

		}
		return result, nil

	}
}

func (v *verifier) validateCachedFlavors(hostId uuid.UUID,
	hostData *types.HostManifest,
	cachedFlavors []hvs.SignedFlavor) (hostTrustCache, error) {
	htc := hostTrustCache{
		hostID: hostId,
	}
	var collectiveReport hvs.TrustReport
	var trustCachesToDelete []uuid.UUID
	for _, cachedFlavor := range cachedFlavors {
		//TODO: change the signature verification depending on decision on signed flavors
		report, err := v.flavorVerifier.Verify(hostData, &cachedFlavor, true)
		if err != nil {
			return hostTrustCache{}, err
		}
		if report.Trusted {
			htc.trustedFlavors = append(htc.trustedFlavors, cachedFlavor.Flavor)
			collectiveReport.Results = append(collectiveReport.Results, report.Results...)
		} else {
			trustCachesToDelete = append(trustCachesToDelete, cachedFlavor.Flavor.Meta.ID)
		}
	}
	// remove cache entries for flavors that could not be verified
	_ = v.hostStore.RemoveTrustCacheFlavors(hostId, trustCachesToDelete)
	htc.trustReport = collectiveReport
	return htc, nil
}

func (v *verifier) storeReport(hostId uuid.UUID, report hvs.TrustReport) {
	// TODO implement
}
