/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package verifier

import (
	"encoding/xml"
	"github.com/google/uuid"
	"github.com/pkg/errors"
	"github.com/intel-secl/intel-secl/v3/pkg/lib/host-connector/types"
	"github.com/intel-secl/intel-secl/v3/pkg/model/hvs"
	"github.com/intel-secl/intel-secl/v3/pkg/model/ta"
	flavor_model "github.com/intel-secl/intel-secl/v3/pkg/lib/flavor/model"
)

// Utility function that finds the hvs.PcrEx at 'bank' and 'index' and returns
// the corresponding host-connector PCR value.  This is typically used by polcies
// when createing rules from the flavor values.
func getPcrValueFromFlavor(flavor *hvs.Flavor, bank types.SHAAlgorithm, index types.PcrIndex) (*types.Pcr, error) {
	if flavor == nil {
		return nil, errors.New("The flavor cannot be nil")
	}

	pcrValue, err := flavor.GetPcrValue(bank, index) 
	if err != nil {
		return nil, err
	}

	return flavorPcr2ManifestPcr(pcrValue, bank, index)
}

func flavorPcr2ManifestPcr(pcrEx *flavor_model.PcrEx, bank types.SHAAlgorithm, index types.PcrIndex) (*types.Pcr, error) {

	if pcrEx == nil {
		return nil, errors.New("The pcrex value cannot be nil")
	}

	return &types.Pcr {
		Value: pcrEx.Value,
		Index: index,
		PcrBank : bank,
	}, nil
}

// lookup the Measurement from the host manifest
func getMeasurementAssociatedWithFlavor(hostManifest *types.HostManifest, flavorId uuid.UUID, flavorLabel string) (*model.Measurement, []byte, error) {
	
	for i, measurementXml := range(hostManifest.MeasurementXmls) {
		var measurement model.Measurement
		xmlBytes := []byte(measurementXml)

		err := xml.Unmarshal(xmlBytes, &measurement)
		if err != nil {
			return nil, nil, errors.Wrapf(err, "An error occurred parsing measurement xml index %d", i)
		}

		if flavorId.String() == measurement.Uuid && flavorLabel == measurement.Label {
			return &measurement, xmlBytes, nil
		}
	}

	// not an error, just return nil
	return nil, nil, nil
}
