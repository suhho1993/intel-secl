/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package types

import (
	"encoding/json"
	"encoding/xml"
	cf "github.com/intel-secl/intel-secl/v3/pkg/lib/flavor/common"
	"github.com/intel-secl/intel-secl/v3/pkg/model/hvs"
	taModel "github.com/intel-secl/intel-secl/v3/pkg/model/ta"
	"github.com/pkg/errors"
)

/**
 *
 * @author mullas
 */

// SoftwareFlavor represents a flavor consisting primarily of the integrity measurements taken on Software environment
// of the target host
type SoftwareFlavor struct {
	Measurement string `json:"measurement"`
}

// NewSoftwareFlavor returns an instance of SoftwareFlavor
func NewSoftwareFlavor(measurement string) SoftwareFlavor {
	return SoftwareFlavor{Measurement: measurement}
}

// GetSoftwareFlavor creates a SoftwareFlavor that would include all the measurements provided in input.
func (sf *SoftwareFlavor) GetSoftwareFlavor() (string, error) {
	var errorMessage = "Error during creation of SOFTWARE flavor"
	var measurements taModel.Measurement
	var err error
	err = xml.Unmarshal([]byte(sf.Measurement), &measurements)
	if err != nil {
		return "", err
	}
	var software = sfutil.GetSoftware(measurements)
	// create meta section details
	newMeta, err := pfutil.GetMetaSectionDetails(nil, nil, sf.Measurement, cf.Software, "")
	if err != nil {
		err = errors.Wrap(err, errorMessage+" Failure in Meta section details")
		return "", err
	}

	f := hvs.NewFlavor(newMeta, nil, nil, nil, nil, &software)
	strf, err := json.Marshal(f)
	if err != nil {
		err = errors.Wrapf(err, "Error marshalling SoftwareFlavor: %s", err)
		return "", err
	}
	return string(strf), nil
}
