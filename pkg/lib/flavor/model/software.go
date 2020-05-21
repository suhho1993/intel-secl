/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package model

import (
	"github.com/intel-secl/intel-secl/v3/pkg/model/ta"
)

/**
 *
 * @author mullas
 */

// Software struct
type Software struct {
	Measurements   map[string]model.MeasurementType `json:"measurements,omitempty"`
	CumulativeHash string                           `json:"cumulative_hash,omitempty"`
}
