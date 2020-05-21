/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package model

/**
 *
 * @author mullas
 */

// Validity holds the timestamps pertaining to the temporal validity of the Flavor
type Validity struct {
	NotBefore string `json:"not_before,omitempty"`
	NotAfter  string `json:"not_after,omitempty"`
}
