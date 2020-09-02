/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package kbs

import (
	"time"
)

//Certificate stores the decoded certificate values
type Certificate struct {
	ID          string     `json:"id"`
	Certificate string     `json:"certificate"`
	Subject     string     `json:"subject,omitempty"`
	Issuer      string     `json:"issuer,omitempty"`
	Digest      string     `json:"digest,omitempty"`
	NotBefore   *time.Time `json:"not_before,omitempty"`
	NotAfter    *time.Time `json:"not_after,omitempty"`
	Revoked     bool       `json:"revoked,omitempty"`
}
