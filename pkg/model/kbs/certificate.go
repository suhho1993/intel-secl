/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package kbs

import (
	"time"

	"github.com/google/uuid"
)

//Certificate stores the decoded certificate values
type Certificate struct {
	ID          uuid.UUID  `json:"id"`
	Certificate []byte     `json:"certificate"`
	Subject     string     `json:"subject,omitempty"`
	Issuer      string     `json:"issuer,omitempty"`
	NotBefore   *time.Time `json:"not_before,omitempty"`
	NotAfter    *time.Time `json:"not_after,omitempty"`
	Revoked     bool       `json:"revoked,omitempty"`
	Digest      string     `json:"digest,omitempty"`
}
