/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */

package models

import (
	"github.com/google/uuid"
	"github.com/intel-secl/intel-secl/v3/pkg/model/hvs"
	"time"
)

type HVSReport struct {
	ID          uuid.UUID       `json:"id,omitempty"`
	HostID      uuid.UUID       `json:"host_id"`
	TrustReport hvs.TrustReport `json:"trust_report"`
	CreatedAt   time.Time       `json:"created"`
	Expiration  time.Time       `json:"expiration"`
	Saml        string          `json:"saml"`
}

