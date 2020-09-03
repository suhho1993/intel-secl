/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package models

import (
	"time"

	"github.com/google/uuid"
)

type DefaultTransferPolicy struct {
	ID             uuid.UUID `json:"id"`
	CreatedAt      time.Time `json:"created_at"`
	TransferPolicy string    `json:"transfer_policy"`
}
