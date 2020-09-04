/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package keymanager

import (
	"github.com/google/uuid"
	"github.com/intel-secl/intel-secl/v3/pkg/kbs/domain/models"
	"github.com/intel-secl/intel-secl/v3/pkg/model/kbs"
)

type KeyManager interface {
	CreateKey(*kbs.KeyRequest) (*models.KeyAttributes, error)
	DeleteKey(uuid.UUID) error
	RegisterKey(*kbs.KeyRequest) (*models.KeyAttributes, error)
	TransferKey(*models.KeyAttributes) ([]byte, error)
}
