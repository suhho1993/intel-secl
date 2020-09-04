/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package keymanager

import (
	"errors"
	"github.com/google/uuid"
	"github.com/intel-secl/intel-secl/v3/pkg/kbs/domain/models"
	"github.com/intel-secl/intel-secl/v3/pkg/model/kbs"
)

type KmipManager struct {
}

func (km *KmipManager) CreateKey(request *kbs.KeyRequest) (*models.KeyAttributes, error) {
	defaultLog.Trace("keymanager/kmip_key_manager:CreateKey() Entering")
	defer defaultLog.Trace("keymanager/kmip_key_manager:CreateKey() Leaving")

	return nil, nil
}

func (km *KmipManager) DeleteKey(keyId uuid.UUID) error {
	defaultLog.Trace("keymanager/kmip_key_manager:DeleteKey() Entering")
	defer defaultLog.Trace("keymanager/kmip_key_manager:DeleteKey() Leaving")

	return nil
}

func (km *KmipManager) RegisterKey(request *kbs.KeyRequest) (*models.KeyAttributes, error) {
	defaultLog.Trace("keymanager/kmip_key_manager:RegisterKey() Entering")
	defer defaultLog.Trace("keymanager/kmip_key_manager:RegisterKey() Leaving")

	return nil, errors.New("register operation is not supported")
}

func (km *KmipManager) TransferKey(attributes *models.KeyAttributes) ([]byte, error) {
	defaultLog.Trace("keymanager/kmip_key_manager:TransferKey() Entering")
	defer defaultLog.Trace("keymanager/kmip_key_manager:TransferKey() Leaving")

	return nil, nil
}
