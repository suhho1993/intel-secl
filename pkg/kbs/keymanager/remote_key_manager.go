/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package keymanager

import (
	"fmt"
	"github.com/google/uuid"
	"github.com/intel-secl/intel-secl/v3/pkg/kbs/domain"
	"github.com/intel-secl/intel-secl/v3/pkg/kbs/domain/models"
	"github.com/intel-secl/intel-secl/v3/pkg/lib/common/log"
	"github.com/intel-secl/intel-secl/v3/pkg/model/kbs"
)

var defaultLog = log.GetDefaultLogger()

type RemoteManager struct {
	Store       domain.KeyStore
	Manager     KeyManager
	EndpointURL string
}

func (rm *RemoteManager) CreateKey(request *kbs.KeyRequest) (*kbs.KeyResponse, error) {
	defaultLog.Trace("keymanager/remote_key_manager:CreateKey() Entering")
	defer defaultLog.Trace("keymanager/remote_key_manager:CreateKey() Leaving")

	keyAttributes, err := rm.Manager.CreateKey(request)
	if err != nil {
		return nil, err
	}

	keyAttributes.TransferLink = rm.getTransferLink(keyAttributes.ID)
	storedKey, err := rm.Store.Create(keyAttributes)
	if err != nil {
		return nil, err
	}

	return storedKey.ToKeyResponse(), nil
}

func (rm *RemoteManager) RetrieveKey(keyId uuid.UUID) (*kbs.KeyResponse, error) {
	defaultLog.Trace("keymanager/remote_key_manager:RetrieveKey() Entering")
	defer defaultLog.Trace("keymanager/remote_key_manager:RetrieveKey() Leaving")

	keyAttributes, err := rm.Store.Retrieve(keyId)
	if err != nil {
		return nil, err
	}

	return keyAttributes.ToKeyResponse(), nil
}

func (rm *RemoteManager) DeleteKey(keyId uuid.UUID) error {
	defaultLog.Trace("keymanager/remote_key_manager:DeleteKey() Entering")
	defer defaultLog.Trace("keymanager/remote_key_manager:DeleteKey() Leaving")

	if err := rm.Manager.DeleteKey(keyId); err != nil {
		return err
	}

	return rm.Store.Delete(keyId)
}

func (rm *RemoteManager) SearchKeys(criteria *models.KeyFilterCriteria) ([]*kbs.KeyResponse, error) {
	defaultLog.Trace("keymanager/remote_key_manager:SearchKeys() Entering")
	defer defaultLog.Trace("keymanager/remote_key_manager:SearchKeys() Leaving")

	keyAttributesList, err := rm.Store.Search(criteria)
	if err != nil {
		return nil, err
	}

	var keyResponses []*kbs.KeyResponse
	for _, keyAttributes := range keyAttributesList {
		keyResponses = append(keyResponses, keyAttributes.ToKeyResponse())
	}

	return keyResponses, nil
}

func (rm *RemoteManager) RegisterKey(request *kbs.KeyRequest) (*kbs.KeyResponse, error) {
	defaultLog.Trace("keymanager/remote_key_manager:RegisterKey() Entering")
	defer defaultLog.Trace("keymanager/remote_key_manager:RegisterKey() Leaving")

	keyAttributes, err := rm.Manager.RegisterKey(request)
	if err != nil {
		return nil, err
	}

	keyAttributes.TransferLink = rm.getTransferLink(keyAttributes.ID)
	storedKey, err := rm.Store.Create(keyAttributes)
	if err != nil {
		return nil, err
	}

	return storedKey.ToKeyResponse(), nil
}

func (rm *RemoteManager) TransferKey(keyId uuid.UUID) ([]byte, error) {
	defaultLog.Trace("keymanager/remote_key_manager:TransferKey() Entering")
	defer defaultLog.Trace("keymanager/remote_key_manager:TransferKey() Leaving")

	keyAttributes, err := rm.Store.Retrieve(keyId)
	if err != nil {
		return nil, err
	}

	return rm.Manager.TransferKey(keyAttributes)
}

func (rm *RemoteManager) getTransferLink(keyId uuid.UUID) string {
	defaultLog.Trace("keymanager/remote_key_manager:getTransferLink() Entering")
	defer defaultLog.Trace("keymanager/remote_key_manager:getTransferLink() Leaving")

	return fmt.Sprintf("%s/keys/%s/transfer", rm.EndpointURL, keyId.String())
}
