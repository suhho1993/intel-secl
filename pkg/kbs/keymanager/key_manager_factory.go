/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package keymanager

import (
	"strings"

	"github.com/intel-secl/intel-secl/v3/pkg/kbs/config"
	"github.com/intel-secl/intel-secl/v3/pkg/kbs/constants"
	"github.com/intel-secl/intel-secl/v3/pkg/kbs/kmipclient"
	"github.com/intel-secl/intel-secl/v3/pkg/lib/common/log"
)

var defaultLog = log.GetDefaultLogger()

// Provider is an interface implemented by Factory for injecting KeyManager instances at runtime
type Provider interface {
	NewKeyManager(string) (KeyManager, error)
}

type Factory struct {
	cfg *config.KmipConfig
}

func NewKeyManagerFactory(cfg *config.KmipConfig) *Factory {
	return &Factory{cfg: cfg}
}

func (kmf *Factory) NewKeyManager(provider string) (KeyManager, error) {
	defaultLog.Trace("keymanager/key_manager_factory:NewKeyManager() Entering")
	defer defaultLog.Trace("keymanager/key_manager_factory:NewKeyManager() Leaving")

	if strings.ToLower(provider) == constants.KmipKeyManager {
		kmipClient := kmipclient.NewKmipClient()
		err := kmipClient.InitializeClient(kmf.cfg.ServerIP, kmf.cfg.ServerPort, kmf.cfg.ClientCert, kmf.cfg.ClientKey, kmf.cfg.RootCert)
		if err != nil {
			return nil, err
		}
		return &KmipManager{kmipClient}, nil
	} else {
		return &DirectoryManager{}, nil
	}
}
