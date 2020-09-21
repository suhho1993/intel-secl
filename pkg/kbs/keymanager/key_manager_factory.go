/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package keymanager

import (
	"github.com/intel-secl/intel-secl/v3/pkg/kbs/config"
	"github.com/intel-secl/intel-secl/v3/pkg/kbs/constants"
	"strings"
)

type KeyManagerFactory struct {
	cfg *config.Configuration
}

func NewKeyManagerFactory(cfg *config.Configuration) *KeyManagerFactory {
	return &KeyManagerFactory{cfg:cfg}
}

func (kmf *KeyManagerFactory) GetKeyManager() KeyManager {

	if strings.ToLower(kmf.cfg.KeyManager) == constants.KmipKeyManager {
		return &KmipManager{}
	} else {
		return &DirectoryManager{}
	}
}
