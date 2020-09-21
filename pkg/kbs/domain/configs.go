/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package domain

import "github.com/google/uuid"

type KeyControllerConfig struct {
	SamlCertsDir            string
	TrustedCaCertsDir       string
	TpmIdentityCertsDir     string
	DefaultTransferPolicyId uuid.UUID
}
