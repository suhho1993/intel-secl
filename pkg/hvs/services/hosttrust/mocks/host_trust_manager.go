/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package mocks

import (
	"github.com/google/uuid"
	"github.com/intel-secl/intel-secl/v3/pkg/hvs/domain/models"
)

type MockHostTrustManager struct{}

func (mock *MockHostTrustManager) VerifyHost(hostId uuid.UUID, fetchHostData, preferHashMatch bool) (*models.HVSReport, error) {
	return nil, nil
}

func (mock *MockHostTrustManager) VerifyHostsAsync(hostIds []uuid.UUID, fetchHostData, preferHashMatch bool) error {
	return nil
}
