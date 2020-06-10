/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package domain

import (
	"github.com/google/uuid"
	"github.com/intel-secl/intel-secl/v3/pkg/hvs/domain/models"
	"github.com/intel-secl/intel-secl/v3/pkg/model/hvs"
)

type (
	FlavorGroupStore interface {
		Create(*hvs.FlavorGroup) (*hvs.FlavorGroup, error)
		Retrieve(*uuid.UUID) (*hvs.FlavorGroup, error)
		Search(*hvs.FlavorGroupFilterCriteria) (*hvs.FlavorgroupCollection, error)
		Delete(*uuid.UUID) error
	}

	TlsPolicyStore interface {
		Create(*hvs.TlsPolicy) (*hvs.TlsPolicy, error)
		Retrieve(uuid.UUID) (*hvs.TlsPolicy, error)
		Update(*hvs.TlsPolicy) (*hvs.TlsPolicy, error)
		Delete(uuid.UUID) error
		Search(*hvs.TlsPolicyFilterCriteria) (*hvs.TlsPolicyCollection, error)
	}

	FlavorStore interface {
	}
	// TODO: Define all contract methods here

	QueueStore interface {
		Search(*models.QueueFilterCriteria) ([]*models.Queue, error)
		Retrieve(uuid.UUID) (*models.Queue, error)
		Update(*models.Queue) error
		Create(*models.Queue) (*models.Queue, error)
		Delete(uuid.UUID) error
	}
)
