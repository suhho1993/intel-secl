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
		Retrieve(uuid.UUID) (*hvs.FlavorGroup, error)
		Search(*models.FlavorGroupFilterCriteria) (*hvs.FlavorgroupCollection, error)
		Delete(uuid.UUID) error
	}

	HostStore interface {
		Create(*hvs.Host) (*hvs.Host, error)
		Retrieve(uuid.UUID) (*hvs.Host, error)
		Update(*hvs.Host) (*hvs.Host, error)
		Delete(uuid.UUID) error
		Search(*models.HostFilterCriteria) (*hvs.HostCollection, error)
	}

	FlavorStore interface {
		Create(*hvs.SignedFlavor) (*hvs.SignedFlavor, error)
		Retrieve(uuid.UUID) (*hvs.SignedFlavor, error)
		Search(*models.FlavorFilterCriteria) ([]*hvs.SignedFlavor, error)
		Delete(uuid.UUID) error
	}

	// HostStatusStore specifies the DB operations that must be implemented for the Host Status API
	HostStatusStore interface {
		Create(*hvs.HostStatus) (*hvs.HostStatus, error)
		Retrieve(uuid.UUID) (*hvs.HostStatus, error)
		Search(*models.HostStatusFilterCriteria) (*hvs.HostStatusCollection, error)
		Delete(uuid.UUID) error
		Update(*hvs.HostStatus) error
	}

	QueueStore interface {
		Search(*models.QueueFilterCriteria) ([]*models.Queue, error)
		Retrieve(uuid.UUID) (*models.Queue, error)
		Update(*models.Queue) error
		Create(*models.Queue) (*models.Queue, error)
		Delete(uuid.UUID) error
	}

	ESXiClusterStore interface {
		Create(*hvs.ESXiCluster) (*hvs.ESXiCluster, error)
		Retrieve(uuid.UUID) (*hvs.ESXiCluster, error)
		Search(*models.ESXiClusterFilterCriteria) (*hvs.ESXiClusterCollection, error)
		Delete(uuid.UUID) error
	}

	// TagCertificateStore enumerates the operations expected to be performed on a TagCertificate backend
	TagCertificateStore interface {
		Create(*hvs.TagCertificate) (*hvs.TagCertificate, error)
		Retrieve(uuid.UUID) (*hvs.TagCertificate, error)
		Delete(uuid.UUID) error
		Search(*models.TagCertificateFilterCriteria) ([]*hvs.TagCertificate, error)
	}
)
