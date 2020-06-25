/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package domain

import (
	"context"
	"github.com/google/uuid"
	"github.com/intel-secl/intel-secl/v3/pkg/hvs/domain/models"
	"github.com/intel-secl/intel-secl/v3/pkg/model/hvs"
	tamodel "github.com/intel-secl/intel-secl/v3/pkg/model/ta"
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

	TpmEndorsementStore interface {
		Create(*hvs.TpmEndorsement) (*hvs.TpmEndorsement, error)
		Update(*hvs.TpmEndorsement) (*hvs.TpmEndorsement, error)
		Retrieve(uuid.UUID) (*hvs.TpmEndorsement, error)
		Search(*models.TpmEndorsementFilterCriteria) (*hvs.TpmEndorsementCollection, error)
		Delete(uuid.UUID) error
	}
	// TODO: Define all contract methods here

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

	ReportStore interface {
		Search(*models.ReportFilterCriteria) ([]*models.HVSReport, error)
		Retrieve(uuid.UUID) (*models.HVSReport, error)
		Create(*models.HVSReport) (*models.HVSReport, error)
		Update(*models.HVSReport) (*models.HVSReport, error)
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

	HostTrustManager interface {
		// Verify the trust of the a host.
		//Returns the host trust report. For now marking this as interface since we have not defined the report structure
		VerifyHost(hostId uuid.UUID, fetchHostData, preferHashMatch bool) (interface{}, error)

		// This method is an ansychrounous method meant to do the verify the trust of the host
		// asynchronously. The request are persisted to Store in case the server is taken down.
		// Parameters:
		// hostIds - slice of hosts id whose trust should be verified
		// fetchHostData - Fetch a new Manifest/Data from the host.
		// preferHashMatch - Can attempt to do match a cumulative hash from the Host Manifest/ Data rather than
		//                   doing a full report.
		VerifyHostsAsync(hostIds []uuid.UUID, fetchHostData, preferHashMatch bool) error
	}

	HostDataReceiver interface {
		ProcessHostData(context.Context, hvs.Host, *tamodel.Manifest, error) error
	}

	HostDataFetcher interface {
		// Synchronous method that blocks till the data is retrieved from the host.
		Retrieve(context.Context, hvs.Host) (*tamodel.Manifest, error)

		// Asynchronous method to be used to fetch data from hosts. As soon as the request is registered,
		// the method returns. The result is returned individually as they are processed.
		// We need the single host method a there is a need to cancel individual host fetch
		// using the context
		RetriveAsync(context.Context, hvs.Host, ...HostDataReceiver) error

		// TODO: ? Do we need a method that can use used to pass in a list rather than one at a time
		// RetriveMultipleAsync(context.Context, []*hvs.Host, rcvrs ...HostDataReceiver) error
	}
)
