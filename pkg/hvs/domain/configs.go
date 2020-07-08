/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */

package domain

import (
	"github.com/intel-secl/intel-secl/v3/pkg/hvs/domain/models"
	"github.com/intel-secl/intel-secl/v3/pkg/lib/host-connector"
	"github.com/intel-secl/intel-secl/v3/pkg/lib/saml"
	"github.com/intel-secl/intel-secl/v3/pkg/lib/verifier"
)

type HostTrustVerifierConfig struct {
	FlavorStore      FlavorStore
	FlavorGroupStore FlavorGroupStore
	HostStore        HostStore
	ReportStore      ReportStore
	FlavorVerifier   verifier.Verifier
	CertsStore       models.CertificatesStore
	SamlIssuerConfig saml.IssuerConfiguration
}

type HostTrustMgrConfig struct {
	PersistStore      QueueStore
	HostStore         HostStore
	HostStatusStore   HostStatusStore
	HostFetcher       HostDataFetcher
	Verifiers         int
	HostTrustVerifier HostTrustVerifier
}

type HostDataFetcherConfig struct {
	HostConnectorFactory host_connector.HostConnectorFactory
	RetryTimeMinutes     int
	HostStatusStore      HostStatusStore
}

type HostControllerConfig struct {
	HostConnectorFactory host_connector.HostConnectorFactory
	DataEncryptionKey    []byte
	Username             string
	Password             string
}

type TagCertControllerConfig struct {
	AASApiUrl       string
	ServiceUsername string
	ServicePassword string
}
