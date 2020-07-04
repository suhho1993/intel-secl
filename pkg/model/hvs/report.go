/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */

package hvs

import (
	"github.com/google/uuid"
	"github.com/intel-secl/intel-secl/v3/pkg/lib/flavor/common"
	taModel "github.com/intel-secl/intel-secl/v3/pkg/model/ta"
	"time"
)

type ReportCollection struct {
	Reports []*Report `json:"reports" xml:"reports"`
}

type Report struct {
	ID                uuid.UUID           `json:"id"`
	TrustInformation  TrustInformation    `json:"trust_information"`
	HostID            uuid.UUID           `json:"host_id"`
	TrustReport       TrustReport         `json:"-"`
	Saml              Saml                `json:"-"`
	HostInfo          taModel.HostInfo    `json:"host_info"`
	CreatedAt         time.Time           `json:"created"`
	Expiration        time.Time           `json:"expiration"`
}

type TrustInformation struct {
	Overall  bool `json:"overall"`
	FlavorTrust map[common.FlavorPart]FlavorTrustStatus `json:"flavors_trust"`
}

type FlavorTrustStatus struct {
	Trust  bool `json:"trust"`
	RuleResultCollection []RuleResult `json:"rules"`
}

type ReportCreateCriteria struct {
	HostID	            uuid.UUID   `json:"host_id"`
	HardwareUUID        uuid.UUID   `json:"hardware_uuid"`
	HostName            string      `json:"host_name"`
}