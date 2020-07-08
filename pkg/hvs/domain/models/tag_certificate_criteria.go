/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package models

import (
	"github.com/google/uuid"
	asset_tag "github.com/intel-secl/intel-secl/v3/pkg/lib/asset-tag"
	"time"
)

// TagCertificateFilterCriteria is passed to the TagCertificates Search API to filter the response
type TagCertificateFilterCriteria struct {
	ID              uuid.UUID `json:"id"`
	SubjectEqualTo  string    `json:"subjectEqualTo"`
	SubjectContains string    `json:"subjectContains"`
	IssuerEqualTo   string    `json:"issuerEqualTo"`
	IssuerContains  string    `json:"issuerContains"`
	ValidOn         time.Time `json:"validOn"`
	ValidBefore     time.Time `json:"validBefpre"`
	ValidAfter      time.Time `json:"validAfter"`
	HardwareUUID    uuid.UUID `json:"hardwareUuid"`
}

// TagCertificateCreateCriteria holds the data used to create a TagCertificate
type TagCertificateCreateCriteria struct {
	// HardwareUUID The hardware UUID of the host to which the tag certificate is associated.
	HardwareUUID uuid.UUID `json:"hardware_uuid"`
	// SelectionContent is an array of one or more key-value pairs with the tag selection attributes.
	SelectionContent []asset_tag.TagKvAttribute `json:"selection_content,omitempty"`
}

// TagCertificateDeployCriteria holds the data used to deploy a TagCertificate onto a host
type TagCertificateDeployCriteria struct {
	CertID uuid.UUID `json:"certificate_id,omitempty"`
}
