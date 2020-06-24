/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package hvs

import (
	"github.com/google/uuid"
	"time"
)

// TagCertificate
type TagCertificate struct {
	ID           uuid.UUID `json:"id"`
	Certificate  []byte    `json:"certificate"`
	Subject      string    `json:"subject"`
	Issuer       string    `json:"issuer"`
	NotBefore    time.Time `json:"not_before"`
	NotAfter     time.Time `json:"not_after"`
	HardwareUUID uuid.UUID `json:"hardware_uuid"`
}

// TagCertificateCollection is the response sent by the tag-certificate API
type TagCertificateCollection struct {
	TagCertificates []*TagCertificate `json:"certificates" xml:"certificates"`
}
