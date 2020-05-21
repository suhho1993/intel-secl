/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package model

/**
 *
 * @author mullas
 */

// AssetTag struct
type AssetTag struct {
	TagCertificate X509AttributeCertificate `json:"tag_certificate"`
}
