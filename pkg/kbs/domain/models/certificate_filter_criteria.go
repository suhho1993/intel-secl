/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package models

import "time"

//CertificateFilterCriteria stores the parameters for filtering the certificates
type CertificateFilterCriteria struct {
	SubjectEqualTo  string
	SubjectContains string
	IssuerEqualTo   string
	IssuerContains  string
	ValidBefore     time.Time
	ValidAfter      time.Time
	ValidOn         time.Time
}
