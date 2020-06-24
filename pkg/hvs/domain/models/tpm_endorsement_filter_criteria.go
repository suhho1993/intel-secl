/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */

package models

type TpmEndorsementFilterCriteria struct {
	Id                  string
	HardwareUuidEqualTo string
	IssuerEqualTo       string
	IssuerContains      string
	RevokedEqualTo      string
	CommentEqualTo      string
	CommentContains     string
}
