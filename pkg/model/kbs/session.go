/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package kbs

type SessionManagementAttributes struct {
	ChallengeType    string `json:"challenge_type"`
	Challenge        string `json:"challenge"`
	Quote            string `json:"quote"`
	CertificateChain string `json:"certificate_chain,omitempty"`
}
