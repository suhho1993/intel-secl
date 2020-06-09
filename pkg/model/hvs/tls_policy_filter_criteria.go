/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package hvs

/**
 * The db_tls_policy does not have a hostId field; when this parameter
 * is specified, the store searches for private=true and name=hostId
 * which is a per-host private record.
 */
type TlsPolicyFilterCriteria struct {
	Id              string `json:"id"`
	HostId          string `json:"hostId"`
	NameEqualTo     string `json:"nameEqualTo"`
	NameContains    string `json:"nameContains"`
	CommentEqualTo  string `json:"commentEqualTo"`
	CommentContains string `json:"commentContains"`
	PrivateEqualTo  string `json:"privateEqualTo"`
}
