/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */

package domain

type HostTrustMgrConfig struct {
	FlavStore    FlavorStore
	FlavGrpStore FlavorGroupStore
	PersistStore QueueStore
	HostStore    HostStore
	HostFetcher  HostDataFetcher
	Verifiers    int
}
