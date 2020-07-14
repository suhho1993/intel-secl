/*
 *  Copyright (C) 2020 Intel Corporation
 *  SPDX-License-Identifier: BSD-3-Clause
 */

package hvs

import "github.com/google/uuid"

type DeployManifestRequest struct {
	HostId   uuid.UUID `json:"host_id"`
	FlavorId uuid.UUID `json:"flavor_id"`
}
