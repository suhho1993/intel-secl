/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package auth

import (
	types "github.com/intel-secl/intel-secl/v3/pkg/lib/common/types/aas"
	"strings"
)

func ValidatePermissionAndGetPermissionsContext(privileges []types.PermissionInfo, reqPermissions types.PermissionInfo,
	retNilCtxForEmptyCtx bool) (*map[string]types.PermissionInfo, bool) {

	ctx := make(map[string]types.PermissionInfo)
	for _, permission := range privileges {
		if reqPermissions.Service == permission.Service {
			for _, rule := range permission.Rules {
				for reqRuleIndex, reqRule := range reqPermissions.Rules {
					if isAuthorized(rule, reqRule) {
						if len(reqPermissions.Rules) > 1 {
							reqPermissions.Rules[reqRuleIndex] = reqPermissions.Rules[len(reqPermissions.Rules) - 1]
							reqPermissions.Rules = reqPermissions.Rules[:len(reqPermissions.Rules) - 1]
						} else {
							if strings.TrimSpace(permission.Context) == "" && retNilCtxForEmptyCtx == true {
								return nil, true
							} else if strings.TrimSpace(permission.Context) != "" {
								ctx[strings.TrimSpace(permission.Context)] = permission
								return &ctx, true
							}
						}
					}
				}
			}
		}
	}
	return &ctx, false
}

func isAuthorized(rule string, reqPermission string) bool {
	splitRule := strings.Split(rule, ":")
	splitReqPermission := strings.Split(reqPermission, ":")
	if len(splitRule) < 2 {
		return false
	}
	if len(splitRule) > 2 && splitRule[2] != "*" {
		return false
	}
	if (splitRule[0] == "*" || splitRule[0] == splitReqPermission[0]) && (splitRule[1] == "*" || splitRule[1] == splitReqPermission[1]) {
		return true
	} else {
		return false
	}
}