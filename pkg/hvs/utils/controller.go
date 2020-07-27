/*
 *  Copyright (C) 2020 Intel Corporation
 *  SPDX-License-Identifier: BSD-3-Clause
 */

package utils

import (
	"errors"
	"net/url"
)

func ValidateQueryParams(params url.Values , validQueries map[string]bool) error {
	defaultLog.Trace("utils/controller:ValidateQueryParams() Entering")
	defer defaultLog.Trace("utils/controller:ValidateQueryParams() Leaving")

	if len(params) > 0 {
		for param, _ := range params {
			if _, hasQuery := validQueries[param]; !hasQuery {
				return errors.New("Invalid query parameter provided. Refer to product guide for details.")
			}
		}
	}
	return nil
}
