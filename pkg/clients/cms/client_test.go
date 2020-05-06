/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package cms

import (
	"fmt"
	"io/ioutil"
	"testing"
)

func TestCMS(t *testing.T) {

	cms := Client{
		BaseURL: "",
	}
	jwtToken, err := ioutil.ReadFile("/var/jwtToken")
	if err != nil {
		fmt.Println(err.Error())
		return
	}
	cms.JWTToken = jwtToken

}
