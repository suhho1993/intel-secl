/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package aas

import (
	"fmt"
	"testing"

	types "intel/isecl/lib/common/v2/types/aas"
)

// Run with command: go test -count=1 -v <filenames>
// insert the url to a working aas instance to "aasURL" variable
func TestAASClient(t *testing.T) {

	var token []byte
	var err error
	aasURL := "https://url.to.aas.instance:port/aas"

	// get token of aas admin
	jwt := NewJWTClient(aasURL)
	jwt.AddUser("admin", "password")
	err = jwt.FetchAllTokens()
	if err != nil {
		fmt.Println("err: ", err.Error())
	}
	token, err = jwt.GetUserToken("admin")
	fmt.Println("token: ", string(token))
	if err != nil {
		fmt.Println("err: ", err.Error())
	}

	aasClient := Client{
		BaseURL:  aasURL,
		JWTToken: token,
	}
	role := types.RoleCreate{
		Service: "test_service",
		Name:    "test_name",
	}
	resp, err := aasClient.CreateRole(role)
	if err == nil {
		fmt.Println(resp)
	} else {
		fmt.Println(err)
	}
}
