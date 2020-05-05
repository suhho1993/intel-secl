/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package aas

import (
	"fmt"
	"testing"
)

// Run with command: go test -count=1 -v <filenames>
func TestJWT(t *testing.T) {

	jwt := NewJWTClient("https://url.to.aas.instance:port/aas")

	cert, certErr := jwt.GetJWTSigningCert()
	fmt.Println(cert, certErr)

	var token []byte
	var err error
	jwt.AddUser("user1", "password")
	jwt.AddUser("user2", "password")
	jwt.AddUser("user3", "password")

	fmt.Println("fetch 1")
	token, err = jwt.FetchTokenForUser("user1")
	fmt.Println("fetch token 1: ", string(token))
	if err != nil {
		fmt.Println("err: ", err.Error())
	}
	token, err = jwt.GetUserToken("user1")
	fmt.Println("token 1: ", string(token))
	if err != nil {
		fmt.Println("err: ", err.Error())
	}
	token, err = jwt.GetUserToken("user2")
	fmt.Println("token 2")
	if err != nil {
		fmt.Println(err == ErrJWTNotYetFetched)
		fmt.Println("err: ", err.Error())
	}

	fmt.Println("fetch all")
	err = jwt.FetchAllTokens()
	if err != nil {
		fmt.Println("err: ", err.Error())
	}

	token, err = jwt.GetUserToken("user1")
	fmt.Println("token 1: ", string(token))
	if err != nil {
		fmt.Println("err: ", err.Error())
	}
	token, err = jwt.GetUserToken("user2")
	fmt.Println("token 2: ", string(token))
	if err != nil {
		fmt.Println("err: ", err.Error())
	}
	token, err = jwt.GetUserToken("user3")
	fmt.Println("token 3: ", string(token))
	if err != nil {
		fmt.Println("err: ", err.Error())
	}
	token, err = jwt.GetUserToken("user4")
	if err != nil {
		fmt.Println(err == ErrUserNotFound)
		fmt.Println("err: ", err.Error())
	}

	jwt404 := NewJWTClient("https://url.to.aas.instance:port/abc")
	_, err = jwt404.GetJWTSigningCert()
	if err != nil {
		fmt.Println(err == ErrHTTPGetJWTCert)
		fmt.Println("err: ", err.Error())
	}
	jwt404.AddUser("user1", "password")
	err = jwt404.FetchAllTokens()
	if err != nil {
		fmt.Println(err == ErrHTTPFetchJWTToken)
		fmt.Println("err: ", err.Error())
	}
}
