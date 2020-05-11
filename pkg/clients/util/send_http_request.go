/*
 *  Copyright (C) 2020 Intel Corporation
 *  SPDX-License-Identifier: BSD-3-Clause
 */
package util

import (
	"github.com/intel-secl/intel-secl/v3/pkg/clients"
	commLog "github.com/intel-secl/intel-secl/v3/pkg/lib/common/log"
	"io/ioutil"
	"net/http"
	"strconv"
	"sync"

	"github.com/intel-secl/intel-secl/v3/pkg/clients/aas"

	"github.com/pkg/errors"
)


var aasClient = aas.NewJWTClient("")
var aasRWLock = sync.RWMutex{}

var log = commLog.GetDefaultLogger()
var secLog = commLog.GetSecurityLogger()

func addJWTToken(req *http.Request, aasURL string, serviceUsername string, servicePassword string,
	trustedCaCertsDir string) error {
	log.Trace("clients/send_http_request:addJWTToken() Entering")
	defer log.Trace("clients/send_http_request:addJWTToken() Leaving")
	if aasClient.BaseURL == "" {
		aasClient = aas.NewJWTClient(aasURL)
		if aasClient.HTTPClient == nil {
			if trustedCaCertsDir == "" {
				c := clients.HTTPClientTLSNoVerify()
				aasClient.HTTPClient = c
			} else {
				c, err := clients.HTTPClientWithCADir(trustedCaCertsDir)
				if err != nil {
					return errors.Wrap(err, "clients/send_http_request.go:addJWTToken() Error initializing http client")
				}
				aasClient.HTTPClient = c
			}
		}
	}
	aasRWLock.RLock()
	jwtToken, err := aasClient.GetUserToken(serviceUsername)
	secLog.Debug("clients/send_http_request:addJWTToken() Getting user token from AAS...")
	aasRWLock.RUnlock()

	if err != nil {
		aasRWLock.Lock()
		jwtToken, err = aasClient.GetUserToken(serviceUsername)
		if err != nil {
			aasClient.AddUser(serviceUsername, servicePassword)
			err = aasClient.FetchAllTokens()
			if err != nil {
				return errors.Wrap(err, "clients/send_http_request.go:addJWTToken() Could not fetch token")
			}
		}
		aasRWLock.Unlock()
	}
	secLog.Debug("clients/send_http_request:addJWTToken() successfully added jwt bearer token")
	req.Header.Set("Authorization", "Bearer "+string(jwtToken))
	return nil
}

//SendRequest method is used to create an http client object and send the request to the server
func SendRequest(req *http.Request, aasURL string, serviceUsername string, servicePassword string,
	trustedCaCertsDir string) ([]byte, error) {
	log.Trace("clients/send_http_request:SendRequest() Entering")
	defer log.Trace("clients/send_http_request:SendRequest() Leaving")

	var aasClient = aas.NewJWTClient(aasURL)
	var err error
	if trustedCaCertsDir == "" {
		aasClient.HTTPClient = clients.HTTPClientTLSNoVerify()
	} else {
		aasClient.HTTPClient, err = clients.HTTPClientWithCADir(trustedCaCertsDir)
	}
	log.Debug("clients/send_http_request:SendRequest() AAS client successfully created")
	if err != nil {
		return nil, errors.Wrap(err, "clients/send_http_request.go:SendRequest() Failed to create http client")
	}
	err = addJWTToken(req, aasURL, serviceUsername, servicePassword, trustedCaCertsDir)
	if err != nil {
		return nil, errors.Wrap(err, "clients/send_http_request.go:SendRequest() Failed to add JWT token")
	}

	response, err := aasClient.HTTPClient.Do(req)
	if err != nil {
		return nil, errors.Wrap(err, "clients/send_http_request.go:SendRequest() Error from response")
	}
	defer response.Body.Close()
	if response.StatusCode == http.StatusUnauthorized {
		// fetch token and try again
		aasRWLock.Lock()
		aasClient.FetchAllTokens()
		aasRWLock.Unlock()
		err = addJWTToken(req, aasURL, serviceUsername, servicePassword, trustedCaCertsDir)
		if err != nil {
			return nil, errors.Wrap(err, "clients/send_http_request.go:SendRequest() Failed to add JWT token")
		}
		response, err = aasClient.HTTPClient.Do(req)
		if err != nil {
			return nil, errors.Wrap(err, "clients/send_http_request.go:SendRequest() Error from response")
		}
	}
	if response.StatusCode != http.StatusOK {
		return nil, errors.Wrap(errors.New("HTTP Status :"  + strconv.Itoa(response.StatusCode)),
			"clients/send_http_request.go:SendRequest() Error from response")
	}

	//create byte array of HTTP response body
	body, err := ioutil.ReadAll(response.Body)
	if err != nil {
		return nil, errors.Wrap(err, "clients/send_http_request.go:SendRequest() Error from response")
	}
	log.Info("clients/send_http_request.go:SendRequest() Received the response successfully")
	return body, nil
}
