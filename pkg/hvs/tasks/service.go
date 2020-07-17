/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package tasks

import (
	"fmt"
	"io"

	"github.com/intel-secl/intel-secl/v3/pkg/hvs/config"
	"github.com/intel-secl/intel-secl/v3/pkg/lib/common/setup"
	"github.com/pkg/errors"
)

type ServiceSetup struct {
	config.HVSConfig

	SvcConfigPtr  *config.HVSConfig
	ConsoleWriter io.Writer

	commandName string
}

const svcEnvHelpPrompt = "Following environment variables are required for Service setup:"

var svcEnvHelp = map[string]string{
	"HVS_SERVICE_USERNAME": "The service username for HVS configured in AAS",
	"HVS_SERVICE_PASSWORD": "The service password for HVS configured in AAS",
}

func (t *ServiceSetup) Run() error {
	if t.SvcConfigPtr == nil {
		return errors.New("Pointer to service configuration structure can not be nil")
	}
	if t.Username == "" {
		return errors.New("HVS configuration not provided: HVS_SERVICE_USERNAME is not set")
	}
	if t.Password == "" {
		return errors.New("HVS configuration not provided: HVS_SERVICE_PASSWORD is not set")
	}
	t.SvcConfigPtr.Username = t.Username
	t.SvcConfigPtr.Password = t.Password
	return nil
}

func (t *ServiceSetup) Validate() error {
	if t.SvcConfigPtr == nil {
		return errors.New("Pointer to service configuration structure can not be nil")
	}
	if t.SvcConfigPtr.Username == "" ||
		t.SvcConfigPtr.Password == "" {
		return errors.New("Configured service username/password is not valid")
	}
	return nil
}

func (t *ServiceSetup) PrintHelp(w io.Writer) {
	setup.PrintEnvHelp(w, svcEnvHelpPrompt, "", svcEnvHelp)
	fmt.Fprintln(w, "")
}

func (t *ServiceSetup) SetName(n, e string) {
	t.commandName = n
}
