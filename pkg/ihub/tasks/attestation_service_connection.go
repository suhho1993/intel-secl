/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package tasks

import (
	"fmt"
	"io"

	vsPlugin "github.com/intel-secl/intel-secl/v3/pkg/ihub/attestationPlugin"
	"github.com/intel-secl/intel-secl/v3/pkg/ihub/config"
	"github.com/intel-secl/intel-secl/v3/pkg/ihub/constants"
	"github.com/intel-secl/intel-secl/v3/pkg/lib/common/setup"
	"github.com/spf13/viper"

	"github.com/pkg/errors"
)

// AttestationServiceConnection is a setup task for setting up the connection to the Host Verification Service (Attestation Service)
type AttestationServiceConnection struct {
	AASConfig         *config.AASConfig
	IHUBConfig        *config.IHUBConfig
	AttestationConfig *config.AttestationConfig
	ConsoleWriter     io.Writer
}

// Run will run the Attestation Service Connection setup task, but will skip if Validate() returns no errors
func (attestationService AttestationServiceConnection) Run() error {
	fmt.Fprintln(attestationService.ConsoleWriter, "Setting up Attestation Service Connection...")

	aasURL := viper.GetString("aas-api-url")
	serviceUsername := viper.GetString("ihub-service-username")
	servicePassword := viper.GetString("ihub-service-password")
	attestationType := viper.GetString("attestation-type")
	attestationURL := viper.GetString("attestation-service-url")

	if aasURL == "" {
		return errors.New("tasks/attestation_service_connection:Run() Missing AAS_API_URL")
	}

	if serviceUsername == "" {
		return errors.New("tasks/attestation_service_connection:Run() Missing ihub service username")
	}

	if servicePassword == "" {
		return errors.New("tasks/attestation_service_connection:Run() Missing ihub service user password")
	}

	if attestationURL == "" {
		return errors.New("tasks/attestation_service_connection:Run() Missing attestation service endpoint url in environment")
	}

	if attestationType == "" {
		attestationType = constants.DefaultAttestationType
		fmt.Fprintln(attestationService.ConsoleWriter, "Attestation type is not defined in environment, default attestation type set")
	}

	attestationService.AASConfig.URL = aasURL
	attestationService.IHUBConfig.Username = serviceUsername
	attestationService.IHUBConfig.Password = servicePassword
	attestationService.AttestationConfig.AttestationType = attestationType
	attestationService.AttestationConfig.AttestationURL = attestationURL

	return nil
}

// Validate checks whether or not the Attestation Service Connection setup task was completed successfully
func (attestationService AttestationServiceConnection) Validate() error {
	if attestationService.AttestationConfig.AttestationType == "" {
		return errors.New("tasks/attestation_service_connection:Validate() Attestation service connection: Attestation type is not set")
	}

	if attestationService.AttestationConfig.AttestationURL == "" {
		return errors.New("tasks/attestation_service_connection:Validate() Attestation service Connection: Attestation url is not set")
	}

	//validating the service url
	return attestationService.validateService()
}

//validateService Validates the attestation service connection is successful or not by hitting the service url's
func (attestationService AttestationServiceConnection) validateService() error {

	conf := config.Configuration{
		AAS:                *attestationService.AASConfig,
		AttestationService: *attestationService.AttestationConfig,
		IHUB:               *attestationService.IHUBConfig,
	}

	if attestationService.AttestationConfig.AttestationType == "HVS" {
		_, err := vsPlugin.GetCaCerts("saml", &conf, "")
		if err != nil {
			return errors.Wrap(err, "tasks/attestation_service_connection:validateService() Error while getting response from attestation service")
		}
	} else if attestationService.AttestationConfig.AttestationType == "SGX" {
		_, err := vsPlugin.GetSHVSVersion(&conf, "")
		if err != nil {
			return errors.Wrap(err, "tasks/attestation_service_connection:validateService() Error while getting response from SGX attestation service")
		}
	} else {
		return errors.New("tasks/attestation_service_connection:validateService() Attestation type is not supported")
	}

	fmt.Fprintln(attestationService.ConsoleWriter, "Attestation Service Connection is successful")
	return nil
}

//PrintHelp Prints the help message
func (attestationService AttestationServiceConnection) PrintHelp(w io.Writer) {
	var envHelp = map[string]string{
		"ATTESTATION_TYPE": "Type of Attestation Service",
		"ATTESTATION_URL":  "Base URL for the Attestation Service",
	}
	setup.PrintEnvHelp(w, "Following environment variables are required for attestation-service-connection setup:", "", envHelp)
	fmt.Fprintln(w, "")
}

func (attestationService AttestationServiceConnection) SetName(n, e string) {}
