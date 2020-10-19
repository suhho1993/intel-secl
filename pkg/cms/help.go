/*
 *  Copyright (C) 2020 Intel Corporation
 *  SPDX-License-Identifier: BSD-3-Clause
 */

package cms

import (
	"fmt"
	"github.com/intel-secl/intel-secl/v3/pkg/cms/version"
)

const helpStr = `
Usage:
    cms <command> [arguments]

Available Commands:
    -h|--help            Show this help message
    setup [task]         Run setup task
    start                Start cms
    status               Show the status of cms
    stop                 Stop cms
    tlscertsha384        Show the SHA384 digest of the certificate used for TLS
    uninstall [--purge]  Uninstall cms. --purge option needs to be applied to remove configuration and data files
    -v|--version         Show the version of cms

Usage of cms setup:
	cms setup <task> [--help] [--force] [-f <answer-file>]
		--help                      show help message for setup task
		--force                     existing configuration will be overwritten if this flag is set
		-f|--file <answer-file>     the answer file with required arguments

Available Tasks for setup:
    all                       Runs all setup tasks
                              Required env variables:
                                  - get required env variables from all the setup tasks
                              Optional env variables:
                                  - get optional env variables from all the setup tasks

    root_ca                   Creates a self signed Root CA key pair in /etc/cms/root-ca/ for quality of life
                              - Option [--force] overwrites any existing files, and always generate new Root CA keypair
                              Optional env variables specific to setup task are:
                                  - CMS_CA_CERT_VALIDITY=<cert life span in years>     : Certificate Management Service Root Certificate Validity
                                  - CMS_CA_ORGANIZATION=<cert org>                     : Certificate Management Service Root Certificate Organization
                                  - CMS_CA_LOCALITY=<cert locality>                    : Certificate Management Service Root Certificate Locality
                                  - CMS_CA_PROVINCE=<cert province>                    : Certificate Management Service Root Certificate Province
                                  - CMS_CA_COUNTRY=<cert country>                      : Certificate Management Service Root Certificate Country

    intermediate_ca           Creates a root_ca signed intermediate CA key pair(signing, tls-server and tls-client) in /etc/cms/intermediate-ca/ for quality of life
                              - Option [--force] overwrites any existing files, and always generate new root_ca signed Intermediate CA key pair
                              Available argument specific to setup task is:
                                  - type          available options are: TLS, TLS-Client, Signing

    tls                       Creates an intermediate_ca signed TLS key pair in /etc/cms for quality of life
                              - Option [--force] overwrites any existing files, and always generate intermediate_ca signed TLS keypair
                              Available argument and optional env variable specific to setup task is:
                                  - SAN_LIST            : TLS SAN list

    server                    Setup http server on given port
                              Available optional env variables specific to task are:
                                  - CMS_PORT
                                  - AAS_API_URL
                              Optional env variables specific to setup task are:
                                  - CMS_SERVER_READ_TIMEOUT=<read timeout in seconds>                    : Certificate Management Service Read Timeout
                                  - CMS_SERVER_READ_HEADER_TIMEOUT=<read header timeout in seconds>      : Certificate Management Service Read Header Timeout
                                  - CMS_SERVER_WRITE_TIMEOUT=<write timeout in seconds>                  : Certificate Management Service Write Timeout
                                  - CMS_SERVER_IDLE_TIMEOUT=<idle timeout in seconds>                    : Certificate Management Service Idle Timeout
                                  - CMS_SERVER_MAX_HEADER_BYTES=<max header bytes>            : Certificate Management Service Max Header Bytes
                                  - LOG_ENTRY_MAXLENGTH=<log max length>                      : Maximum length of each entry in a log
                                  - CMS_ENABLE_CONSOLE_LOG=<bool>                             : Certificate Management Service Enable standard output

    cms_auth_token            Create its own self signed JWT key pair in /etc/cms/jwt for quality of life
                              - Option [--force] overwrites any existing files, and always generate new JWT keypair and token
                              Optional env variables specific to setup task are:
                                  - AAS_JWT_CN=<jwt common-name>          : Authentication and Authorization JWT Common Name
                                  - AAS_TLS_CN=<tls common-name>          : Authentication and Authorization TLS Common Name
                                  - AAS_TLS_SAN=<tls SAN>                 : Authentication and Authorization TLS SAN list
`

func (a *App) printUsage() {
	fmt.Fprintln(a.consoleWriter(), helpStr)
}

func (a *App) printUsageWithError(err error) {
	fmt.Fprintln(a.errorWriter(), "Application returned with error:", err.Error())
	fmt.Fprintln(a.errorWriter(), helpStr)
}

func (a *App) printVersion() {
	fmt.Fprintf(a.consoleWriter(), "Certificate Management Service %s-%s\nBuilt %s\n", version.Version, version.GitHash, version.BuildDate)
}
