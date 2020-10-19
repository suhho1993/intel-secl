/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package aas

import (
	"fmt"

	"github.com/intel-secl/intel-secl/v3/pkg/aas/version"
)

const helpStr = `Usage:
	authservice <command> [arguments]

Available Commands:
	-h|--help              Show this help message
	setup <task>           Run setup task
	start                  Start authservice
	status                 Show the status of authservice
	stop                   Stop authservice
	tlscertsha384          Show the SHA384 digest of the certificate used for TLS
	uninstall [--purge]    Uninstall authservice. --purge option needs to be applied to remove configuration and data files
	-v|--version           Show the version of authservice

	Setup command usage:       authservice setup [task] [--arguments=<argument_value>] [--force]
	Available Tasks for setup:
	    all                   Runs all setup tasks
	                          Required env variables:
	                              - get required env variables from all the setup tasks
	                         Optional env variables:
	                              - get optional env variables from all the setup tasks
	
		database              Setup authservice database
	                          Available arguments and Required Env variables specific to setup task are:
	                              - set environment variable AAS_DB_HOSTNAME
	                              - set environment variable AAS_DB_PORT
	                              - set environment variable AAS_DB_USERNAME
	                              - set environment variable AAS_DB_PASSWORD
	                              - set environment variable AAS_DB_NAME
	                          Available arguments and Optional env variables specific to setup task are:
	                              - set environment variable AAS_DB_SSLMODE <disable|allow|prefer|require|verify-ca|verify-full>
	                              - set environment variable AAS_DB_SSLCERT. Only applicable for db-sslmode=<verify-ca|verify-full. 
									If left empty, the cert will be copied to /etc/authservice/aasdbcert.pem
	                              - set environment variable AAS_DB_SSLCERTSR <path to where the database ssl/tls certificate file>. 
									Mandatory if AAS_DB_SSLCERT does not already exist
	
		admin                 Setup task to register authservice user with default admin roles to database
	                          Available arguments and required env variables specific to setup task are:
	                              - set environment variable AAS_ADMIN_USERNAME
	                              - set environment variable AAS_ADMIN_PASSWORD
	
		download_ca_cert      Download CMS root CA certificate
	                          - Option [--force] overwrites any existing files, and always downloads new root CA cert
	                          Required env variables specific to setup task are:
	                              - CMS_BASE_URL=<url>                                : for CMS API url
	                              - CMS_TLS_CERT_SHA384=<CMS TLS cert sha384 hash>    : to ensure that AAS is talking to the right CMS instance
	
		download-cert-tls     Generates Key pair and CSR, gets it signed from CMS
	                          - Option [--force] overwrites any existing files, and always downloads newly signed TLS cert
	                          Required env variable if AAS_NOSETUP=true or variable not set in config.yml:
	                              - CMS_TLS_CERT_SHA384=<CMS TLS cert sha384 hash>      : to ensure that AAS is talking to the right CMS instance
	                          Required env variables specific to setup task are:
	                              - CMS_BASE_URL=<url>               : for CMS API url
	                              - BEARER_TOKEN=<token>             : for authenticating with CMS
	                              - SAN_LIST=<san>                   : list of hosts which needs access to service
	                          Optional env variables specific to setup task are:
	                              - KEY_PATH=<key_path>              : Path of file where TLS key needs to be stored
	                              - CERT_PATH=<cert_path>            : Path of file/directory where TLS certificate needs to be stored
	
		jwt                   Create jwt signing key and jwt certificate signed by CMS
	                          - Option [--force] overwrites any existing files, and always downloads newly signed JWT cert
	                          Required env variable if AAS_NOSETUP=true or variable not set in config.yml:
	                              - CMS_TLS_CERT_SHA384=<CMS TLS cert sha384 hash>       : to ensure that AAS is talking to the right CMS instance")
	                          Available arguments and Required env variables specific to setup task are:
	                              - set environment variable CMS_BASE_URL
	                              - set environment variable BEARER_TOKEN
	                          Available arguments and Optional env variables specific to setup task are:
	                              - set environment variable AAS_JWT_CERT_CN
	                              - set environment variable AAS_JWT_INCLUDE_KEYID
	                              - set environment variable AAS_JWT_TOKEN_DURATION_MINS
	
		server                Setup http server on given port
	                          Available argument and Optional env variables specific to setup task are:
	                              - set environment variable AAS_PORT
	                              - AAS_SERVER_READ_TIMEOUT=<read timeout in seconds>                    : Auth Service Read Timeout
	                              - AAS_SERVER_READ_HEADER_TIMEOUT=<read header timeout in seconds>      : Auth Service Read Header Timeout
	                              - AAS_SERVER_WRITE_TIMEOUT=<write timeout in seconds>                  : Auth Service Write Timeout
	                              - AAS_SERVER_IDLE_TIMEOUT=<idle timeout in seconds>                    : Auth Service Idle Timeout
	                              - AAS_SERVER_MAX_HEADER_BYTES=<max header bytes>                       : Auth Service Max Header Bytes
	                              - AAS_LOG_MAX_LENGTH=<log max length>                                  : Auth Service Log maximum length
	                              - AAS_ENABLE_CONSOLE_LOG=<bool>                                        : Auth Service Enable standard output
`

func (a *App) printUsage() {
	fmt.Fprintln(a.consoleWriter(), helpStr)
}

func (a *App) printUsageWithError(err error) {
	fmt.Fprintln(a.errorWriter(), "Application returned with error:", err.Error())
	fmt.Fprintln(a.errorWriter(), helpStr)
}

func (a *App) printVersion() {
	fmt.Fprintf(a.consoleWriter(), "Auth Service %s-%s\nBuilt %s\n", version.Version, version.GitHash, version.BuildDate)
}
