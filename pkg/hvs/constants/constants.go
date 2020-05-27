/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package constants

import "time"

const (
	ServiceName                   = "HVS"
	OldServiceName                = "mtwilson"
	ApiVersion                    = "/v2"
	ServiceUserName               = "hvs"
	ServiceDir                    = "hvs/"
	HomeDir                       = "/opt/" + ServiceDir
	ConfigDir                     = "/etc/" + ServiceDir
	ConfigFile                    = "config.yml"
	ExecLinkPath                  = "/usr/bin/" + ServiceUserName
	RunDirPath                    = "/run/" + ServiceDir
	LogDir                        = "/var/log/" + ServiceDir
	TrustedJWTSigningCertsDir     = ConfigDir + "/certs/trustedjwt/"
	TrustedCaCertsDir             = ConfigDir + "/certs/trustedca/"
	ServiceRemoveCmd              = "systemctl disable hvs"
	DefaultTLSCertPath            = ConfigDir + "tls-cert.pem"
	DefaultTLSKeyPath             = ConfigDir + "tls.key"
	CertApproverGroupName         = "CertApprover"
	DefaultHvsTlsCn               = "HVS TLS Certificate"
	DefaultHvsTlsSan              = "127.0.0.1,localhost"
	DefaultKeyAlgorithm           = "rsa"
	DefaultKeyAlgorithmLength     = 3072
	DefaultSSLCertFilePath        = ConfigDir + "hvsdbsslcert.pem"
	BearerTokenEnv                = "BEARER_TOKEN"
	CmsBaseUrlEnv                 = "CMS_BASE_URL"
	AasApiUrlEnv                  = "AAS_API_URL"
	HvsServiceUsernameEnv         = "HVS_SERVICE_USERNAME"
	HvsServicePasswordEnv         = "HVS_SERVICE_PASSWORD"
	CmsTlsCertDigestEnv           = "CMS_TLS_CERT_SHA384"
	JWTCertsCacheTime             = "1m"
	DefaultReadTimeout            = 30 * time.Second
	DefaultReadHeaderTimeout      = 10 * time.Second
	DefaultWriteTimeout           = 10 * time.Second
	DefaultIdleTimeout            = 10 * time.Second
	DefaultMaxHeaderBytes         = 1 << 20
	DefaultHVSListenerPort        = 8443
	DBTypePostgres                = "postgres"
	DefaultLogEntryMaxlength      = 300
	DefaultDbConnRetryAttempts    = 4
	DefaultDbConnRetryTime        = 1
)

//Roles and permissions
const (
	Administrator = "*:*:*"

	FlavorGroupCreate   = "flavorgroups:create"
	FlavorGroupRetrieve = "flavorgroups:retrieve"
	FlavorGroupSearch   = "flavorgroups:search"
	FlavorGroupDelete   = "flavorgroups:delete"
)

//Postgres connection SslModes
const (
	SslModeAllow      = "allow"
	SslModePrefer     = "prefer"
	SslModeVerifyCa   = "verify-ca"
	SslModeRequire    = "require"
	SslModeVerifyFull = "verify-full"
)

// State represents whether or not a daemon is running or not
type State bool

const (
	// Stopped is the default nil value, indicating not running
	Stopped State = false
	// Running means the daemon is active
	Running State = true
)
