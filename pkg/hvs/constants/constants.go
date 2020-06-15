/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package constants

import "time"

const (
	ServiceName               = "HVS"
	OldServiceName            = "mtwilson"
	ApiVersion                = "/v2"
	ServiceUserName           = "hvs"
	ServiceDir                = "hvs/"
	HomeDir                   = "/opt/" + ServiceDir
	ConfigDir                 = "/etc/" + ServiceDir
	ConfigFile                = "config.yml"
	ExecLinkPath              = "/usr/bin/" + ServiceUserName
	RunDirPath                = "/run/" + ServiceDir
	LogDir                    = "/var/log/" + ServiceDir
	TrustedJWTSigningCertsDir = ConfigDir + "certs/trustedjwt/"
	TrustedCaCertsDir         = ConfigDir + "certs/trustedca/"
	KeyPath                   = ConfigDir + "trusted-keys/privacy-ca-key.pem"
	CertPath                  = TrustedCaCertsDir + "privacy-ca-cert.pem"
	//TODO remove or dont use temporary files
	AikRequestsDir = HomeDir + "privacyca-aik-requests/"
	//TODO use EndorsementCA file after implementation of create_endorsement_ca setup task
	EndorsementCAFile              = ConfigDir + "certs/endorsement/EndorsementCA-external.pem"
	AIKCertValidity                = 1
	DefaultPrivacyCACertValidity   = 5
	HostSigningKeyCertificateCN    = "Signing_Key_Certificate"
	HostBindingKeyCertificateCN    = "Binding_Key_Certificate"
	DefaultPrivacyCaIdentityIssuer = "hvs-pca-aik"
	ServiceRemoveCmd               = "systemctl disable hvs"
	DefaultTLSCertPath             = ConfigDir + "tls-cert.pem"
	DefaultTLSKeyPath              = ConfigDir + "tls.key"
	DefaultHvsTlsCn                = "HVS TLS Certificate"
	DefaultHvsTlsSan               = "127.0.0.1,localhost"
	DefaultKeyAlgorithm            = "rsa"
	DefaultKeyAlgorithmLength      = 3072
	DefaultSSLCertFilePath         = ConfigDir + "hvsdbsslcert.pem"
	BearerTokenEnv                 = "BEARER_TOKEN"
	CmsBaseUrlEnv                  = "CMS_BASE_URL"
	AasApiUrlEnv                   = "AAS_API_URL"
	HvsServiceUsernameEnv          = "HVS_SERVICE_USERNAME"
	HvsServicePasswordEnv          = "HVS_SERVICE_PASSWORD"
	CmsTlsCertDigestEnv            = "CMS_TLS_CERT_SHA384"
	JWTCertsCacheTime              = "1m"
	DefaultReadTimeout             = 30 * time.Second
	DefaultReadHeaderTimeout       = 10 * time.Second
	DefaultWriteTimeout            = 10 * time.Second
	DefaultIdleTimeout             = 10 * time.Second
	DefaultMaxHeaderBytes          = 1 << 20
	DefaultHVSListenerPort         = 8443
	DBTypePostgres                 = "postgres"
	DefaultLogEntryMaxlength       = 300
	DefaultDbConnRetryAttempts     = 4
	DefaultDbConnRetryTime         = 1
	DefaultSearchResultRowLimit    = 10000
)

//Roles and permissions
const (
	Administrator = "*:*:*"

	FlavorGroupCreate   = "flavorgroups:create"
	FlavorGroupRetrieve = "flavorgroups:retrieve"
	FlavorGroupSearch   = "flavorgroups:search"
	FlavorGroupDelete   = "flavorgroups:delete"

	CertifyAik = "host_aiks:certify"

	HostStatusRetrieve = "host_status:retrieve"
	HostStatusSearch   = "host_status:search"

	CertifyHostSigningKey = "host_signing_key_certificates:create"

	HostCreate   = "hosts:create"
	HostRetrieve = "hosts:retrieve"
	HostUpdate   = "hosts:store"
	HostDelete   = "hosts:delete"
	HostSearch   = "hosts:search"
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

// Timestamp operations
const (
	HostStatusDateFormat = "2006-01-02 15:04:05"
)
