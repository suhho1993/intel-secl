/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package constants

import "time"

const (
	ServiceName     = "kbs"
	ServiceDir      = "kbs/"
	ApiVersion      = "/v1"
	ServiceUserName = "kbs"

	HomeDir      = "/opt/" + ServiceDir
	RunDirPath   = "/run/" + ServiceDir
	ExecLinkPath = "/usr/bin/" + ServiceUserName
	LogDir       = "/var/log/" + ServiceDir

	// certificates' path
	TrustedJWTSigningCertsDir = ConfigDir + "certs/trustedjwt/"
	TrustedCaCertsDir         = ConfigDir + "certs/trustedca/"
	SamlCertsDir              = ConfigDir + "certs/saml/"
	TpmCertsDir               = ConfigDir + "certs/tpm/"

	ConfigDir                 = "/etc/" + ServiceDir
	DefaultConfigFilePath     = ConfigDir + "config.yml"
	ConfigFile                = "config"

	KeysDir                   = HomeDir + "keys/"
	KeysTransferPolicyDir     = HomeDir + "keys-transfer-policy/"

	// defaults
	DefaultKeyManager         = "Directory"
	DefaultEndpointUrl        = "http://localhost"
	DefaultTransferPolicy     = "urn:intel:trustedcomputing:key-transfer-policy:require-trust-or-authorization"
	DefaultTransferPolicyName = "default_transfer_policy"
	DefaultTransferPolicyFile = KeysTransferPolicyDir + DefaultTransferPolicyName

	// default locations for tls certificate and key
	DefaultTLSCertPath  = ConfigDir + "tls-cert.pem"
	DefaultTLSKeyPath   = ConfigDir + "tls.key"

	// service remove command
	ServiceRemoveCmd    = "systemctl disable kbs"

	// tls constants
	DefaultKbsTlsCn     = "KBS TLS Certificate"
	DefaultKbsTlsSan    = "127.0.0.1,localhost"
	DefaultKeyAlgorithm = "rsa"
	DefaultKeyLength    = 3072

	// jwt constants
	JWTCertsCacheTime        = "1m"

	// server constants
	DefaultReadTimeout       = 30 * time.Second
	DefaultReadHeaderTimeout = 10 * time.Second
	DefaultWriteTimeout      = 600 * time.Second
	DefaultIdleTimeout       = 10 * time.Second
	DefaultMaxHeaderBytes    = 1 << 20
	DefaultKBSListenerPort   = 9443

	// log constants
	DefaultLogEntryMaxlength = 1500
)

//Roles and permissions
const (
	Administrator = "*:*:*"

	KeyCreate   = "keys:create"
	KeyRetrieve = "keys:retrieve"
	KeyDelete   = "keys:delete"
	KeySearch   = "keys:search"
	KeyRegister = "keys:register"
	KeyTransfer = "keys:transfer"

	SamlCertCreate = "saml_certificates:create"
	SamlCertSearch = "saml_certificates:search"

	TpmCertCreate = "tpm_identity_certificates:create"
	TpmCertSearch = "tpm_identity_certificates:search"

	KeyTransferPolicyCreate   = "key_transfer_policies:create"
	KeyTransferPolicyRetrieve = "key_transfer_policies:retrieve"
	KeyTransferPolicyDelete   = "key_transfer_policies:delete"
	KeyTransferPolicySearch   = "key_transfer_policies:search"
)
