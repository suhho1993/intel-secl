/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package constants

// Roles and permissions
const (
	Administrator = "*:*:*"

	KeyCreate   = "keys:create"
	KeyRetrieve = "keys:retrieve"
	KeyDelete   = "keys:delete"
	KeySearch   = "keys:search"
	KeyRegister = "keys:register"
	KeyTransfer = "keys:transfer"

	SamlCertCreate   = "saml_certificates:create"
	SamlCertRetrieve = "saml_certificates:retrieve"
	SamlCertDelete   = "saml_certificates:delete"
	SamlCertSearch   = "saml_certificates:search"

	TpmIdentityCertCreate   = "tpm_identity_certificates:create"
	TpmIdentityCertRetrieve = "tpm_identity_certificates:retrieve"
	TpmIdentityCertDelete   = "tpm_identity_certificates:delete"
	TpmIdentityCertSearch   = "tpm_identity_certificates:search"

	KeyTransferPolicyCreate   = "key_transfer_policies:create"
	KeyTransferPolicyRetrieve = "key_transfer_policies:retrieve"
	KeyTransferPolicyDelete   = "key_transfer_policies:delete"
	KeyTransferPolicySearch   = "key_transfer_policies:search"

	SessionCreate = "key-session-api:create"
)
