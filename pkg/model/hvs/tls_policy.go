/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */

package hvs

import "github.com/google/uuid"

type TlsPolicyCollection struct {
	TlsPolicies []*TlsPolicy `json:"tls_policies" xml:"tls_policy"`
}

type TlsPolicy struct {
	Id           uuid.UUID            `json:"id,omitempty"`
	Name         string               `json:"name"`
	Comment      string               `json:"comment,omitempty"`
	PrivateScope bool                 `json:"private,omitempty"`
	Descriptor   *TlsPolicyDescriptor `json:"descriptor"`
}

type TlsPolicyDescriptor struct {
	// PolicyType defines the type of tls policy.
	// Can be one of following values:
	// TRUST_FIRST_CERTIFICATE, certificate
	PolicyType string            `json:"policy_type"`

	// Ciphers defines the list of allowed ciphers
	// must be comma-separated
	// AES128-SHA, EDH-DSS-CBC-SHA, NULL-MD5 etc.
	// with ! prefix to mean exclude for example !NULL means exclude null ciphers,
	// !DES means exclude ciphers with DES,
	// !MD5 means exclude ciphers with MD5 hashing, etc.
	// and + means "at least" so +AES128 means "AES128 or greater"
	// and no prefix means exact match so "AES128" would not match AES256
	// but "AES" would match both AES128 and AES256,
	// similarly "SHA" matches SHA-1 and any SHA-2 algorithm
	Ciphers    string            `json:"ciphers,omitempty"`

	// Protocols defines the list of allowed protocols
	// must be comma-separated
	// ssl, ssl2, ssl3, tls, tls1.2, tls1.3,
	// with ! prefix to mean exclude for example !SSLv2 means don't allow ssl2,
	// and "ssl" matches any ssl and "tls" matches any tls version;
	// -ssl  means don't include ssl but if one is added later it's ok,
	// whereas !ssl would not allow any to be added
	// (-ssl,ssl3 means ssl3 but not others,
	// whereas !ssl,ssl3 means no ssl at all)
	Protocols  string            `json:"protocols,omitempty"`

	// Data contains the actual content
	// for example the actual certificate if policy type is certificate
	Data       []string          `json:"data"`

	// Metadata defines the characteristics of the content stored in Data field
	// digestAlgorithm (MD5, SHA-1, SHA-256, etc),
	// encoding (base64 or hex)
	Metadata   map[string]string `json:"meta"`

	// Protection defines the type of protection mechanism
	// Can be one of following values:
	// encryption, integrity, authentication, forwardSecrecy
	Protection *TlsProtection    `json:"protection,omitempty"`
}

type TlsProtection struct {
	Integrity      bool
	Encryption     bool
	Authentication bool
	ForwardSecrecy bool
}
