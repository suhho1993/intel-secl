/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package model

/**
 *
 * @author mullas
 */

// AES_NI
type AES_NI struct {
	Enabled bool `json:"enabled,omitempty"`
}

// TXT
type TXT struct {
	Enabled bool `json:"enabled"`
}

// TPM
type TPM struct {
	Enabled  bool     `json:"enabled"`
	Version  string   `json:"version,omitempty"`
	PcrBanks []string `json:"pcr_banks,omitempty"`
}

// CBNT
type CBNT struct {
	Enabled bool   `json:"enabled,omitempty"`
	Profile string `json:"profile,omitempty"`
}

// SUEFI
type SUEFI struct {
	Enabled bool `json:"enabled,omitempty"`
}

// Feature encapsulates the presence of various Platform security features on the Host hardware
type Feature struct {
	AES_NI *AES_NI `json:"AES_NI,omitempty"`
	TXT    *TXT    `json:"TXT,omitempty"`
	TPM    *TPM    `json:"TPM,omitempty"`
	CBNT   *CBNT   `json:"CBNT,omitempty"`
	SUEFI  *SUEFI  `json:"SUEFI,omitempty"`
}
