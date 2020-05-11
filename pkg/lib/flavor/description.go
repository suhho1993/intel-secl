/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package flavor

/**
 *
 * @author purvades
 */

// Description contains information about the host hardware identifiers
type Description struct {
	FlavorPart   string `json:"flavor_part,omitempty"`
	Source       string `json:"source,omitempty"`
	Label        string `json:"label,omitempty"`
	IPAddress    string `json:"ip_address,omitempty"`
	BiosName     string `json:"bios_name,omitempty"`
	BiosVersion  string `json:"bios_version,omitempty"`
	OSName       string `json:"os_name,omitempty"`
	OSVersion    string `json:"os_version,omitempty"`
	VMMName      string `json:"vmm_name,omitempty"`
	VMMVersion   string `json:"vmm_version,omitempty"`
	TPMVersion   string `json:"tpm_version,omitempty"`
	HardwareUUID string `json:"hardware_uuid,omitempty"`
	Comment      string `json:"comment,omitempty"`
}
