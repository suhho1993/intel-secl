/*
 *  Copyright (C) 2020 Intel Corporation
 *  SPDX-License-Identifier: BSD-3-Clause
 */

package types

type Info struct {
	ComponentName string `json:"ComponentName"`
	EventName     string `json:"EventName"`
}
type Pcr struct {
	Index      string `json:"index"`
	Value      string `json:"value"`
	PcrBank    string `json:"pcr_bank"`
}

type EventLog struct {
	DigestType string `json:"digest_type"`
	Value      string `json:"value"`
	Label      string `json:"label"`
	Info       Info   `json:"info"`
}

type EventLogEntry struct {
	PcrIndex   string     `json:"pcr_index"`
	EventLogs  []EventLog `json:"event_log"`
	PcrBank    string     `json:"pcr_bank"`
}

type PcrSha1 Pcr
type PcrSha256 Pcr
type Sha1EventLogEntry EventLogEntry
type Sha256EventLogEntry EventLogEntry

type PcrEventLogMap struct {
	Sha1EventLogs   []Sha1EventLogEntry   `json:"SHA1"`
	Sha256EventLogs []Sha256EventLogEntry `json:"SHA256"`
}

type PcrManifest struct {
	Sha1Pcrs       []PcrSha1      `json:"sha1pcrs"`
	Sha256Pcrs     []PcrSha256    `json:"sha2pcrs"`
	PcrEventLogMap PcrEventLogMap `json:"pcr_event_log_map"`
}
