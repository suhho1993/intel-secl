/*
 *  Copyright (C) 2020 Intel Corporation
 *  SPDX-License-Identifier: BSD-3-Clause
 */

package types
import (
	"fmt"
	"strconv"
	"strings"
	"github.com/pkg/errors"
	"encoding/xml"
	"encoding/json"
)

const (
	PCR_INDEX_PREFIX          = "pcr_"
)

type Info struct {
	ComponentName string `json:"ComponentName"`
	EventName     string `json:"EventName"`
}
type Pcr struct {
	Index      PcrIndex     `json:"index"`
	Value      string       `json:"value"`
	PcrBank    SHAAlgorithm `json:"pcr_bank"`
}

type EventLog struct {
	DigestType string `json:"digest_type"`
	Value      string `json:"value"`
	Label      string `json:"label"`
	Info       Info   `json:"info"`
}

type EventLogEntry struct {
	PcrIndex   PcrIndex      `json:"pcr_index"`
	EventLogs  []EventLog    `json:"event_log"`
	PcrBank    SHAAlgorithm  `json:"pcr_bank"`
}

type Sha1EventLogEntry EventLogEntry
type Sha256EventLogEntry EventLogEntry

type PcrEventLogMap struct {
	Sha1EventLogs   []Sha1EventLogEntry   `json:"SHA1"`
	Sha256EventLogs []Sha256EventLogEntry `json:"SHA256"`
}

type PcrManifest struct {
	Sha1Pcrs       []Pcr          `json:"sha1pcrs"`
	Sha256Pcrs     []Pcr          `json:"sha2pcrs"`
	PcrEventLogMap PcrEventLogMap `json:"pcr_event_log_map"`
}

type PcrIndex int
const (
	PCR0  PcrIndex = iota
	PCR1
	PCR2
	PCR3
	PCR4
	PCR5
	PCR6 
	PCR7
	PCR8 
	PCR9
	PCR10
	PCR11
	PCR12
	PCR13
	PCR14
	PCR15 
	PCR16
	PCR17
	PCR18
	PCR19
	PCR20
	PCR21
	PCR22
	PCR23
	INVALID_INDEX = -1
)

// Convert the integer value of PcrIndex into "pcr_N" string (for xml serialization)
func (pcrIndex PcrIndex) MarshalXML(e *xml.Encoder, start xml.StartElement) error {
	xmlValue := fmt.Sprintf("pcr_%d", int(pcrIndex))
	return e.EncodeElement(xmlValue, start)	
}

// Convert the xml string value "pcr_N" to PcrIndex
func (pcrIndex *PcrIndex) UnmarshalXML(d *xml.Decoder, start xml.StartElement) error {
	var xmlValue string
	err := d.DecodeElement(&xmlValue, &start)
	if err != nil {
		return errors.Wrap(err, "Could not decode PcrIndex from XML")
	}

	index, err := GetPcrIndexFromString(xmlValue)
	if err != nil {
		return errors.Wrap(err, "Could not unmarshal PcrIndex from XML")
	}

	*pcrIndex = index
	return nil
}

// Convert the integer value of PcrIndex into "pcr_N" string (for json serialization)
func (pcrIndex PcrIndex) MarshalJSON() ([]byte, error) {
	jsonValue := fmt.Sprintf("pcr_%d", int(pcrIndex))
	return json.Marshal(jsonValue)
}

// Convert the json string value "pcr_N" to PcrIndex
func (pcrIndex *PcrIndex) UnmarshalJSON(b []byte) error {
	var jsonValue string
	if err := json.Unmarshal(b, &jsonValue); err != nil {
		return errors.Wrap(err, "Could not unmarshal PcrIndex from JSON")
	}

	index, err := GetPcrIndexFromString(jsonValue)
	if err != nil {
		return errors.Wrap(err, "Could not unmarshal PcrIndex from JSON")
	}

	*pcrIndex = index
	return nil
}

type SHAAlgorithm string
const (
	SHA1   SHAAlgorithm = "SHA1"
	SHA256              = "SHA256"
	SHA384              = "SHA384"
	SHA512              = "SHA512"
	UNKNOWN             = "unknown"
)

func GetSHAAlgorithm(algorithm string) (SHAAlgorithm, error){
	switch(algorithm) {
	case string(SHA1): return SHA1, nil
	case string(SHA256): return SHA256, nil
	case string(SHA384): return SHA384, nil
	case string(SHA512): return SHA512, nil
	}

	return UNKNOWN, errors.Errorf("Could not retrieve SHA from value '%s'", algorithm)
}

// Parses a string value in either integer form (i.e. "8") or "pcr_N"
// where 'N' is the integer value between 0 and 23.  Ex. "pcr_7".  Returns 
// an error if the string is not in the correct format or if the index 
// value is not between 0 and 23.
func GetPcrIndexFromString(stringValue string) (PcrIndex, error) {

	intString := stringValue

	if strings.Contains(intString, PCR_INDEX_PREFIX) {
		intString = strings.ReplaceAll(stringValue, PCR_INDEX_PREFIX, "")
	}

	intValue, err := strconv.ParseInt(intString, 0, 64)
	if err != nil {
		return INVALID_INDEX, errors.Wrapf(err, "Could not unmarshal PcrIndex from string value '%s'", stringValue)
	}

	if intValue < int64(PCR0) || intValue > int64(PCR23) {
		return INVALID_INDEX, errors.Errorf("Invalid PCR index %d", intValue)
	}

	return PcrIndex(intValue), nil
}

// Finds the Pcr in a PcrManifest provided the pcrBank and index.  Returns
// null if not found.  Returns an error if the pcrBank is not supported
// by intel-secl (currently supports SHA1 and SHA256).
func (pcrManifest *PcrManifest) GetPcrValue(pcrBank SHAAlgorithm, pcrIndex PcrIndex) (*Pcr, error) {
	// TODO: Is this the right data model for the PcrManifest?  Two things...
	// - Flavor API returns a map[bank]map[pcrindex] 
	// - Finding the PCR by bank/index is a linear search.
	var pcrValue *Pcr

	if pcrBank == SHA1 {
		for _, pcr := range pcrManifest.Sha1Pcrs {
			if pcr.Index == pcrIndex {
				pcrValue = &pcr
				break
			}
		}
	} else if pcrBank == SHA256 {
		for _, pcr := range pcrManifest.Sha256Pcrs {
			if pcr.Index == pcrIndex {
				pcrValue = &pcr
				break
			}
		}
	} else {
		return nil, errors.Errorf("Unsupported sha algorithm %s", pcrBank)
	}

	return pcrValue, nil
}

// Utility function that uses GetPcrValue but also returns an error if
// the Pcr was not found.
func (pcrManifest *PcrManifest) GetRequiredPcrValue(bank SHAAlgorithm, pcrIndex PcrIndex) (*Pcr, error) {
	pcrValue, err := pcrManifest.GetPcrValue(bank, pcrIndex)
	if err != nil {
		return nil, err
	}

	if pcrValue == nil {
		return nil, errors.Errorf("Could not retrive PCR at bank '%s', index %d", bank, pcrIndex)
	}

	return pcrValue, nil
}
