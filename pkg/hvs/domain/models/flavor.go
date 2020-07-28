/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package models

import (
	"encoding/json"
	"github.com/google/uuid"
	cf "github.com/intel-secl/intel-secl/v3/pkg/lib/flavor/common"
	"github.com/intel-secl/intel-secl/v3/pkg/model/hvs"
)

type flavors []hvs.Flavor
type signedFlavors []hvs.SignedFlavor

type FlavorCreateRequest struct {
	ConnectionString       string                     `json:"connection_string,omitempty"`
	FlavorCollection       hvs.FlavorCollection       `json:"flavor_collection,omitempty"`
	SignedFlavorCollection hvs.SignedFlavorCollection `json:"signed_flavor_collection,omitempty"`
	FlavorgroupName        string                     `json:"flavorgroup_name,omitempty"`
	FlavorParts            []cf.FlavorPart            `json:"partial_flavor_types,omitempty"`
}

type FlavorFilterCriteria struct {
	Ids           []uuid.UUID
	Key           string
	Value         string
	FlavorgroupID uuid.UUID
	FlavorParts   []cf.FlavorPart
}

type FlavorVerificationFC struct {
	FlavorFC              FlavorFilterCriteria
	FlavorMeta            map[cf.FlavorPart]map[string]interface{}
	FlavorPartsWithLatest map[cf.FlavorPart]bool
}

func (fcr FlavorCreateRequest) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		ConnectionString       string                     `json:"connection_string,omitempty"`
		FlavorCollection       hvs.FlavorCollection       `json:"flavor_collection,omitempty"`
		SignedFlavorCollection hvs.SignedFlavorCollection `json:"signed_flavor_collection,omitempty"`
		FlavorgroupName        string                     `json:"flavorgroup_name,omitempty"`
		FlavorParts            []cf.FlavorPart            `json:"partial_flavor_types,omitempty"`
	}{
		ConnectionString:       fcr.ConnectionString,
		FlavorCollection:       fcr.FlavorCollection,
		SignedFlavorCollection: fcr.SignedFlavorCollection,
		FlavorgroupName:        fcr.FlavorgroupName,
		FlavorParts:            fcr.FlavorParts,
	})
}

func (fcr *FlavorCreateRequest) UnmarshalJSON(b []byte) error {
	decoded := new(struct {
		ConnectionString       string                     `json:"connection_string,omitempty"`
		FlavorCollection       hvs.FlavorCollection       `json:"flavor_collection,omitempty"`
		SignedFlavorCollection hvs.SignedFlavorCollection `json:"signed_flavor_collection,omitempty"`
		FlavorgroupName        string                     `json:"flavorgroup_name,omitempty"`
		FlavorParts            []cf.FlavorPart            `json:"partial_flavor_types,omitempty"`
	})
	err := json.Unmarshal(b, decoded)
	if err == nil {
		fcr.ConnectionString = decoded.ConnectionString
		fcr.FlavorgroupName = decoded.FlavorgroupName
		fcr.FlavorCollection = decoded.FlavorCollection
		fcr.SignedFlavorCollection = decoded.SignedFlavorCollection
		fcr.FlavorParts = decoded.FlavorParts
	}
	return err
}
