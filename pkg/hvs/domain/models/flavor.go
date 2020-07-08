/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package models

import (
	"encoding/json"
	"github.com/google/uuid"
	cf "github.com/intel-secl/intel-secl/v3/pkg/lib/flavor/common"
	hcTypes "github.com/intel-secl/intel-secl/v3/pkg/lib/host-connector/types"
	"github.com/intel-secl/intel-secl/v3/pkg/model/hvs"
)

type flavors []hvs.Flavor
type signedFlavors []hvs.SignedFlavor

type FlavorCreateRequest struct {
	ConnectionString       string          `json:"connection_string,omitempty"`
	FlavorCollection       flavors         `json:"flavors,omitempty"`
	SignedFlavorCollection signedFlavors   `json:"signed_flavors,omitempty"`
	FlavorgroupName        string          `json:"flavorgroup_name,omitempty"`
	FlavorParts            []cf.FlavorPart `json:"flavor_parts,omitempty"`
}

//TODO: this struct will change when search store for hostManifest is created
type FlavorFilterCriteria struct {
	Id                    uuid.UUID
	Key                   string
	Value                 string
	FlavorGroupID         uuid.UUID
	FlavorParts           []cf.FlavorPart
	FlavorPartsWithLatest []cf.FlavorPart
	HostManifest          *hcTypes.HostManifest
}

func (fcr FlavorCreateRequest) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		ConnectionString       string          `json:"connection_string,omitempty"`
		FlavorCollection       flavors         `json:"flavors,omitempty"`
		SignedFlavorCollection signedFlavors   `json:"signed_flavors,omitempty"`
		FlavorgroupName        string          `json:"flavorgroup_name,omitempty"`
		FlavorParts            []cf.FlavorPart `json:"flavor_parts,omitempty"`
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
		ConnectionString       string          `json:"connection_string,omitempty"`
		FlavorCollection       flavors         `json:"flavors,omitempty"`
		SignedFlavorCollection signedFlavors   `json:"signed_flavors,omitempty"`
		FlavorgroupName        string          `json:"flavorgroup_name,omitempty"`
		FlavorParts            []cf.FlavorPart `json:"flavor_parts,omitempty"`
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
