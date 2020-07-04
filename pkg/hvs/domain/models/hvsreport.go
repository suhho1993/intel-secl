/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */

package models

import (
	"encoding/xml"
	"github.com/google/uuid"
	"github.com/intel-secl/intel-secl/v3/pkg/model/hvs"
	"github.com/pkg/errors"
	"time"
)

type HVSReport struct {
	ID          uuid.UUID
	HostID      uuid.UUID
	TrustReport hvs.TrustReport
	CreatedAt   time.Time
	Expiration  time.Time
	// Saml is string which is actually xml encoded to string
	Saml        string
}

func (hvsReport *HVSReport) GetSaml() (hvs.Saml, error) {
	var samlStruct hvs.Saml
	err := xml.Unmarshal([]byte(hvsReport.Saml), samlStruct)
	if err != nil {
		return hvs.Saml{}, errors.Wrap(err, "models/hvsreport:GetSaml() Error while unmarshalling saml report")
	}
	return samlStruct, nil
}