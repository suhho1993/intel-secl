/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package model

import "encoding/xml"

// Measurement represents the details of an individual integrity measurement taken on a target Host
type DirectoryMeasurementType struct {
	Value      string `xml:",chardata"`
	Include    string `xml:"Include,attr,omitempty"`
	Exclude    string `xml:"Exclude,attr,omitempty"`
	FilterType string `xml:"FilterType,attr,omitempty"`
	Path       string `xml:"Path,attr"`
	SearchType string `xml:"SearchType,attr,omitempty"`
}

type FileMeasurementType struct {
	Value      string `xml:",chardata"`
	Path       string `xml:"Path,attr"`
	SearchType string `xml:"SearchType,attr,omitempty"`
}

type Measurement struct {
	XMLName        xml.Name                   `xml:"Measurement"`
	File           []FileMeasurementType      `xml:"lib:wml:measurements:1.0 File"`
	Dir            []DirectoryMeasurementType `xml:"lib:wml:measurements:1.0 Dir"`
	Symlink        []SymlinkMeasurementType   `xml:"lib:wml:measurements:1.0 Symlink"`
	CumulativeHash string                     `xml:"lib:wml:measurements:1.0 CumulativeHash"`
	DigestAlg      string                     `xml:"DigestAlg,attr,omitempty"`
	Label          string                     `xml:"Label,attr,omitempty"`
	Uuid           string                     `xml:"Uuid,attr,omitempty"`
}

type MeasurementType interface{}

type SymlinkMeasurementType struct {
	Value      string `xml:",chardata"`
	Path       string `xml:"Path,attr"`
	SearchType string `xml:"SearchType,attr,omitempty"`
}
