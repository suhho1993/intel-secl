/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package model

import "encoding/xml"

// xml request format sent from VS...
// <?xml version="1.0" encoding="UTF-8" standalone="yes"?>
// <Manifest xmlns="lib:wml:manifests:1.0" Label="ISecL_Default_Workload_Flavor_v1.0" Uuid="7a9ac586-40f9-43b2-976b-26667431efca" DigestAlg="SHA384">
// 	   <Dir Exclude="" FilterType="regex" Include=".*" Path="/opt/workload-agent/bin"/>
// 	   <Symlink Path="/opt/workload-agent/bin/wlagent"/>
// 	   <File Path="/opt/workload-agent/bin/.*" SearchType="regex"/>
// </Manifest>
type Manifest struct {
	XMLName   xml.Name `xml:"Manifest"`
	Text      string   `xml:",chardata"`
	Xmlns     string   `xml:"xmlns,attr"`
	Label     string   `xml:"Label,attr"`
	Uuid      string   `xml:"Uuid,attr"`
	DigestAlg string   `xml:"DigestAlg,attr"`
	Dir       []struct {
		Text       string `xml:",chardata"`
		Exclude    string `xml:"Exclude,attr,omitempty"`
		FilterType string `xml:"FilterType,attr,omitempty"`
		Include    string `xml:"Include,attr,omitempty"`
		Path       string `xml:"Path,attr"`
		SearchType string `xml:"SearchType,attr,omitempty"`
	} `xml:"Dir"`
	File []struct {
		Text       string `xml:",chardata"`
		Path       string `xml:"Path,attr"`
		SearchType string `xml:"SearchType,attr,omitempty"`
	} `xml:"File"`
	Symlink []struct {
		Text       string `xml:",chardata"`
		Path       string `xml:"Path,attr"`
		SearchType string `xml:"SearchType,attr,omitempty"`
	} `xml:"Symlink"`
}
