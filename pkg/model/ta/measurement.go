/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package model

import "encoding/xml"

// xml response format received from TA...
// <?xml version="1.0" encoding="UTF-8" standalone="yes"?>
// <Measurement xmlns="lib:wml:measurements:1.0" Label="ISecL_Default_Workload_Flavor_v1.0" Uuid="7a9ac586-40f9-43b2-976b-26667431efca" DigestAlg="SHA384">
// 	   <Dir Exclude="" Include=".*" Path="/opt/workload-agent/bin">e64e6d5afaad329d94d749e9b72c76e23fd3cb34655db10eadab4f858fb40b25ff08afa2aa6dbfbf081e11defdb58d5a</Dir>
// 	   <Symlink Path="/opt/workload-agent/bin/wlagent">5bd1737fc090c552f97eb783f194884edec570ac43c892a88078e02034185a535a47fb69566c58b3ee716993eac9e2e7</Symlink>
// 	   <File Path="/opt/workload-agent/bin/wlagent">ac8b967514f0a4c0ddcd87ee6cfdd03ffc5e5dd73598d40b8f6b6ef6dd606040a5fc31667908561093dd28317dfa1033</File>
//     <CumulativeHash>2ae673d241fed6e55d89e33a3ae8c6d127ed228e4afedfabfc2409c2d7bf51714d469786f948935c0b25c954904a2302</CumulativeHash>
// </Measurement>
type Measurement struct {
	XMLName   xml.Name `xml:"Measurement"`
	Text      string   `xml:",chardata"`
	Xmlns     string   `xml:"xmlns,attr"`
	Label     string   `xml:"Label,attr"`
	Uuid      string   `xml:"Uuid,attr"`
	DigestAlg string   `xml:"DigestAlg,attr"`
	Dir       []struct {
		Text       string `xml:",chardata"`
		Exclude    string `xml:"Exclude,attr,omitempty"`
		Include    string `xml:"Include,attr,omitempty"`
		Path       string `xml:"Path,attr"`
	} `xml:"Dir"`
	File []struct {
		Text       string `xml:",chardata"`
		Path       string `xml:"Path,attr"`
	} `xml:"File"`
	Symlink []struct {
		Text       string `xml:",chardata"`
		Path       string `xml:"Path,attr"`
	} `xml:"Symlink"`
	CumulativeHash string `xml:"CumulativeHash"`
}
