/*
 *  Copyright (C) 2020 Intel Corporation
 *  SPDX-License-Identifier: BSD-3-Clause
 */

package types

import "encoding/xml"

type Module struct {
	PcrBank   string `xml:"pcrBank"`
	PcrNumber string `xml:"pcrNumber"`
	Name      string `xml:"name"`
	Value     string `xml:"value"`
}

type MeasureLog struct {
	XMLName xml.Name `xml:"measureLog"`
	Txt     struct {
		TxtStatus string `xml:"txtStatus"`
		Modules   struct {
			Module []Module `xml:"module"`
		} `xml:"modules"`
	} `xml:"txt"`
}
