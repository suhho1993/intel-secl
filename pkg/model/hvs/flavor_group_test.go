/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package hvs_test

import (
	"encoding/json"
	"github.com/intel-secl/intel-secl/v3/pkg/model/hvs"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

const (
	flavorgroupJson string = `{
								"name": "hvs_flavorgroup_test3",
								"flavor_match_policy_collection": {
									"flavor_match_policies": [
										{
											"flavor_part": "PLATFORM",
											"match_policy": {
												"match_type": "ANY_OF",
												"required": "REQUIRED"
											}
										},
										{
											"flavor_part": "OS",
											"match_policy": {
												"match_type": "ANY_OF",
												"required": "REQUIRED"
											}
										},
										{
											"flavor_part": "HOST_UNIQUE",
											"match_policy": {
												"match_type": "LATEST",
												"required": "REQUIRED_IF_DEFINED"
											}
										}
									]
								}
							}`
)

var _ = Describe("FlavorGroup", func() {

	// Parse flavorgroup object
	Describe("Unmarshal flavorgroup json string", func() {
		Context("Provided a valid Flavorgroup json string", func() {
			It("Should be unmarshalled to Flavorgroup struct", func() {
				var fg hvs.FlavorGroup
				err := json.Unmarshal([]byte(flavorgroupJson), &fg)
				Expect(err).NotTo(HaveOccurred())
			})
		})
	})
})
