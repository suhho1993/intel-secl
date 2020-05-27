/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package controllers_test

import (
	"encoding/json"
	"github.com/intel-secl/intel-secl/v3/pkg/hvs/controllers"
	hvsRoutes "github.com/intel-secl/intel-secl/v3/pkg/hvs/router"
	"github.com/intel-secl/intel-secl/v3/pkg/model/hvs"
	"net/http"
	"net/http/httptest"
	"strings"

	"github.com/gorilla/mux"
	cf "github.com/intel-secl/intel-secl/v3/pkg/lib/flavor/common"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("FlavorgroupController", func() {
	var router *mux.Router
	var w *httptest.ResponseRecorder
	var flavorgroupStore *FakeFlavorgroupStore
	var flavorgroupController *controllers.FlavorgroupController
	BeforeEach(func() {
		router = mux.NewRouter()
		flavorgroupStore = newFakeFlavorgroupStore()
		flavorgroupController = &controllers.FlavorgroupController{Store: flavorgroupStore}
	})

	// Specs for HTTP Get to "/flavorgroups"
	Describe("Get list of FlavorGroups", func() {
		Context("Get all FlavorGroups from data store", func() {
			It("Should get list of FlavorGroups", func() {
				router.Handle("/flavorgroups", hvsRoutes.ErrorHandler(hvsRoutes.ResponseHandler(flavorgroupController.Search))).Methods("GET")
				req, err := http.NewRequest("GET", "/flavorgroups", nil)
				Expect(err).NotTo(HaveOccurred())
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(200))
				var flavorgroups []hvs.FlavorGroup
				json.Unmarshal(w.Body.Bytes(), &flavorgroups)
				// Verifying mocked data of 2 flavorgroups
				Expect(len(flavorgroups)).To(Equal(2))
			})
		})
	})

	// Specs for HTTP Post to "/flavorgroups"
	Describe("Post a new Flavorgroup", func() {
		Context("Provide a valid Flavorgroup data", func() {
			It("Should create a new Flavorgroup and get HTTP Status: 201", func() {
				router.Handle("/flavorgroups", hvsRoutes.ErrorHandler(hvsRoutes.ResponseHandler(flavorgroupController.Create))).Methods("POST")
				flavorgroupJson := `{
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

				req, err := http.NewRequest(
					"POST",
					"/flavorgroups",
					strings.NewReader(flavorgroupJson),
				)
				Expect(err).NotTo(HaveOccurred())
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(201))
			})
		})
		Context("Provide a Flavorgroup data that contains duplicate flavorgroup name", func() {
			It("Should get HTTP Status: 400", func() {
				router.Handle("/flavorgroups", hvsRoutes.ErrorHandler(hvsRoutes.ResponseHandler(flavorgroupController.Create))).Methods("POST")
				flavorgroupJson := `{
								"name": "hvs_flavorgroup_test2",
								"flavor_match_policy_collection": {
									"flavor_match_policies": [
										{
											"flavor_part": "HOST_UNIQUE",
											"match_policy": {
												"match_type": "ALL_OF",
												"required": "REQUIRED_IF_DEFINED"
											}
										}
									]
								}
							}`


				req, err := http.NewRequest(
					"POST",
					"/flavorgroups",
					strings.NewReader(flavorgroupJson),
				)
				Expect(err).NotTo(HaveOccurred())
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(400))
			})
		})
	})
})

// FakeFlavorgroupStore provides a mocked implementation of interface hvs.FlavorGroupStore
type FakeFlavorgroupStore struct {
	flavorgroupStore []*hvs.FlavorGroup
}

// Delete returns deletes group
func (store *FakeFlavorgroupStore) Delete(id string)  error {
	return nil
}

// Retrieve returns FlavorGroup
func (store *FakeFlavorgroupStore) Retrieve(id string) (*hvs.FlavorGroup, error) {
	return store.flavorgroupStore[0], nil
}

// Search returns all FlavorGroups
func (store *FakeFlavorgroupStore) Search(criteria *hvs.FlavorGroupFilterCriteria) (*hvs.FlavorgroupCollection, error) {
	return &hvs.FlavorgroupCollection{Flavorgroups: store.flavorgroupStore}, nil
}

// Create inserts a Flavorgroup
func (store *FakeFlavorgroupStore) Create(flavorgroup *hvs.FlavorGroup) (*hvs.FlavorGroup, error) {
	store.flavorgroupStore = append(store.flavorgroupStore, flavorgroup)
	return flavorgroup, nil
}


// newFakeFlavorgroupStore provides two dummy data for Flavorgroups
func newFakeFlavorgroupStore() *FakeFlavorgroupStore {
	store := &FakeFlavorgroupStore{}

	store.Create(&hvs.FlavorGroup{
		Name: "hvs_flavorgroup_test1",
		FlavorMatchPolicyCollection: &hvs.FlavorMatchPolicyCollection{
			FlavorMatchPolicies: []hvs.FlavorMatchPolicy{
				{
					FlavorPart: cf.Os,
					MatchPolicy: hvs.MatchPolicy{
						MatchType: hvs.AllOf,
						Required: hvs.Required,
					},
				},
				{
					FlavorPart: cf.Platform,
					MatchPolicy: hvs.MatchPolicy{
						MatchType: hvs.AnyOf,
						Required: hvs.RequiredIfDefined,
					},
				},
			},
		},
	})

	store.Create(&hvs.FlavorGroup{
		Name: "hvs_flavorgroup_test2",
		FlavorMatchPolicyCollection: &hvs.FlavorMatchPolicyCollection{
			FlavorMatchPolicies: []hvs.FlavorMatchPolicy{
				{
					FlavorPart: cf.HostUnique,
					MatchPolicy: hvs.MatchPolicy{
						MatchType: hvs.AllOf,
						Required: hvs.Required,
					},
				},
			},
		},
	})

	return store
}
