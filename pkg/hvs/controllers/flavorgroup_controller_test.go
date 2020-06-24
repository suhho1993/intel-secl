/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package controllers_test

import (
	"encoding/json"
	"github.com/intel-secl/intel-secl/v3/pkg/hvs/controllers"
	"github.com/intel-secl/intel-secl/v3/pkg/hvs/controllers/mocks"
	"github.com/intel-secl/intel-secl/v3/pkg/hvs/domain/models"
	hvsRoutes "github.com/intel-secl/intel-secl/v3/pkg/hvs/router"
	"github.com/intel-secl/intel-secl/v3/pkg/model/hvs"
	"net/http"
	"net/http/httptest"
	"strings"

	"github.com/gorilla/mux"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("FlavorgroupController", func() {
	var router *mux.Router
	var w *httptest.ResponseRecorder
	var flavorgroupStore *mocks.MockFlavorgroupStore
	var flavorgroupController *controllers.FlavorgroupController
	BeforeEach(func() {
		router = mux.NewRouter()
		flavorgroupStore = mocks.NewFakeFlavorgroupStore()
		flavorgroupController = &controllers.FlavorgroupController{FlavorGroupStore: flavorgroupStore}
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

				var fgCollection *hvs.FlavorgroupCollection
				json.Unmarshal(w.Body.Bytes(), &fgCollection)
				Expect(len(fgCollection.Flavorgroups)).To(Equal(2))
			})
		})
		Context("Search FlavorGroups from data store", func() {
			It("Should get filtered list of FlavorGroups", func() {
				router.Handle("/flavorgroups", hvsRoutes.ErrorHandler(hvsRoutes.ResponseHandler(flavorgroupController.Search))).Methods("GET")
				req, err := http.NewRequest("GET", "/flavorgroups?nameEqualTo=hvs_flavorgroup_test2", nil)
				Expect(err).NotTo(HaveOccurred())
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(200))

				var fgCollection *hvs.FlavorgroupCollection
				json.Unmarshal(w.Body.Bytes(), &fgCollection)
				Expect(len(fgCollection.Flavorgroups)).To(Equal(1))
			})
		})
		Context("Search FlavorGroups from data store", func() {
			It("Should get filtered list of FlavorGroups", func() {
				router.Handle("/flavorgroups", hvsRoutes.ErrorHandler(hvsRoutes.ResponseHandler(flavorgroupController.Search))).Methods("GET")
				req, err := http.NewRequest("GET", "/flavorgroups?nameContains=hvs_flavorgroup", nil)
				Expect(err).NotTo(HaveOccurred())
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(200))

				var fgCollection *hvs.FlavorgroupCollection
				json.Unmarshal(w.Body.Bytes(), &fgCollection)
				Expect(len(fgCollection.Flavorgroups)).To(Equal(2))
			})
		})
		Context("Get all FlavorGroups from data store with flavor content", func() {
			It("Should get list of FlavorGroups with flavor content", func() {
				router.Handle("/flavorgroups", hvsRoutes.ErrorHandler(hvsRoutes.ResponseHandler(flavorgroupController.Search))).Methods("GET")
				req, err := http.NewRequest("GET", "/flavorgroups?includeFlavorContent=true", nil)
				Expect(err).NotTo(HaveOccurred())
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(200))

				var fgCollection *hvs.FlavorgroupCollection
				json.Unmarshal(w.Body.Bytes(), &fgCollection)
				Expect(len(fgCollection.Flavorgroups)).To(Equal(2))
			})
		})
		Context("Search FlavorGroups from data store with invalid id", func() {
			It("Should return bad request error", func() {
				router.Handle("/flavorgroups", hvsRoutes.ErrorHandler(hvsRoutes.ResponseHandler(flavorgroupController.Search))).Methods("GET")
				req, err := http.NewRequest("GET", "/flavorgroups?id=e57e5ea0-d465-461e-882d-", nil)
				Expect(err).NotTo(HaveOccurred())
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(400))
			})
		})
	})

	// Specs for HTTP Get to "/flavorgroups/{flavorgroup_id}"
	Describe("Get FlavorGroup by ID", func() {
		Context("Retrieve FlavorGroup by ID from data store", func() {
			It("Should retrieve FlavorGroup", func() {
				router.Handle("/flavorgroups/{id}", hvsRoutes.ErrorHandler(hvsRoutes.ResponseHandler(flavorgroupController.Retrieve))).Methods("GET")
				req, err := http.NewRequest("GET", "/flavorgroups/ee37c360-7eae-4250-a677-6ee12adce8e2", nil)
				Expect(err).NotTo(HaveOccurred())
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(200))
			})
		})
		Context("Try to retrieve FlavorGroup by invalid ID from data store", func() {
			It("Should fail to retrieve FlavorGroup", func() {
				router.Handle("/flavorgroups/{id}", hvsRoutes.ErrorHandler(hvsRoutes.ResponseHandler(flavorgroupController.Retrieve))).Methods("GET")
				req, err := http.NewRequest("GET", "/flavorgroups/73755fda-c910-46be-821f-e8ddeab189e9", nil)
				Expect(err).NotTo(HaveOccurred())
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(404))
			})
		})
	})

	// Specs for HTTP Delete to "/flavorgroups/{flavorgroup_id}"
	Describe("Delete FlavorGroup by ID", func() {
		Context("Delete FlavorGroup by ID from data store", func() {
			It("Should delete FlavorGroup", func() {
				router.Handle("/flavorgroups/{id}", hvsRoutes.ErrorHandler(hvsRoutes.ResponseHandler(flavorgroupController.Delete))).Methods("DELETE")
				req, err := http.NewRequest("DELETE", "/flavorgroups/ee37c360-7eae-4250-a677-6ee12adce8e2", nil)
				Expect(err).NotTo(HaveOccurred())
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(204))
			})
		})

		Context("Delete FlavorGroup by invalid ID from data store", func() {
			It("Should fail to delete FlavorGroup", func() {
				router.Handle("/flavorgroups/{id}", hvsRoutes.ErrorHandler(hvsRoutes.ResponseHandler(flavorgroupController.Delete))).Methods("DELETE")
				req, err := http.NewRequest("DELETE", "/flavorgroups/73755fda-c910-46be-821f-e8ddeab189e9", nil)
				Expect(err).NotTo(HaveOccurred())
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(404))
			})
		})
	})

	// Specs for HTTP Post to "/flavorgroups"
	Describe("Post a new Flavorgroup", func() {
		Context("Provide a valid Flavorgroup data", func() {
			It("Should create a new Flavorgroup and get HTTP Status: 201", func() {
				router.Handle("/flavorgroups", hvsRoutes.ErrorHandler(hvsRoutes.ResponseHandler(flavorgroupController.Create))).Methods("POST")
				flavorgroupJson := `{
								"name": "hvs_flavorgroup_new",
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
								"name": "hvs_flavorgroup_test1",
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

	Context("Provide a empty data  in request", func() {
		It("Should get HTTP Status: 400", func() {
			router.Handle("/flavorgroups", hvsRoutes.ErrorHandler(hvsRoutes.ResponseHandler(flavorgroupController.Create))).Methods("POST")
			flavorgroupJson := ``
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

	Context("Provide a invalid Flavorgroup data", func() {
		It("Should get HTTP Status: 400", func() {
			router.Handle("/flavorgroups", hvsRoutes.ErrorHandler(hvsRoutes.ResponseHandler(flavorgroupController.Create))).Methods("POST")
			flavorgroupJson := `{
								"id": "hvs_flavorgroup_test1",
								"flavor_match_policy_collection": {
									"flavor_part": [
										{
											"flavor_part": "HOST_UNIQUE",
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

	Context("Provide a incorrect Flavorgroup data", func() {
		It("Should get HTTP Status: 400", func() {
			router.Handle("/flavorgroups", hvsRoutes.ErrorHandler(hvsRoutes.ResponseHandler(flavorgroupController.Create))).Methods("POST")
			flavorgroupJson := `{
								"name": "hvs_flavorgroup_test1",
								"flavor_match_policy_collection": {
									"flavor_part": []
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

	// Specs for flavorGroup validation
	Describe("FlavorGroup Validation", func() {
		Context("FlavorGroup with correct content", func() {
			It("should pass flavorGroup validation", func() {
				flavorgroupJson := `{
								"name": "hvs_flavorgroup_test1",
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

				flavorGroup := hvs.FlavorGroup{}
				json.Unmarshal([]byte(flavorgroupJson), &flavorGroup)
				err := controllers.ValidateFlavorGroup(flavorGroup)
				Ω(err).ShouldNot(HaveOccurred())
			})
		})
		Context("FlavorGroup with incorrect content", func() {
			It("should fail flavorGroup validation", func() {
				flavorgroupJson := `{
								"flavor_match_policy_collection": {
									"name": "hvs_flavorgroup_test1",
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

				flavorGroup := hvs.FlavorGroup{}
				json.Unmarshal([]byte(flavorgroupJson), &flavorGroup)
				flavorGroup.Name = ""
				err := controllers.ValidateFlavorGroup(flavorGroup)
				Ω(err).Should(HaveOccurred())

				flavorGroup.Name = "----"
				err = controllers.ValidateFlavorGroup(flavorGroup)
				Ω(err).Should(HaveOccurred())

				flavorGroup.Name = "test"
				flavorGroup.FlavorMatchPolicyCollection = hvs.FlavorMatchPolicyCollection{}
				err = controllers.ValidateFlavorGroup(flavorGroup)
				Ω(err).Should(HaveOccurred())
			})
		})
	})

	// Specs for FlavorGroupFilterCriteria validation
	Describe("FlavorGroupFilterCriteria Validation", func() {
		Context("FlavorGroupFilterCriteria with correct/empty content", func() {
			It("should pass FlavorGroupFilterCriteria validation", func() {
				filterCriteria := models.FlavorGroupFilterCriteria{}
				err := controllers.ValidateFgCriteria(filterCriteria)
				Ω(err).ShouldNot(HaveOccurred())
			})
		})
		Context("FlavorGroupFilterCriteria with incorrect content", func() {
			It("should fail FlavorGroupFilterCriteria validation", func() {
				filterCriteria := models.FlavorGroupFilterCriteria{
					Id: "123",
				}
				err := controllers.ValidateFgCriteria(filterCriteria)
				Ω(err).Should(HaveOccurred())

				filterCriteria = models.FlavorGroupFilterCriteria{
					HostId: "123",
				}
				err = controllers.ValidateFgCriteria(filterCriteria)
				Ω(err).Should(HaveOccurred())

				filterCriteria = models.FlavorGroupFilterCriteria{
					NameContains: "----",
				}
				err = controllers.ValidateFgCriteria(filterCriteria)
				Ω(err).Should(HaveOccurred())

				filterCriteria = models.FlavorGroupFilterCriteria{
					NameEqualTo: "----",
				}
				err = controllers.ValidateFgCriteria(filterCriteria)
				Ω(err).Should(HaveOccurred())
			})
		})
	})
})
