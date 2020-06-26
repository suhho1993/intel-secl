/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package controllers_test

import (
	"encoding/json"
	"github.com/intel-secl/intel-secl/v3/pkg/hvs/controllers"
	"github.com/intel-secl/intel-secl/v3/pkg/hvs/controllers/mocks"
	hvsRoutes "github.com/intel-secl/intel-secl/v3/pkg/hvs/router"
	"github.com/intel-secl/intel-secl/v3/pkg/model/hvs"
	"net/http"
	"net/http/httptest"
	"strings"

	"github.com/gorilla/mux"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("HostController", func() {
	var router *mux.Router
	var w *httptest.ResponseRecorder
	var hostStore *mocks.MockHostStore
	var hostStatusStore *mocks.MockHostStatusStore
	var flavorGroupStore *mocks.MockFlavorgroupStore
	var hostController *controllers.HostController
	BeforeEach(func() {
		router = mux.NewRouter()
		hostStore = mocks.NewMockHostStore()
		hostStatusStore = mocks.NewFakeHostStatusStore()
		flavorGroupStore = mocks.NewFakeFlavorgroupStore()
		hostController = &controllers.HostController{
			HStore:  hostStore,
			HSStore: hostStatusStore,
			FGStore: flavorGroupStore,
		}
	})

	// Specs for HTTP Post to "/hosts"
	Describe("Create a new Host", func() {
		Context("Provide a valid Host data", func() {
			It("Should create a new Host", func() {
				router.Handle("/hosts", hvsRoutes.ErrorHandler(hvsRoutes.ResponseHandler(hostController.Create))).Methods("POST")
				hostJson := `{
								"host_name": "localhost3",
								"connection_string": "intel:https://another.ta.ip.com:1443",
								"description": "Another Intel Host"
							}`

				req, err := http.NewRequest(
					"POST",
					"/hosts",
					strings.NewReader(hostJson),
				)
				Expect(err).NotTo(HaveOccurred())
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusCreated))
			})
		})
		Context("Provide a Host data that contains duplicate hostname", func() {
			It("Should fail to create new Host", func() {
				router.Handle("/hosts", hvsRoutes.ErrorHandler(hvsRoutes.ResponseHandler(hostController.Create))).Methods("POST")
				hostJson := `{
								"host_name": "localhost2",
								"connection_string": "intel:https://ta.ip.com:1443",
								"description": "Intel Host"
							}`

				req, err := http.NewRequest(
					"POST",
					"/hosts",
					strings.NewReader(hostJson),
				)
				Expect(err).NotTo(HaveOccurred())
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusBadRequest))
			})
		})
		Context("Provide a Host data that contains malformed connection string", func() {
			It("Should fail to create new Host", func() {
				router.Handle("/hosts", hvsRoutes.ErrorHandler(hvsRoutes.ResponseHandler(hostController.Create))).Methods("POST")
				hostJson := `{
								"host_name": "localhost3",
								"connection_string": "intel:https://t a.ip.com:1443",
								"description": "Intel Host"
							}`

				req, err := http.NewRequest(
					"POST",
					"/hosts",
					strings.NewReader(hostJson),
				)
				Expect(err).NotTo(HaveOccurred())
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusBadRequest))
			})
		})
		Context("Provide a Host data that contains invalid hostname", func() {
			It("Should fail to create new Host", func() {
				router.Handle("/hosts", hvsRoutes.ErrorHandler(hvsRoutes.ResponseHandler(hostController.Create))).Methods("POST")
				hostJson := `{
								"host_name": "local host",
								"connection_string": "intel:https://ta.ip.com:1443",
								"description": "Intel Host"
							}`

				req, err := http.NewRequest(
					"POST",
					"/hosts",
					strings.NewReader(hostJson),
				)
				Expect(err).NotTo(HaveOccurred())
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusBadRequest))
			})
		})
	})

	// Specs for HTTP Get to "/hosts/{id}"
	Describe("Retrieve an existing Host", func() {
		Context("Retrieve Host by ID", func() {
			It("Should retrieve a Host", func() {
				router.Handle("/hosts/{id:(?i:[a-fA-F0-9]{8}-[a-fA-F0-9]{4}-4[a-fA-F0-9]{3}-[8|9|aA|bB][a-fA-F0-9]{3}-[a-fA-F0-9]{12}$)}", hvsRoutes.ErrorHandler(hvsRoutes.ResponseHandler(hostController.Retrieve))).Methods("GET")
				req, err := http.NewRequest("GET", "/hosts/ee37c360-7eae-4250-a677-6ee12adce8e2", nil)
				Expect(err).NotTo(HaveOccurred())
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusOK))
			})
		})
		Context("Retrieve Host by non-existent ID", func() {
			It("Should fail to retrieve Host", func() {
				router.Handle("/hosts/{id:(?i:[a-fA-F0-9]{8}-[a-fA-F0-9]{4}-4[a-fA-F0-9]{3}-[8|9|aA|bB][a-fA-F0-9]{3}-[a-fA-F0-9]{12}$)}", hvsRoutes.ErrorHandler(hvsRoutes.ResponseHandler(hostController.Retrieve))).Methods("GET")
				req, err := http.NewRequest("GET", "/hosts/73755fda-c910-46be-821f-e8ddeab189e9", nil)
				Expect(err).NotTo(HaveOccurred())
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusNotFound))
			})
		})
	})

	// Specs for HTTP Put to "/hosts/{id}"
	Describe("Update an existing Host", func() {
		Context("Provide a valid Host data", func() {
			It("Should update an existing Host", func() {
				router.Handle("/hosts/{id:(?i:[a-fA-F0-9]{8}-[a-fA-F0-9]{4}-4[a-fA-F0-9]{3}-[8|9|aA|bB][a-fA-F0-9]{3}-[a-fA-F0-9]{12}$)}", hvsRoutes.ErrorHandler(hvsRoutes.ResponseHandler(hostController.Update))).Methods("PUT")
				hostJson := `{
								"host_name": "127.0.0.1",
								"connection_string": "intel:https://127.0.0.1:1443"
							}`

				req, err := http.NewRequest(
					"PUT",
					"/hosts/ee37c360-7eae-4250-a677-6ee12adce8e2",
					strings.NewReader(hostJson),
				)
				Expect(err).NotTo(HaveOccurred())
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusOK))
			})
		})
		Context("Provide a Host data that contains malformed connection string", func() {
			It("Should fail to update Host", func() {
				router.Handle("/hosts/{id:(?i:[a-fA-F0-9]{8}-[a-fA-F0-9]{4}-4[a-fA-F0-9]{3}-[8|9|aA|bB][a-fA-F0-9]{3}-[a-fA-F0-9]{12}$)}", hvsRoutes.ErrorHandler(hvsRoutes.ResponseHandler(hostController.Update))).Methods("PUT")
				hostJson := `{
								"host_name": "localhost1",
								"connection_string": "intel:https://t a.ip.com:1443"
							}`

				req, err := http.NewRequest(
					"PUT",
					"/hosts/ee37c360-7eae-4250-a677-6ee12adce8e2",
					strings.NewReader(hostJson),
				)
				Expect(err).NotTo(HaveOccurred())
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusBadRequest))
			})
		})
		Context("Provide a non-existent Host data", func() {
			It("Should fail to update Host", func() {
				router.Handle("/hosts/{id:(?i:[a-fA-F0-9]{8}-[a-fA-F0-9]{4}-4[a-fA-F0-9]{3}-[8|9|aA|bB][a-fA-F0-9]{3}-[a-fA-F0-9]{12}$)}", hvsRoutes.ErrorHandler(hvsRoutes.ResponseHandler(hostController.Update))).Methods("PUT")
				hostJson := `{
								"host_name": "localhost1",
								"connection_string": "intel:https://ta.ip.com:1443"
							}`

				req, err := http.NewRequest(
					"PUT",
					"/hosts/73755fda-c910-46be-821f-e8ddeab189e9",
					strings.NewReader(hostJson),
				)
				Expect(err).NotTo(HaveOccurred())
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusNotFound))
			})
		})
	})

	// Specs for HTTP Delete to "/hosts/{id}"
	Describe("Delete an existing Host", func() {
		Context("Delete Host by ID", func() {
			It("Should delete a Host", func() {
				router.Handle("/hosts/{id:(?i:[a-fA-F0-9]{8}-[a-fA-F0-9]{4}-4[a-fA-F0-9]{3}-[8|9|aA|bB][a-fA-F0-9]{3}-[a-fA-F0-9]{12}$)}", hvsRoutes.ErrorHandler(hvsRoutes.ResponseHandler(hostController.Delete))).Methods("DELETE")
				req, err := http.NewRequest("DELETE","/hosts/ee37c360-7eae-4250-a677-6ee12adce8e2",nil)
				Expect(err).NotTo(HaveOccurred())
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusNoContent))
			})
		})
		Context("Delete Host by non-existent ID", func() {
			It("Should fail to delete Host", func() {
				router.Handle("/hosts/{id:(?i:[a-fA-F0-9]{8}-[a-fA-F0-9]{4}-4[a-fA-F0-9]{3}-[8|9|aA|bB][a-fA-F0-9]{3}-[a-fA-F0-9]{12}$)}", hvsRoutes.ErrorHandler(hvsRoutes.ResponseHandler(hostController.Delete))).Methods("DELETE")
				req, err := http.NewRequest("DELETE","/hosts/73755fda-c910-46be-821f-e8ddeab189e9",nil)
				Expect(err).NotTo(HaveOccurred())
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusNotFound))
			})
		})
	})

	// Specs for HTTP Get to "/hosts"
	Describe("Search for all the Hosts", func() {
		Context("Get all the Hosts", func() {
			It("Should get list of all the Hosts", func() {
				router.Handle("/hosts", hvsRoutes.ErrorHandler(hvsRoutes.ResponseHandler(hostController.Search))).Methods("GET")
				req, err := http.NewRequest("GET", "/hosts", nil)
				Expect(err).NotTo(HaveOccurred())
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusOK))

				var hostCollection hvs.HostCollection
				json.Unmarshal(w.Body.Bytes(), &hostCollection)
				// Verifying mocked data of 2 hosts
				Expect(len(hostCollection.Hosts)).To(Equal(2))
			})
		})
		Context("Get all the Hosts with hostname", func() {
			It("Should get list of all the filtered Hosts", func() {
				router.Handle("/hosts", hvsRoutes.ErrorHandler(hvsRoutes.ResponseHandler(hostController.Search))).Methods("GET")
				req, err := http.NewRequest("GET", "/hosts?nameContains=localhost", nil)
				Expect(err).NotTo(HaveOccurred())
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusOK))

				var hostCollection hvs.HostCollection
				json.Unmarshal(w.Body.Bytes(), &hostCollection)
				// Verifying mocked data of 2 hosts
				Expect(len(hostCollection.Hosts)).To(Equal(2))
			})
		})
		Context("Get all the Hosts with invalid hostname", func() {
			It("Should fail to get Hosts", func() {
				router.Handle("/hosts", hvsRoutes.ErrorHandler(hvsRoutes.ResponseHandler(hostController.Search))).Methods("GET")
				req, err := http.NewRequest("GET", "/hosts?nameContains=local host", nil)
				Expect(err).NotTo(HaveOccurred())
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusBadRequest))
			})
		})
	})
})
