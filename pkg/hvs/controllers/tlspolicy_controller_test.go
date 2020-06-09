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

var _ = Describe("TlsPolicyController", func() {
	var router *mux.Router
	var w *httptest.ResponseRecorder
	var tlsPolicyStore *mocks.MockTlsPolicyStore
	var tlsPolicyController *controllers.TlsPolicyController
	BeforeEach(func() {
		router = mux.NewRouter()
		tlsPolicyStore = mocks.NewMockTlsPolicyStore()
		tlsPolicyController = &controllers.TlsPolicyController{Store: tlsPolicyStore}
	})

	// Specs for HTTP Post to "/tls-policies"
	Describe("Create a new TlsPolicy", func() {
		Context("Provide a valid TlsPolicy data", func() {
			It("Should create a new TlsPolicy", func() {
				router.Handle("/tls-policies", hvsRoutes.ErrorHandler(hvsRoutes.ResponseHandler(tlsPolicyController.Create))).Methods("POST")
				tlsPolicyJson := `{
								"name": "hvs_tlspolicy_test3",
								"private": true,
								"descriptor": {
									"policy_type": "certificate",
									"meta": {
										"encoding": "base64"
									},
									"data": ["MIIBwzCCASygAwIBAgIJANE6wc0/mOjZMA0GCSqGSIb3DQEBCwUAMBExDzANBgNVBAMTBnRlc3RjYTAeFw0xNDA2MjQyMDQ1MjdaFw0xNDA3MjQyMDQ1MjdaMBExDzANBgNVBAMTBnRlc3RjYTCBnzANBgkqhkiG9w0BAQEFAAOBjQAwgYkCgYEAt9EmIilK3qSRGMRxEtcGj42dsJUf5h2OZIG25Er7dDxJbdw6KrOQhVUUx+2DUOQLMsr3sJt9D5eyWC4+vhoiNRMUjamR52/hjIBosr2XTfWKdKG8NsuDzwljHkB/6uv3P+AfQQ/eStXc42cv8J6vZXeQF6QMf63roW8i6SNYHwMCAwEAAaMjMCEwDgYDVR0PAQH/BAQDAgIEMA8GA1UdEwEB/wQFMAMBAf8wDQYJKoZIhvcNAQELBQADgYEAXov/vFVOMAznD+BT8tBfAT1R/nWFmrFB7os4Ry1mYjbr0lrW2vtUzA2XFx6nUzafYdyL1L4PnI7LGYqRqicT6WzGb1grNTJUJhrI7FkGg6TXQ4QSf6EmcEwsTlGHk9rxp9YySJt/xrhboP33abdXMHUWOXnJEHu4la8tnuzwSvM="]
								}
							}`

				req, err := http.NewRequest(
					"POST",
					"/tls-policies",
					strings.NewReader(tlsPolicyJson),
				)
				Expect(err).NotTo(HaveOccurred())
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(201))
			})
		})
		Context("Provide a TlsPolicy data that contains duplicate name", func() {
			It("Should fail to create new TlsPolicy", func() {
				router.Handle("/tls-policies", hvsRoutes.ErrorHandler(hvsRoutes.ResponseHandler(tlsPolicyController.Create))).Methods("POST")
				tlsPolicyJson := `{
								"name": "hvs_tlspolicy_test2",
								"private": true,
								"descriptor": {
									"policy_type": "certificate",
									"meta": {
										"encoding": "base64"
									},
									"data": ["MIIBwzCCASygAwIBAgIJANE6wc0/mOjZMA0GCSqGSIb3DQEBCwUAMBExDzANBgNVBAMTBnRlc3RjYTAeFw0xNDA2MjQyMDQ1MjdaFw0xNDA3MjQyMDQ1MjdaMBExDzANBgNVBAMTBnRlc3RjYTCBnzANBgkqhkiG9w0BAQEFAAOBjQAwgYkCgYEAt9EmIilK3qSRGMRxEtcGj42dsJUf5h2OZIG25Er7dDxJbdw6KrOQhVUUx+2DUOQLMsr3sJt9D5eyWC4+vhoiNRMUjamR52/hjIBosr2XTfWKdKG8NsuDzwljHkB/6uv3P+AfQQ/eStXc42cv8J6vZXeQF6QMf63roW8i6SNYHwMCAwEAAaMjMCEwDgYDVR0PAQH/BAQDAgIEMA8GA1UdEwEB/wQFMAMBAf8wDQYJKoZIhvcNAQELBQADgYEAXov/vFVOMAznD+BT8tBfAT1R/nWFmrFB7os4Ry1mYjbr0lrW2vtUzA2XFx6nUzafYdyL1L4PnI7LGYqRqicT6WzGb1grNTJUJhrI7FkGg6TXQ4QSf6EmcEwsTlGHk9rxp9YySJt/xrhboP33abdXMHUWOXnJEHu4la8tnuzwSvM="]
								}
							}`

				req, err := http.NewRequest(
					"POST",
					"/tls-policies",
					strings.NewReader(tlsPolicyJson),
				)
				Expect(err).NotTo(HaveOccurred())
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(400))
			})
		})
		Context("Provide a TlsPolicy data that contains prohibited policy type", func() {
			It("Should fail to create new TlsPolicy", func() {
				router.Handle("/tls-policies", hvsRoutes.ErrorHandler(hvsRoutes.ResponseHandler(tlsPolicyController.Create))).Methods("POST")
				tlsPolicyJson := `{
								"name": "hvs_tlspolicy_test3",
								"private": true,
								"descriptor": {
									"policy_type": "certificate-digest",
									"meta": {
										"digest_algorithm": "SHA-1"
									},
									"data": ["d0 8f 07 b0 5c 6d 78 62 b9 27 48 ff 35 da 27 bf f2 03 b3 c1"]
								}
							}`

				req, err := http.NewRequest(
					"POST",
					"/tls-policies",
					strings.NewReader(tlsPolicyJson),
				)
				Expect(err).NotTo(HaveOccurred())
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(400))
			})
		})
		Context("Provide a TlsPolicy data that contains empty name", func() {
			It("Should fail to create new TlsPolicy", func() {
				router.Handle("/tls-policies", hvsRoutes.ErrorHandler(hvsRoutes.ResponseHandler(tlsPolicyController.Create))).Methods("POST")
				tlsPolicyJson := `{
								"name": "",
								"private": true,
								"descriptor": {
									"policy_type": "certificate",
									"meta": {
										"encoding": "base64"
									},
									"data": ["MIIBwzCCASygAwIBAgIJANE6wc0/mOjZMA0GCSqGSIb3DQEBCwUAMBExDzANBgNVBAMTBnRlc3RjYTAeFw0xNDA2MjQyMDQ1MjdaFw0xNDA3MjQyMDQ1MjdaMBExDzANBgNVBAMTBnRlc3RjYTCBnzANBgkqhkiG9w0BAQEFAAOBjQAwgYkCgYEAt9EmIilK3qSRGMRxEtcGj42dsJUf5h2OZIG25Er7dDxJbdw6KrOQhVUUx+2DUOQLMsr3sJt9D5eyWC4+vhoiNRMUjamR52/hjIBosr2XTfWKdKG8NsuDzwljHkB/6uv3P+AfQQ/eStXc42cv8J6vZXeQF6QMf63roW8i6SNYHwMCAwEAAaMjMCEwDgYDVR0PAQH/BAQDAgIEMA8GA1UdEwEB/wQFMAMBAf8wDQYJKoZIhvcNAQELBQADgYEAXov/vFVOMAznD+BT8tBfAT1R/nWFmrFB7os4Ry1mYjbr0lrW2vtUzA2XFx6nUzafYdyL1L4PnI7LGYqRqicT6WzGb1grNTJUJhrI7FkGg6TXQ4QSf6EmcEwsTlGHk9rxp9YySJt/xrhboP33abdXMHUWOXnJEHu4la8tnuzwSvM="]
								}
							}`

				req, err := http.NewRequest(
					"POST",
					"/tls-policies",
					strings.NewReader(tlsPolicyJson),
				)
				Expect(err).NotTo(HaveOccurred())
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(400))
			})
		})
	})

	// Specs for HTTP Get to "/tls-policies/{id}"
	Describe("Retrieve an existing TlsPolicy", func() {
		Context("Retrieve TlsPolicy by ID", func() {
			It("Should retrieve a TlsPolicy", func() {
				router.Handle("/tls-policies/{id:(?i:[a-fA-F0-9]{8}-[a-fA-F0-9]{4}-4[a-fA-F0-9]{3}-[8|9|aA|bB][a-fA-F0-9]{3}-[a-fA-F0-9]{12}$)}", hvsRoutes.ErrorHandler(hvsRoutes.ResponseHandler(tlsPolicyController.Retrieve))).Methods("GET")
				req, err := http.NewRequest("GET", "/tls-policies/ee37c360-7eae-4250-a677-6ee12adce8e2", nil)
				Expect(err).NotTo(HaveOccurred())
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(200))
			})
		})
		Context("Retrieve TlsPolicy by non-existent ID", func() {
			It("Should fail to retrieve TlsPolicy", func() {
				router.Handle("/tls-policies/{id:(?i:[a-fA-F0-9]{8}-[a-fA-F0-9]{4}-4[a-fA-F0-9]{3}-[8|9|aA|bB][a-fA-F0-9]{3}-[a-fA-F0-9]{12}$)}", hvsRoutes.ErrorHandler(hvsRoutes.ResponseHandler(tlsPolicyController.Retrieve))).Methods("GET")
				req, err := http.NewRequest("GET", "/tls-policies/73755fda-c910-46be-821f-e8ddeab189e9", nil)
				Expect(err).NotTo(HaveOccurred())
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(404))
			})
		})
	})

	// Specs for HTTP Put to "/tls-policies/{id}"
	Describe("Update an existing TlsPolicy", func() {
		Context("Provide a valid TlsPolicy data", func() {
			It("Should update an existing TlsPolicy", func() {
				router.Handle("/tls-policies/{id:(?i:[a-fA-F0-9]{8}-[a-fA-F0-9]{4}-4[a-fA-F0-9]{3}-[8|9|aA|bB][a-fA-F0-9]{3}-[a-fA-F0-9]{12}$)}", hvsRoutes.ErrorHandler(hvsRoutes.ResponseHandler(tlsPolicyController.Update))).Methods("PUT")
				tlsPolicyJson := `{
								"name": "hvs_tlspolicy_test1",
								"private": false
							}`

				req, err := http.NewRequest(
					"PUT",
					"/tls-policies/ee37c360-7eae-4250-a677-6ee12adce8e2",
					strings.NewReader(tlsPolicyJson),
				)
				Expect(err).NotTo(HaveOccurred())
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(201))
			})
		})
		Context("Provide a TlsPolicy data that contains prohibited policy type", func() {
			It("Should fail to update TlsPolicy", func() {
				router.Handle("/tls-policies/{id:(?i:[a-fA-F0-9]{8}-[a-fA-F0-9]{4}-4[a-fA-F0-9]{3}-[8|9|aA|bB][a-fA-F0-9]{3}-[a-fA-F0-9]{12}$)}", hvsRoutes.ErrorHandler(hvsRoutes.ResponseHandler(tlsPolicyController.Update))).Methods("PUT")
				tlsPolicyJson := `{
								"name": "hvs_tlspolicy_test1",
								"descriptor": {
									"policy_type": "certificate-digest",
									"meta": {
										"digest_algorithm": "SHA-1"
									},
									"data": ["d0 8f 07 b0 5c 6d 78 62 b9 27 48 ff 35 da 27 bf f2 03 b3 c1"]
								}
							}`

				req, err := http.NewRequest(
					"PUT",
					"/tls-policies/ee37c360-7eae-4250-a677-6ee12adce8e2",
					strings.NewReader(tlsPolicyJson),
				)
				Expect(err).NotTo(HaveOccurred())
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(400))
			})
		})
		Context("Provide a non-existent TlsPolicy data", func() {
			It("Should fail to update TlsPolicy", func() {
				router.Handle("/tls-policies/{id:(?i:[a-fA-F0-9]{8}-[a-fA-F0-9]{4}-4[a-fA-F0-9]{3}-[8|9|aA|bB][a-fA-F0-9]{3}-[a-fA-F0-9]{12}$)}", hvsRoutes.ErrorHandler(hvsRoutes.ResponseHandler(tlsPolicyController.Update))).Methods("PUT")
				tlsPolicyJson := `{
								"name": "hvs_tlspolicy_test1",
								"private": false
							}`

				req, err := http.NewRequest(
					"PUT",
					"/tls-policies/73755fda-c910-46be-821f-e8ddeab189e9",
					strings.NewReader(tlsPolicyJson),
				)
				Expect(err).NotTo(HaveOccurred())
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(404))
			})
		})
	})

	// Specs for HTTP Delete to "/tls-policies/{id}"
	Describe("Delete an existing TlsPolicy", func() {
		Context("Delete TlsPolicy by ID", func() {
			It("Should delete a TlsPolicy", func() {
				router.Handle("/tls-policies/{id:(?i:[a-fA-F0-9]{8}-[a-fA-F0-9]{4}-4[a-fA-F0-9]{3}-[8|9|aA|bB][a-fA-F0-9]{3}-[a-fA-F0-9]{12}$)}", hvsRoutes.ErrorHandler(hvsRoutes.ResponseHandler(tlsPolicyController.Delete))).Methods("DELETE")
				req, err := http.NewRequest("DELETE","/tls-policies/ee37c360-7eae-4250-a677-6ee12adce8e2",nil)
				Expect(err).NotTo(HaveOccurred())
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(204))
			})
		})
		Context("Delete TlsPolicy by non-existent ID", func() {
			It("Should fail to delete TlsPolicy", func() {
				router.Handle("/tls-policies/{id:(?i:[a-fA-F0-9]{8}-[a-fA-F0-9]{4}-4[a-fA-F0-9]{3}-[8|9|aA|bB][a-fA-F0-9]{3}-[a-fA-F0-9]{12}$)}", hvsRoutes.ErrorHandler(hvsRoutes.ResponseHandler(tlsPolicyController.Delete))).Methods("DELETE")
				req, err := http.NewRequest("DELETE","/tls-policies/73755fda-c910-46be-821f-e8ddeab189e9",nil)
				Expect(err).NotTo(HaveOccurred())
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(404))
			})
		})
	})

	// Specs for HTTP Get to "/tls-policies"
	Describe("Search for all the TlsPolicies", func() {
		Context("Get all the TlsPolicies", func() {
			It("Should get list of all the TlsPolicies", func() {
				router.Handle("/tls-policies", hvsRoutes.ErrorHandler(hvsRoutes.ResponseHandler(tlsPolicyController.Search))).Methods("GET")
				req, err := http.NewRequest("GET", "/tls-policies", nil)
				Expect(err).NotTo(HaveOccurred())
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(200))

				var tlsPolicyCollection hvs.TlsPolicyCollection
				json.Unmarshal(w.Body.Bytes(), &tlsPolicyCollection)
				// Verifying mocked data of 2 tls policies
				Expect(len(tlsPolicyCollection.TlsPolicies)).To(Equal(2))
			})
		})
		Context("Get all the TlsPolicies with private scope", func() {
			It("Should get list of all the private TlsPolicies", func() {
				router.Handle("/tls-policies", hvsRoutes.ErrorHandler(hvsRoutes.ResponseHandler(tlsPolicyController.Search))).Methods("GET")
				req, err := http.NewRequest("GET", "/tls-policies?privateEqualTo=true", nil)
				Expect(err).NotTo(HaveOccurred())
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(200))

				var tlsPolicyCollection hvs.TlsPolicyCollection
				json.Unmarshal(w.Body.Bytes(), &tlsPolicyCollection)
				// Verifying mocked data of 2 tls policies
				Expect(len(tlsPolicyCollection.TlsPolicies)).To(Equal(2))
			})
		})
		Context("Get all the TlsPolicies with invalid private scope", func() {
			It("Should fail to get TlsPolicies", func() {
				router.Handle("/tls-policies", hvsRoutes.ErrorHandler(hvsRoutes.ResponseHandler(tlsPolicyController.Search))).Methods("GET")
				req, err := http.NewRequest("GET", "/tls-policies?privateEqualTo=private", nil)
				Expect(err).NotTo(HaveOccurred())
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(400))
			})
		})
	})
})
