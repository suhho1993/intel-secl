/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */

package controllers_test

import (
	"encoding/json"
	"github.com/intel-secl/intel-secl/v3/pkg/hvs/controllers"
	mocks2 "github.com/intel-secl/intel-secl/v3/pkg/hvs/domain/mocks"
	hvsRoutes "github.com/intel-secl/intel-secl/v3/pkg/hvs/router"
	"github.com/intel-secl/intel-secl/v3/pkg/model/hvs"
	"net/http"
	"net/http/httptest"
	"strings"

	"github.com/gorilla/mux"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)


var _ = Describe("TpmEndorsementController", func() {
	var router *mux.Router
	var w *httptest.ResponseRecorder
	var mockEndorsement *mocks2.MockTpmEndorsementStore
	var tpmEndorsmentController *controllers.TpmEndorsementController

	BeforeEach(func() {
		router = mux.NewRouter()
		mockEndorsement = mocks2.NewFakeTpmEndorsementStore()
		tpmEndorsmentController = &controllers.TpmEndorsementController{Store: mockEndorsement}
	})


	// Specs for HTTP Get to "/tpm-endorsements"
	Describe("Get list of TpmEndorsements", func() {
		Context("Get all TpmEndorsements from data store", func() {
			It("Should get list of TpmEndorsements", func() {

				router.Handle("/tpm-endorsements", hvsRoutes.ErrorHandler(hvsRoutes.ResponseHandler(tpmEndorsmentController.Search))).Methods("GET")
				req, err := http.NewRequest("GET", "/tpm-endorsements", nil)
				Expect(err).NotTo(HaveOccurred())
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(200))

				var teCollection *hvs.TpmEndorsementCollection
				json.Unmarshal(w.Body.Bytes(), &teCollection)
				Expect(len(teCollection.TpmEndorsement)).To(Equal(2))
			})
		})

		Context("Search TpmEndorsements from data store based on issuerEqualTo as filter criteria", func() {
			It("Should get filtered list of TpmEndorsements", func() {
				router.Handle("/tpm-endorsements", hvsRoutes.ErrorHandler(hvsRoutes.ResponseHandler(tpmEndorsmentController.Search))).Methods("GET")
				req, err := http.NewRequest("GET", "/tpm-endorsements?issuerEqualTo=CN=Infineon OPTIGA(TM) RSA Manufacturing CA 007,OU=OPTIGA(TM) TPM2.0,O=Infineon Technologies AG,C=DE", nil)
				Expect(err).NotTo(HaveOccurred())
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(200))
				var teCollection *hvs.TpmEndorsementCollection
				json.Unmarshal(w.Body.Bytes(), &teCollection)
				Expect(len(teCollection.TpmEndorsement)).To(Equal(2))
			})
		})
		Context("Search TpmEndorsements from data store based on commentContains as filter criteria", func() {
			It("Should get filtered list of TpmEndorsements", func() {
				router.Handle("/tpm-endorsements", hvsRoutes.ErrorHandler(hvsRoutes.ResponseHandler(tpmEndorsmentController.Search))).Methods("GET")
				req, err := http.NewRequest("GET", "/tpm-endorsements?commentContains=trust agent", nil)
				Expect(err).NotTo(HaveOccurred())
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(200))

				var teCollection *hvs.TpmEndorsementCollection
				json.Unmarshal(w.Body.Bytes(), &teCollection)
				Expect(len(teCollection.TpmEndorsement)).To(Equal(1))
			})
		})
		Context("Search TpmEndorsements from data store based on hardwareUuidEqualTo filter criteria", func() {
			It("Should get list of TpmEndorsements", func() {
				router.Handle("/tpm-endorsements", hvsRoutes.ErrorHandler(hvsRoutes.ResponseHandler(tpmEndorsmentController.Search))).Methods("GET")
				req, err := http.NewRequest("GET", "/tpm-endorsements?hardwareUuidEqualTo=ee37c360-7eae-4250-a677-6ee12adce8e5", nil)
				Expect(err).NotTo(HaveOccurred())
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(200))

				var teCollection *hvs.TpmEndorsementCollection
				json.Unmarshal(w.Body.Bytes(), &teCollection)
				Expect(len(teCollection.TpmEndorsement)).To(Equal(1))
			})
		})
		Context("Search TpmEndorsements from data store based on commentEqualTo as filter criteria", func() {
			It("Should get filtered list of TpmEndorsements", func() {
				router.Handle("/tpm-endorsements", hvsRoutes.ErrorHandler(hvsRoutes.ResponseHandler(tpmEndorsmentController.Search))).Methods("GET")
				req, err := http.NewRequest("GET", "/tpm-endorsements?commentEqualTo=registered by trust agent", nil)
				Expect(err).NotTo(HaveOccurred())
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(200))

				var teCollection *hvs.TpmEndorsementCollection
				json.Unmarshal(w.Body.Bytes(), &teCollection)
				Expect(len(teCollection.TpmEndorsement)).To(Equal(1))
			})
		})
		Context("Search TpmEndorsements from data store based on revoked as filter criteria", func() {
			It("Should get filtered list of TpmEndorsements", func() {
				router.Handle("/tpm-endorsements", hvsRoutes.ErrorHandler(hvsRoutes.ResponseHandler(tpmEndorsmentController.Search))).Methods("GET")
				req, err := http.NewRequest("GET", "/tpm-endorsements?revokedEqualTo=false", nil)
				Expect(err).NotTo(HaveOccurred())
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(200))

				var teCollection *hvs.TpmEndorsementCollection
				json.Unmarshal(w.Body.Bytes(), &teCollection)
				Expect(len(teCollection.TpmEndorsement)).To(Equal(1))
			})
		})
		Context("Search TpmEndorsements from data store based on commentContains as filter criteria with special characters", func() {
			It("Should return bad request error", func() {
				router.Handle("/tpm-endorsements", hvsRoutes.ErrorHandler(hvsRoutes.ResponseHandler(tpmEndorsmentController.Search))).Methods("GET")
				req, err := http.NewRequest("GET", "/tpm-endorsements?commentContains=trust%20>-agent", nil)
				Expect(err).NotTo(HaveOccurred())
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(400))
			})
		})
		Context("Search TpmEndorsements from data store with invalid id", func() {
			It("Should return bad request error", func() {
				router.Handle("/tpm-endorsements", hvsRoutes.ErrorHandler(hvsRoutes.ResponseHandler(tpmEndorsmentController.Search))).Methods("GET")
				req, err := http.NewRequest("GET", "/tpm-endorsements?id=ijogoirjti", nil)
				Expect(err).NotTo(HaveOccurred())
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(400))
			})
		})

	})

	// Specs for HTTP Get to "/tpm-endorsements/{endorsement_id}"
	Describe("Get TpmEndorsement by ID", func() {
		Context("Retrieve TpmEndorsement by ID from data store", func() {
			It("Should retrieve TpmEndorsement", func() {
				router.Handle("/tpm-endorsements/{id}", hvsRoutes.ErrorHandler(hvsRoutes.ResponseHandler(tpmEndorsmentController.Retrieve))).Methods("GET")
				req, err := http.NewRequest("GET", "/tpm-endorsements/ee37c360-7eae-4250-a677-6ee12adce8e2", nil)
				Expect(err).NotTo(HaveOccurred())
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(200))
			})
		})
		Context("Try to retrieve TpmEndorsement by invalid ID from data store", func() {
			It("Should fail to retrieve TpmEndorsement", func() {
				router.Handle("/tpm-endorsements/{id}", hvsRoutes.ErrorHandler(hvsRoutes.ResponseHandler(tpmEndorsmentController.Retrieve))).Methods("GET")
				req, _ := http.NewRequest("GET", "/tpm-endorsements/73755fda-c910-46be-821f-e8ddeab189e9", nil)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(404))
			})
		})
	})

	// Specs for HTTP Delete to "/tpm-endorsements/{id}"
	Describe("Delete TpmEndorsement by ID", func() {
		Context("Delete TpmEndorsement by ID from data store", func() {
			It("Should delete TpmEndorsement", func() {
				router.Handle("/tpm-endorsements/{id}", hvsRoutes.ErrorHandler(hvsRoutes.ResponseHandler(tpmEndorsmentController.Delete))).Methods("DELETE")
				req, err := http.NewRequest("DELETE", "/tpm-endorsements/ee37c360-7eae-4250-a677-6ee12adce8e2", nil)
				Expect(err).NotTo(HaveOccurred())
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(204))
			})
		})
		Context("Delete TpmEndorsement by invalid ID from data store", func() {
			It("Should fail to delete TpmEndorsement", func() {
				router.Handle("/tpm-endorsements/{id}", hvsRoutes.ErrorHandler(hvsRoutes.ResponseHandler(tpmEndorsmentController.Delete))).Methods("DELETE")
				req, err := http.NewRequest("DELETE", "/tpm-endorsements/ee37c360-7eae-4250-a677-6ee12adce8e6", nil)
				Expect(err).NotTo(HaveOccurred())
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(404))
			})
		})
	})

	// Specs for HTTP Delete to "/tpm-endorsements"
	Describe("Delete TpmEndorsement by criteria", func() {
		Context("Delete TpmEndorsement for filter revoked=false", func() {
			It("Should delete TpmEndorsement", func() {
				router.Handle("/tpm-endorsements", hvsRoutes.ErrorHandler(hvsRoutes.ResponseHandler(tpmEndorsmentController.DeleteCollection))).Methods("DELETE")
				req, err := http.NewRequest("DELETE", "/tpm-endorsements?revoked=false", nil)
				Expect(err).NotTo(HaveOccurred())
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(204))
			})
		})
		Context("Delete TpmEndorsement by incorrect ID from data store", func() {
			It("Should get HTTP Status: 400", func() {
				router.Handle("/tpm-endorsements", hvsRoutes.ErrorHandler(hvsRoutes.ResponseHandler(tpmEndorsmentController.DeleteCollection))).Methods("DELETE")
				req, err := http.NewRequest("DELETE", "/tpm-endorsements?id=ijogoirjti", nil)
				Expect(err).NotTo(HaveOccurred())
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(400))
			})
		})
	})
	// Specs for HTTP Post to "/tpm-endorsements"
	Describe("Post a new TpmEndorsement", func() {
		Context("Provide a valid TpmEndorsement data", func() {
			It("Should create a new TpmEndorsement and get HTTP Status: 201", func() {
				router.Handle("/tpm-endorsements", hvsRoutes.ErrorHandler(hvsRoutes.ResponseHandler(tpmEndorsmentController.Create))).Methods("POST")
				tpmEndorsementJson := `{ 
                                        "hardware_uuid": "eb829e60-c8ef-46ab-ba33-6e62df3062a7",
                                        "issuer": "C = DE, O = Infineon Technologies AG, OU = OPTIGA(TM) TPM2.0, CN = Infineon OPTIGA(TM) RSA Manufacturing CA 007",
							            "certificate": "30820122300d06092a864886f70d01010105000382010f003082010a0282010100919eb68d44dfb84a08519c0d8eca57aa37798286769446b42090bad2375dd78e44e7c8dc85400bae3b6a923b6fbe7eeeaf17ac1a95f681d82ca1dc33fc4ac389b8f3f73c5b7a91c1096b99729fc6099eb8a11b19c795a88dafacc1e2a381a10d16fea697880cdf270ce10df30ed377e88e48be5004db1e2c2b52f04d9f292be21f760b35e6591bf252158a41e11ee257f15a1bf297d85211fea0a183b12cafe04bfbee760720fce609af6387fa7df584b528aba980278670b86e55376f09757676ed15358814552045007f440959d774dc6a9aaf47a3cd94d29f5ef3caf229883456947071b76843305843d5ebed3564cde1e50b0b720ecfef982eae64f94b4f0203010001"  
                                       }`

				req, err := http.NewRequest(
					"POST",
					"/tpm-endorsements",
					strings.NewReader(tpmEndorsementJson),
				)
				Expect(err).NotTo(HaveOccurred())
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(201))
			})
		})
		Context("Provide a TpmEndorsement data that contains duplicate hardware_uuid", func() {
			It("Should get HTTP Status: 400", func() {
				router.Handle("/tpm-endorsements", hvsRoutes.ErrorHandler(hvsRoutes.ResponseHandler(tpmEndorsmentController.Create))).Methods("POST")
				tpmEndorsementJson := `{
                            			"hardware_uuid": "ge37c360-7eae-4250-a677-6ee12adce8e3",
										"issuer": "CN=Infineon OPTIGA(TM) RSA Manufacturing CA",
										"certificate": "40820122300d06092a864886f70d01010105000382010f003082010a0282010100919eb68d44dfb84a08519c0d8eca57aa37798286769446b42090bad2375dd78e44e7c8dc85400bae3b6a923b6fbe7eeeaf17ac1a95f681d82ca1dc\n33fc4ac389b8f3f73c5b7a91c1096b99729fc6099eb8a11b19c795a88dafacc1e2a381a10d16fea697880cdf270ce10df30ed377e88e48be5004db1e2c2b52f04d9f292be21f760b35e6591bf252158a41e11ee257f15a1bf297d85211fea\n0a183b12cafe04bfbee760720fce609af6387fa7df584b528aba980278670b86e55376f09757676ed15358814552045007f440959d774dc6a9aaf47a3cd94d29f5ef3caf229883456947071b76843305843d5ebed3564cde1e50b0b720ecfef982eae64f94b4f02030100322"  
									}`

				req, err := http.NewRequest(
					"POST",
					"/tpm-endorsements",
					strings.NewReader(tpmEndorsementJson),
				)
				Expect(err).NotTo(HaveOccurred())
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(400))
			})
		})

		Context("Provide a TpmEndorsement data invalid data", func() {
			It("Should get HTTP Status: 400", func() {
				router.Handle("/tpm-endorsements", hvsRoutes.ErrorHandler(hvsRoutes.ResponseHandler(tpmEndorsmentController.Create))).Methods("POST")
				tpmEndorsementJson := `{
										"hardware_uuid": "ge37c360-7eae-4250-a677-6ee12",
										"issuer": "CN=Infineon OPTIGA(TM) RSA Manufacturing CA",
										"certificate": "40820122300d06092a864886f70d01010105000382010f003082010a0282010100919eb68d44dfb84a08519c0d8eca57aa37798286769446b42090bad2375dd78e44e7c8dc85400bae3b6a923b6fbe7eeeaf17ac1a95f681d82ca1dc\n33fc4ac389b8f3f73c5b7a91c1096b99729fc6099eb8a11b19c795a88dafacc1e2a381a10d16fea697880cdf270ce10df30ed377e88e48be5004db1e2c2b52f04d9f292be21f760b35e6591bf252158a41e11ee257f15a1bf297d85211fea\n0a183b12cafe04bfbee760720fce609af6387fa7df584b528aba980278670b86e55376f09757676ed15358814552045007f440959d774dc6a9aaf47a3cd94d29f5ef3caf229883456947071b76843305843d5ebed3564cde1e50b0b720ecfef982eae64f94b4f02030100322"  
										}`

				req, err := http.NewRequest(
					"POST",
					"/tpm-endorsements",
					strings.NewReader(tpmEndorsementJson),
				)
				Expect(err).NotTo(HaveOccurred())
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(400))
			})
		})

		Context("Provide a empty data  in request", func() {
			It("Should get HTTP Status: 400", func() {
				router.Handle("/tpm-endorsements", hvsRoutes.ErrorHandler(hvsRoutes.ResponseHandler(tpmEndorsmentController.Create))).Methods("POST")
				data := ``
				req, err := http.NewRequest(
					"POST",
					"/tpm-endorsements",
					strings.NewReader(data),
				)
				Expect(err).NotTo(HaveOccurred())
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(400))
			})
		})
	})

	// Specs for HTTP PUT to "/tpm-endorsements/{id}"
	Describe("Update TpmEndorsement", func() {
		Context("Provide a valid TpmEndorsement data", func() {
			It("Should update TpmEndorsement and get HTTP Status: 200", func() {
				router.Handle("/tpm-endorsements/{id}", hvsRoutes.ErrorHandler(hvsRoutes.ResponseHandler(tpmEndorsmentController.Update))).Methods("PUT")
				tpmEndorsementJson := `{ 
                                        "hardware_uuid": "ee37c360-7eae-4250-a677-6ee12adce8e3",
                                        "issuer": "CN=Infineon OPTIGA(TM) RSA Manufacturing CA",
							            "certificate": "30820122300d06092a864886f70d01010105000382010f003082010a0282010100919eb68d44dfb84a08519c0d8eca57aa37798286769446b42090bad2375dd78e44e7c8dc85400bae3b6a923b6fbe7eeeaf17ac1a95f681d82ca1dc33fc4ac389b8f3f73c5b7a91c1096b99729fc6099eb8a11b19c795a88dafacc1e2a381a10d16fea697880cdf270ce10df30ed377e88e48be5004db1e2c2b52f04d9f292be21f760b35e6591bf252158a41e11ee257f15a1bf297d85211fea0a183b12cafe04bfbee760720fce609af6387fa7df584b528aba980278670b86e55376f09757676ed15358814552045007f440959d774dc6a9aaf47a3cd94d29f5ef3caf229883456947071b76843305843d5ebed3564cde1e50b0b720ecfef982eae64f94b4f0203010001"  
                                       }`

				req, err := http.NewRequest(
					"PUT",
					"/tpm-endorsements/ee37c360-7eae-4250-a677-6ee12adce8e2",
					strings.NewReader(tpmEndorsementJson),
				)
				Expect(err).NotTo(HaveOccurred())
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(200))
			})
		})

		Context("Provide a TpmEndorsement data that does not exist", func() {
			It("Should get HTTP Status: 404", func() {
				router.Handle("/tpm-endorsements/{id}", hvsRoutes.ErrorHandler(hvsRoutes.ResponseHandler(tpmEndorsmentController.Update))).Methods("PUT")
				tpmEndorsementJson := `{
										"hardware_uuid": "ee37c360-7eae-4250-a677-6ee12adce8e5",
										"issuer": "CN=Infineon OPTIGA(TM) RSA Manufacturing CA",
										"certificate": "30820122300d06092a864886f70d01010105000382010f003082010a0282010100919eb68d44dfb84a08519c0d8eca57aa37798286769446b42090bad2375dd78e44e7c8dc85400bae3b6a923b6fbe7eeeaf17ac1a95f681d82ca1dc33fc4ac389b8f3f73c5b7a91c1096b99729fc6099eb8a11b19c795a88dafacc1e2a381a10d16fea697880cdf270ce10df30ed377e88e48be5004db1e2c2b52f04d9f292be21f760b35e6591bf252158a41e11ee257f15a1bf297d85211fea0a183b12cafe04bfbee760720fce609af6387fa7df584b528aba980278670b86e55376f09757676ed15358814552045007f440959d774dc6a9aaf47a3cd94d29f5ef3caf229883456947071b76843305843d5ebed3564cde1e50b0b720ecfef982eae64f94b4f0203010001"  
										}`

				req, err := http.NewRequest(
					"PUT",
					"/tpm-endorsements/ee37c360-7eae-4250-a677-6ee12adce8e9",
					strings.NewReader(tpmEndorsementJson),
				)
				Expect(err).NotTo(HaveOccurred())
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(404))
			})
		})

		Context("Provide a invalid data", func() {
			It("Should get HTTP Status: 400", func() {
				router.Handle("/tpm-endorsements/{id}", hvsRoutes.ErrorHandler(hvsRoutes.ResponseHandler(tpmEndorsmentController.Update))).Methods("PUT")
				tpmEndorsementJson := `{
                            "hardware_uuid": "ee37c360-7eae-4250-a677-6ee12adce",
							"issuer": "CN=Infineon OPTIGA(TM) RSA Manufacturing CA",
							"certificate": "40820122300d06092a864886f70d01010105000382010f003082010a0282010100919eb68d44dfb84a08519c0d8eca57aa37798286769446b42090bad2375dd78e44e7c8dc85400bae3b6a923b6fbe7eeeaf17ac1a95f681d82ca1dc\n33fc4ac389b8f3f73c5b7a91c1096b99729fc6099eb8a11b19c795a88dafacc1e2a381a10d16fea697880cdf270ce10df30ed377e88e48be5004db1e2c2b52f04d9f292be21f760b35e6591bf252158a41e11ee257f15a1bf297d85211fea\n0a183b12cafe04bfbee760720fce609af6387fa7df584b528aba980278670b86e55376f09757676ed15358814552045007f440959d774dc6a9aaf47a3cd94d29f5ef3caf229883456947071b76843305843d5ebed3564cde1e50b0b720ecfef982eae64f94b4f02030100322"  
									}`

				req, err := http.NewRequest(
					"PUT",
					"/tpm-endorsements/ee37c360-7eae-4250-a677-6ee12adce8e4",
					strings.NewReader(tpmEndorsementJson),
				)
				Expect(err).NotTo(HaveOccurred())
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(400))
			})
		})

		Context("Provide a empty data  in request", func() {
			It("Should get HTTP Status: 400", func() {
				router.Handle("/tpm-endorsements/{id}", hvsRoutes.ErrorHandler(hvsRoutes.ResponseHandler(tpmEndorsmentController.Create))).Methods("PUT")
				data := ``
				req, err := http.NewRequest(
					"PUT",
					"/tpm-endorsements/ee37c360-7eae-4250-a677-6ee12adce8e2",
					strings.NewReader(data),
				)
				Expect(err).NotTo(HaveOccurred())
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(400))
			})
		})
	})
})