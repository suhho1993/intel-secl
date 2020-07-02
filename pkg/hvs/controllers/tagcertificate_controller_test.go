/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package controllers_test

import (
	"crypto"
	"encoding/json"
	"github.com/gorilla/mux"
	"github.com/intel-secl/intel-secl/v3/pkg/hvs/constants"
	"github.com/intel-secl/intel-secl/v3/pkg/hvs/controllers"
	mocks2 "github.com/intel-secl/intel-secl/v3/pkg/hvs/domain/mocks"
	"github.com/intel-secl/intel-secl/v3/pkg/hvs/domain/models"
	hvsRoutes "github.com/intel-secl/intel-secl/v3/pkg/hvs/router"
	"github.com/intel-secl/intel-secl/v3/pkg/lib/common/crypt"
	"github.com/intel-secl/intel-secl/v3/pkg/model/hvs"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"time"
)

var _ = Describe("TagCertificateController", func() {
	var router *mux.Router
	var w *httptest.ResponseRecorder
	var tagCertStore *mocks2.MockTagCertificateStore
	var tagCertController *controllers.TagCertificateController
	var signingCertPath = "../domain/mocks/tagcert-scert.pem"
	var signingKeyPath = "../domain/mocks/tagcert-skey.pem"
	var tagKey crypto.PrivateKey

	BeforeEach(func() {
		router = mux.NewRouter()
		tagCertStore = mocks2.NewFakeTagCertificateStore()

		//Generate Privacyca cert
		caCertBytes, key, _ := crypt.CreateKeyPairAndCertificate(constants.DefaultPrivacyCaIdentityIssuer, "", constants.DefaultKeyAlgorithm, constants.DefaultKeyAlgorithmLength)
		_ = crypt.SavePrivateKeyAsPKCS8(key, signingKeyPath)
		_ = crypt.SavePemCert(caCertBytes, signingCertPath)
		tagKey, _ = crypt.GetPrivateKeyFromPKCS8File(signingKeyPath)

		certMap, _ := crypt.GetSubjectCertsMapFromPemFile(signingCertPath)

		var tagCAStore = models.CertificateStore{
			Key:          &tagKey,
			CertPath:     signingCertPath,
			Certificates: certMap,
		}

		var caCertsStore = make(models.CertificatesStore)
		caCertsStore[models.CaCertTypesTagCa.String()] = &tagCAStore

		tagCertController = controllers.NewTagCertificateController(&caCertsStore, tagCertStore)
	})

	AfterEach(func() {
		_ = os.Remove(signingKeyPath)
		_ = os.Remove(signingCertPath)
	})

	Describe("Create TagCertificates", func() {
		Context("When a empty TagCertificate Create Request is passed", func() {
			It("A HTTP Status: 400 response is received", func() {
				router.Handle(hvsRoutes.TagCertificateEndpointPath, hvsRoutes.ErrorHandler(hvsRoutes.ResponseHandler(tagCertController.Create))).Methods("POST")

				// Create Request body
				createTcReq := ``

				req, err := http.NewRequest(
					"POST",
					hvsRoutes.TagCertificateEndpointPath,
					strings.NewReader(createTcReq),
				)
				Expect(err).NotTo(HaveOccurred())
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusBadRequest))
			})
		})

		Context("When a VALID TagCertificate Create Request is passed", func() {
			It("A new TagCertificate record is created and HTTP Status: 201 response is received", func() {
				router.Handle(hvsRoutes.TagCertificateEndpointPath, hvsRoutes.ErrorHandler(hvsRoutes.ResponseHandler(tagCertController.Create))).Methods("POST")

				// Create Request body
				createTcReq := `{ "hardware_uuid" : "56dffe6f-57f8-4f4c-9c98-7c6ef9cc0c8c", "selection_content" : [ { "name" : "Location", "value" : "SantaClara" }, { "name" : "Company", "value" : "IntelCorporation" } ] }`

				req, err := http.NewRequest(
					"POST",
					hvsRoutes.TagCertificateEndpointPath,
					strings.NewReader(createTcReq),
				)
				Expect(err).NotTo(HaveOccurred())
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusCreated))
			})
		})

		Context("When an INVALID TagCertificate Create Request with an empty hardware_uuid is passed", func() {
			It("A new TagCertificate record is NOT created and HTTP Status: 400 response is received", func() {
				router.Handle(hvsRoutes.TagCertificateEndpointPath, hvsRoutes.ErrorHandler(hvsRoutes.ResponseHandler(tagCertController.Create))).Methods("POST")

				// Create Request body
				createTcReq := `{"hardware_uuid" : "", "selection_content": [{ "name" : "Location", "value" : "SantaClara" }, { "name" : "Company", "value" : "IntelCorporation"}]}`

				req, err := http.NewRequest(
					"POST",
					hvsRoutes.TagCertificateEndpointPath,
					strings.NewReader(createTcReq),
				)
				Expect(err).NotTo(HaveOccurred())
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusBadRequest))
			})
		})

		Context("When an INVALID TagCertificate Create Request with no SelectionContent  is passed", func() {
			It("A new TagCertificate record is NOT created and HTTP Status: 400 response is received", func() {
				router.Handle(hvsRoutes.TagCertificateEndpointPath, hvsRoutes.ErrorHandler(hvsRoutes.ResponseHandler(tagCertController.Create))).Methods("POST")

				// Create Request body
				createTcReq := `{ "hardware_uuid" : "56dffe6f-57f8-4f4c-9c98-7c6ef9cc0c8c"}`

				req, err := http.NewRequest(
					"POST",
					hvsRoutes.TagCertificateEndpointPath,
					strings.NewReader(createTcReq),
				)
				Expect(err).NotTo(HaveOccurred())
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusBadRequest))
			})
		})
	})

	// Specs for HTTP Get to "/tag-certificates"
	Describe("Search TagCertificates", func() {
		Context("When no filter arguments are passed", func() {
			It("All TagCertificate records are returned and a 200 response code", func() {
				router.Handle(hvsRoutes.TagCertificateEndpointPath, hvsRoutes.ErrorHandler(hvsRoutes.ResponseHandler(tagCertController.Search))).Methods("GET")
				req, err := http.NewRequest("GET", hvsRoutes.TagCertificateEndpointPath, nil)
				Expect(err).NotTo(HaveOccurred())
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusOK))

				var tcCollection *hvs.TagCertificateCollection
				err = json.Unmarshal(w.Body.Bytes(), &tcCollection)
				Expect(err).ToNot(HaveOccurred())
				Expect(len(tcCollection.TagCertificates)).To(Equal(4))
			})
		})

		Context("When filtered by TagCertificate id", func() {
			It("Should get a single TagCertificate entry and a 200 response code", func() {
				router.Handle(hvsRoutes.TagCertificateEndpointPath, hvsRoutes.ErrorHandler(hvsRoutes.ResponseHandler(tagCertController.Search))).Methods("GET")
				req, err := http.NewRequest("GET", hvsRoutes.TagCertificateEndpointPath+"?id=fda6105d-a340-42da-bc35-0555e7a5e360", nil)
				Expect(err).NotTo(HaveOccurred())
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusOK))

				var tcCollection *hvs.TagCertificateCollection
				err = json.Unmarshal(w.Body.Bytes(), &tcCollection)
				Expect(err).NotTo(HaveOccurred())
				Expect(len(tcCollection.TagCertificates)).To(Equal(1))
			})
		})

		Context("When filtered by a non-existent TagCertificate id", func() {
			It("Should get an empty list of TagCertificates and 200 response code", func() {
				router.Handle(hvsRoutes.TagCertificateEndpointPath, hvsRoutes.ErrorHandler(hvsRoutes.ResponseHandler(tagCertController.Search))).Methods("GET")
				req, err := http.NewRequest("GET", hvsRoutes.TagCertificateEndpointPath+"?id=b47a13b1-0af2-47d6-91d0-717094bfda2d", nil)
				Expect(err).NotTo(HaveOccurred())
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusOK))

				var tcCollection *hvs.TagCertificateCollection
				err = json.Unmarshal(w.Body.Bytes(), &tcCollection)
				Expect(err).NotTo(HaveOccurred())
				Expect(tcCollection.TagCertificates).To(BeNil())
			})
		})

		Context("When filtered by an invalid TagCertificate id", func() {
			It("Should get an empty list of TagCertificates and a 400 response code", func() {
				router.Handle(hvsRoutes.TagCertificateEndpointPath, hvsRoutes.ErrorHandler(hvsRoutes.ResponseHandler(tagCertController.Search))).Methods("GET")
				req, err := http.NewRequest("GET", hvsRoutes.TagCertificateEndpointPath+"?id=13885605-a0ee-41f20000000000000000000000-b6fc-fd82edc487ad", nil)
				Expect(err).NotTo(HaveOccurred())
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusBadRequest))

				var tcCollection *hvs.TagCertificateCollection
				err = json.Unmarshal(w.Body.Bytes(), &tcCollection)
				Expect(err).To(HaveOccurred())
				Expect(tcCollection).To(BeNil())
			})
		})

		// HardwareUUID
		Context("When filtered by HardwareUUID id", func() {
			It("Should get a list of TagCertificate entries with the corresponding HardwareUUID and a 200 response code", func() {
				router.Handle(hvsRoutes.TagCertificateEndpointPath, hvsRoutes.ErrorHandler(hvsRoutes.ResponseHandler(tagCertController.Search))).Methods("GET")
				req, err := http.NewRequest("GET", hvsRoutes.TagCertificateEndpointPath+"?hardwareUuid=80ecce40-04b8-e811-906e-00163566263e", nil)
				Expect(err).NotTo(HaveOccurred())
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusOK))

				var tcCollection *hvs.TagCertificateCollection
				err = json.Unmarshal(w.Body.Bytes(), &tcCollection)
				Expect(err).NotTo(HaveOccurred())
				Expect(len(tcCollection.TagCertificates)).To(Equal(2))
			})
		})

		Context("When filtered by a non-existent HardwareUUID id", func() {
			It("Should get an empty list of TagCertificates and 200 response code", func() {
				router.Handle(hvsRoutes.TagCertificateEndpointPath, hvsRoutes.ErrorHandler(hvsRoutes.ResponseHandler(tagCertController.Search))).Methods("GET")
				req, err := http.NewRequest("GET", hvsRoutes.TagCertificateEndpointPath+"?hardwareUuid=b47a13b1-0af2-47d6-91d0-717094bfda2d", nil)
				Expect(err).NotTo(HaveOccurred())
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusOK))

				var tcCollection *hvs.TagCertificateCollection
				err = json.Unmarshal(w.Body.Bytes(), &tcCollection)
				Expect(err).NotTo(HaveOccurred())
				Expect(tcCollection.TagCertificates).To(BeNil())
			})
		})

		Context("When filtered by an invalid HardwareUUID id", func() {
			It("Should get an empty list of TagCertificates and a 400 response code", func() {
				router.Handle(hvsRoutes.TagCertificateEndpointPath, hvsRoutes.ErrorHandler(hvsRoutes.ResponseHandler(tagCertController.Search))).Methods("GET")
				req, err := http.NewRequest("GET", hvsRoutes.TagCertificateEndpointPath+"?hardwareUuid=13885605-a0ee-41f20000000000000000000000-b6fc-fd82edc487ad", nil)
				Expect(err).NotTo(HaveOccurred())
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusBadRequest))

				var tcCollection *hvs.TagCertificateCollection
				err = json.Unmarshal(w.Body.Bytes(), &tcCollection)
				Expect(err).To(HaveOccurred())
				Expect(tcCollection).To(BeNil())
			})
		})

		Context("When filtered by a valid SubjectEqualTo", func() {
			It("Should get a list of TagCertificates filtered by Subject=SubjectEqualTo and a 200 response code", func() {
				router.Handle(hvsRoutes.TagCertificateEndpointPath, hvsRoutes.ErrorHandler(hvsRoutes.ResponseHandler(tagCertController.Search))).Methods("GET")
				req, err := http.NewRequest("GET", hvsRoutes.TagCertificateEndpointPath+"?subjectEqualTo=00ecd3ab-9af4-e711-906e-001560a04062", nil)
				Expect(err).NotTo(HaveOccurred())
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusOK))

				var tcCollection *hvs.TagCertificateCollection
				err = json.Unmarshal(w.Body.Bytes(), &tcCollection)
				Expect(err).NotTo(HaveOccurred())
				Expect(len(tcCollection.TagCertificates)).To(Equal(2))
			})
		})

		Context("When filtered by a non-existent SubjectEqualTo", func() {
			It("Should get an empty list of TagCertificates and a 200 OK response Code", func() {
				router.Handle(hvsRoutes.TagCertificateEndpointPath, hvsRoutes.ErrorHandler(hvsRoutes.ResponseHandler(tagCertController.Search))).Methods("GET")
				req, err := http.NewRequest("GET", hvsRoutes.TagCertificateEndpointPath+"?subjectEqualTo=afc82547-0691-4be1-8b14-bcebfce86fd6", nil)
				Expect(err).NotTo(HaveOccurred())
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusOK))

				var tcCollection *hvs.TagCertificateCollection
				err = json.Unmarshal(w.Body.Bytes(), &tcCollection)
				Expect(err).NotTo(HaveOccurred())
				Expect(tcCollection.TagCertificates).To(BeNil())
			})
		})

		Context("When filtered by a valid SubjectContains", func() {
			It("Should get a list of TagCertificates that contains the SubjectContains parameter and a 200 OK response Code", func() {
				router.Handle(hvsRoutes.TagCertificateEndpointPath, hvsRoutes.ErrorHandler(hvsRoutes.ResponseHandler(tagCertController.Search))).Methods("GET")
				req, err := http.NewRequest("GET", hvsRoutes.TagCertificateEndpointPath+"?subjectContains=001560a04062", nil)
				Expect(err).NotTo(HaveOccurred())
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusOK))

				var tcCollection *hvs.TagCertificateCollection
				err = json.Unmarshal(w.Body.Bytes(), &tcCollection)
				Expect(err).NotTo(HaveOccurred())
				Expect(len(tcCollection.TagCertificates)).To(Equal(2))
			})
		})

		Context("When filtered by a non-existent SubjectEqualTo", func() {
			It("Should get an empty list of TagCertificates and a 200 response Code", func() {
				router.Handle(hvsRoutes.TagCertificateEndpointPath, hvsRoutes.ErrorHandler(hvsRoutes.ResponseHandler(tagCertController.Search))).Methods("GET")
				req, err := http.NewRequest("GET", hvsRoutes.TagCertificateEndpointPath+"?subjectContains=7a466a5beff9", nil)
				Expect(err).NotTo(HaveOccurred())
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusOK))

				var tcCollection *hvs.TagCertificateCollection
				err = json.Unmarshal(w.Body.Bytes(), &tcCollection)
				Expect(err).NotTo(HaveOccurred())
				Expect(tcCollection.TagCertificates).To(BeNil())
			})
		})

		Context("When filtered by a valid IssuerEqualTo", func() {
			It("Should get a list of TagCertificates filtered by Issuer=IssuerEqualTo and a 200 response code", func() {
				router.Handle(hvsRoutes.TagCertificateEndpointPath, hvsRoutes.ErrorHandler(hvsRoutes.ResponseHandler(tagCertController.Search))).Methods("GET")
				req, err := http.NewRequest("GET", hvsRoutes.TagCertificateEndpointPath+"?issuerEqualTo=CN=asset-tag-service", nil)
				Expect(err).NotTo(HaveOccurred())
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusOK))

				var tcCollection *hvs.TagCertificateCollection
				err = json.Unmarshal(w.Body.Bytes(), &tcCollection)
				Expect(err).NotTo(HaveOccurred())
				Expect(len(tcCollection.TagCertificates) > 0).To(BeTrue())
			})
		})

		Context("When filtered by a non-existent IssuerEqualTo", func() {
			It("Should get an empty list of TagCertificates and a 200 response code", func() {
				router.Handle(hvsRoutes.TagCertificateEndpointPath, hvsRoutes.ErrorHandler(hvsRoutes.ResponseHandler(tagCertController.Search))).Methods("GET")
				req, err := http.NewRequest("GET", hvsRoutes.TagCertificateEndpointPath+"?issuerEqualTo=CN=nonexistent-tag-service", nil)
				Expect(err).NotTo(HaveOccurred())
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusOK))

				var tcCollection *hvs.TagCertificateCollection
				err = json.Unmarshal(w.Body.Bytes(), &tcCollection)
				Expect(err).NotTo(HaveOccurred())
				Expect(tcCollection.TagCertificates).To(BeNil())
			})
		})

		Context("When filtered by a valid IssuerContains", func() {
			It("Should get a list of TagCertificates that contains the IssuerContains parameter and a 200 response Code", func() {
				router.Handle(hvsRoutes.TagCertificateEndpointPath, hvsRoutes.ErrorHandler(hvsRoutes.ResponseHandler(tagCertController.Search))).Methods("GET")
				req, err := http.NewRequest("GET", hvsRoutes.TagCertificateEndpointPath+"?issuerContains=asset-tag", nil)
				Expect(err).NotTo(HaveOccurred())
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusOK))

				var tcCollection *hvs.TagCertificateCollection
				err = json.Unmarshal(w.Body.Bytes(), &tcCollection)
				Expect(err).NotTo(HaveOccurred())
				Expect(len(tcCollection.TagCertificates) > 0).To(BeTrue())
			})
		})

		Context("When filtered by a non-existent IssuerContains", func() {
			It("Should get an empty list of TagCertificates and a 200 response code", func() {
				router.Handle(hvsRoutes.TagCertificateEndpointPath, hvsRoutes.ErrorHandler(hvsRoutes.ResponseHandler(tagCertController.Search))).Methods("GET")
				req, err := http.NewRequest("GET", hvsRoutes.TagCertificateEndpointPath+"?issuerContains=nonexistent-tag-service", nil)
				Expect(err).NotTo(HaveOccurred())
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusOK))

				var tcCollection *hvs.TagCertificateCollection
				err = json.Unmarshal(w.Body.Bytes(), &tcCollection)
				Expect(err).NotTo(HaveOccurred())
				Expect(tcCollection.TagCertificates).To(BeNil())
			})
		})

		Context("Search TagCertificates from data store with valid ValidOn date", func() {
			It("Should return a list of TagCertificates valid on the ValidOn date and a 200 response code", func() {
				router.Handle(hvsRoutes.TagCertificateEndpointPath, hvsRoutes.ErrorHandler(hvsRoutes.ResponseHandler(tagCertController.Search))).Methods("GET")
				req, err := http.NewRequest("GET", hvsRoutes.TagCertificateEndpointPath+"?validOn="+time.Now().Add(-mocks2.TimeDuration12Hrs).Format(constants.HVSParamDateFormat), nil)
				Expect(err).ToNot(HaveOccurred())
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusOK))

				var tcCollection *hvs.TagCertificateCollection
				err = json.Unmarshal(w.Body.Bytes(), &tcCollection)
				Expect(err).ToNot(HaveOccurred())
				Expect(tcCollection).ToNot(BeNil())
			})
		})

		Context("Search TagCertificates from data store with valid ValidBefore date", func() {
			It("Should return a list of TagCertificates which are valid before the ValidBefore date and a 200 response code", func() {
				router.Handle(hvsRoutes.TagCertificateEndpointPath, hvsRoutes.ErrorHandler(hvsRoutes.ResponseHandler(tagCertController.Search))).Methods("GET")
				req, err := http.NewRequest("GET", hvsRoutes.TagCertificateEndpointPath+"?validBefore="+time.Now().AddDate(1, -6, 0).Format(constants.HVSParamDateFormat), nil)
				Expect(err).ToNot(HaveOccurred())
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusOK))

				var tcCollection *hvs.TagCertificateCollection
				err = json.Unmarshal(w.Body.Bytes(), &tcCollection)
				Expect(err).ToNot(HaveOccurred())
				Expect(tcCollection).ToNot(BeNil())
			})
		})

		Context("Search TagCertificates from data store with valid ValidAfter", func() {
			It("Should return a list of TagCertificates which are valid after the ValidAfter date and a 200 response code", func() {
				router.Handle(hvsRoutes.TagCertificateEndpointPath, hvsRoutes.ErrorHandler(hvsRoutes.ResponseHandler(tagCertController.Search))).Methods("GET")
				req, err := http.NewRequest("GET", hvsRoutes.TagCertificateEndpointPath+"?validAfter="+time.Now().AddDate(0, -6, 0).Format(constants.HVSParamDateFormat), nil)
				Expect(err).ToNot(HaveOccurred())
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusOK))

				var tcCollection *hvs.TagCertificateCollection
				err = json.Unmarshal(w.Body.Bytes(), &tcCollection)
				Expect(err).ToNot(HaveOccurred())
				Expect(tcCollection).ToNot(BeNil())
			})
		})

		Context("Search TagCertificates from data store with invalid ValidOn date", func() {
			It("Should get an empty list of TagCertificates and a 400 response code", func() {
				router.Handle(hvsRoutes.TagCertificateEndpointPath, hvsRoutes.ErrorHandler(hvsRoutes.ResponseHandler(tagCertController.Search))).Methods("GET")
				req, err := http.NewRequest("GET", hvsRoutes.TagCertificateEndpointPath+"?validOn="+time.Now().Add(-mocks2.TimeDuration12Hrs).Format(constants.HVSParamDateFormat)+"0000000000000", nil)
				Expect(err).ToNot(HaveOccurred())
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusBadRequest))

				var tcCollection *hvs.TagCertificateCollection
				err = json.Unmarshal(w.Body.Bytes(), &tcCollection)
				Expect(err).To(HaveOccurred())
				Expect(tcCollection).To(BeNil())
			})
		})

		Context("Search TagCertificates from data store with invalid ValidBefore date", func() {
			It("Should get an empty list of TagCertificates and a 400 response code", func() {
				router.Handle(hvsRoutes.TagCertificateEndpointPath, hvsRoutes.ErrorHandler(hvsRoutes.ResponseHandler(tagCertController.Search))).Methods("GET")
				req, err := http.NewRequest("GET", hvsRoutes.TagCertificateEndpointPath+"?validBefore="+time.Now().Add(-mocks2.TimeDuration12Hrs).Format(constants.HVSParamDateFormat)+"01010101010", nil)
				Expect(err).ToNot(HaveOccurred())
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusBadRequest))

				var tcCollection *hvs.TagCertificateCollection
				err = json.Unmarshal(w.Body.Bytes(), &tcCollection)
				Expect(err).To(HaveOccurred())
				Expect(tcCollection).To(BeNil())
			})
		})

		Context("Search TagCertificates from data store with invalid ValidAfter date", func() {
			It("Should get an empty list of TagCertificates and a 400 response code", func() {
				router.Handle(hvsRoutes.TagCertificateEndpointPath, hvsRoutes.ErrorHandler(hvsRoutes.ResponseHandler(tagCertController.Search))).Methods("GET")
				req, err := http.NewRequest("GET", hvsRoutes.TagCertificateEndpointPath+"?validAfter="+time.Now().Add(-mocks2.TimeDuration12Hrs).Format(constants.HVSParamDateFormat)+"ABC", nil)
				Expect(err).ToNot(HaveOccurred())
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusBadRequest))

				var tcCollection *hvs.TagCertificateCollection
				err = json.Unmarshal(w.Body.Bytes(), &tcCollection)
				Expect(err).To(HaveOccurred())
				Expect(tcCollection).To(BeNil())
			})
		})

	})

	// Specs for HTTP DELETE to "/tag-certificates/{tagcertificate_id}"
	Describe("Delete TagCertificate by ID", func() {
		Context("Delete TagCertificate by ID from data store", func() {
			It("Should delete TagCertificate and return a 200 response code", func() {
				router.Handle(hvsRoutes.TagCertificateEndpointPath+"/{id}", hvsRoutes.ErrorHandler(hvsRoutes.ResponseHandler(tagCertController.Delete))).Methods("DELETE")
				req, err := http.NewRequest("DELETE", hvsRoutes.TagCertificateEndpointPath+"/fda6105d-a340-42da-bc35-0555e7a5e360", nil)
				Expect(err).NotTo(HaveOccurred())
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusNoContent))
			})
		})
		Context("Delete TagCertificate by incorrect ID from data store", func() {
			It("Should fail to delete TagCertificate and return a 404 response code", func() {
				router.Handle(hvsRoutes.TagCertificateEndpointPath+"/{id}", hvsRoutes.ErrorHandler(hvsRoutes.ResponseHandler(tagCertController.Delete))).Methods("DELETE")
				req, err := http.NewRequest("DELETE", hvsRoutes.TagCertificateEndpointPath+"/c00135a8-f5e9-4860-ae6c-4acce525d340", nil)
				Expect(err).NotTo(HaveOccurred())
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusNotFound))
			})
		})
		Context("Delete TagCertificate by invalid ID from data store", func() {
			It("Should fail to delete TagCertificate and return a 400 response code", func() {
				router.Handle(hvsRoutes.TagCertificateEndpointPath+"/{id}", hvsRoutes.ErrorHandler(hvsRoutes.ResponseHandler(tagCertController.Delete))).Methods("DELETE")
				req, err := http.NewRequest("DELETE", hvsRoutes.TagCertificateEndpointPath+"/73755fda-c910-46be-821f-xyxyz", nil)
				Expect(err).ToNot(HaveOccurred())
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusNotFound))
			})
		})
	})
})
