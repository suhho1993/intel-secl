/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package controllers_test

import (
	"bytes"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"

	"github.com/intel-secl/intel-secl/v3/pkg/hvs/controllers"
	hvsRoutes "github.com/intel-secl/intel-secl/v3/pkg/hvs/router"
	"github.com/intel-secl/intel-secl/v3/pkg/lib/common/crypt"
	"github.com/intel-secl/intel-secl/v3/pkg/lib/privacyca"
	taModel "github.com/intel-secl/intel-secl/v3/pkg/model/ta"

	"github.com/gorilla/mux"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("CertifyHostAiksController", func() {
	var router *mux.Router
	var w *httptest.ResponseRecorder
	var pCAFileStore *controllers.PrivacyCAFileStore
	var certifyHostAiksController *controllers.CertifyHostAiksController
	var cacert *x509.Certificate
	eCAPath = "../domain/mocks/resources/EndorsementCA-external.pem"
	caCertPath = "../domain/mocks/privacyca-cert.pem"
	caKeyPath = "../domain/mocks/privacycaKey.pem"
	aikRequestsDir = "../domain/mocks/resources/aik/"

	BeforeEach(func() {
		router = mux.NewRouter()
		cacert, _ = crypt.GetCertFromPemFile(caCertPath)
	})

	Describe("Create Identity Proof request", func() {
		Context("Provide valid data in request", func() {
			It("Return Identity Proof request", func() {
				pCAFileStore = controllers.NewPrivacyCAFileStore(caKeyPath, caCertPath, eCAPath, aikRequestsDir)
				certifyHostAiksController = &controllers.CertifyHostAiksController{PcaStore: pCAFileStore}
				router.Handle("/privacyca/identity-challenge-request", hvsRoutes.ErrorHandler(hvsRoutes.ResponseHandler(certifyHostAiksController.IdentityRequestGetChallenge))).Methods("POST")

				// Mock TA Flow for generating data for identityChallengeRequest
				identityRequestBlock, _ := base64.StdEncoding.DecodeString("musrA8GOcUtcD3phno/e4XseAdzLG/Ff1qXBIZ/GWdQUKTvOQlUq5P+BJLD1ifp7bpyvXdpesnHZuhXpi4AM8D2uJYTs4MeamMJ2LKAu/zSk9IDz4Z4gnQACSGSWzqafXv8OAh6D7/EOjzUh/sjkZdTVjsKzyHGp7GbY+G+mt9/PdF1e4/TJlp41s6rQ6BAJ0mA4gNdkrJLW2iedM1MZJn2JgYWDtxej5wD6Gm7/BGD+Rn9wqyU4U6fjEsNqeXj0E0DtkreMAi9cAQuoagckvh/ru1o8psyzTM+Bk+EqpFrfg3nz4nDC+Nrz+IBjuJuFGNUUFbxC6FrdtX4c2jnQIQ==")
				aikModulus, _ := base64.StdEncoding.DecodeString("musrA8GOcUtcD3phno/e4XseAdzLG/Ff1qXBIZ/GWdQUKTvOQlUq5P+BJLD1ifp7bpyvXdpesnHZuhXpi4AM8D2uJYTs4MeamMJ2LKAu/zSk9IDz4Z4gnQACSGSWzqafXv8OAh6D7/EOjzUh/sjkZdTVjsKzyHGp7GbY+G+mt9/PdF1e4/TJlp41s6rQ6BAJ0mA4gNdkrJLW2iedM1MZJn2JgYWDtxej5wD6Gm7/BGD+Rn9wqyU4U6fjEsNqeXj0E0DtkreMAi9cAQuoagckvh/ru1o8psyzTM+Bk+EqpFrfg3nz4nDC+Nrz+IBjuJuFGNUUFbxC6FrdtX4c2jnQIQ==")
				aikBlob, _ := base64.StdEncoding.DecodeString("gQGAAA==")
				aikName, _ := base64.StdEncoding.DecodeString("AAuTbAaKYOG2opc4QXq0QzsUHFRMsV0m5lcmRK4SLrzdRA==")
				identityReq := taModel.IdentityRequest{
					TpmVersion:           "2.0",
					IdentityRequestBlock: identityRequestBlock,
					AikModulus:           aikModulus,
					AikBlob:              aikBlob,
					AikName:              aikName,
				}

				privacycaTpm2, err := privacyca.NewPrivacyCA(identityReq)
				Expect(err).NotTo(HaveOccurred())
				identityChallengeRequest := taModel.IdentityChallengePayload{}
				identityChallengeRequest.IdentityRequest = identityReq
				ekCertBytes, _ := base64.StdEncoding.DecodeString("MIIEnDCCA4SgAwIBAgIEKqkMMTANBgkqhkiG9w0BAQsFADCBgzELMAkGA1UEBhMCREUxITAfBgNVBAoMGEluZmluZW9uIFRlY2hub2xvZ2llcyBBRzEaMBgGA1UECwwRT1BUSUdBKFRNKSBUUE0yLjAxNTAzBgNVBAMMLEluZmluZW9uIE9QVElHQShUTSkgUlNBIE1hbnVmYWN0dXJpbmcgQ0EgMDA3MB4XDTE1MTIyMjEzMDY0NFoXDTMwMTIyMjEzMDY0NFowADCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAJGeto1E37hKCFGcDY7KV6o3eYKGdpRGtCCQutI3XdeOROfI3IVAC647apI7b75+7q8XrBqV9oHYLKHcM/xKw4m48/c8W3qRwQlrmXKfxgmeuKEbGceVqI2vrMHio4GhDRb+ppeIDN8nDOEN8w7Td+iOSL5QBNseLCtS8E2fKSviH3YLNeZZG/JSFYpB4R7iV/FaG/KX2FIR/qChg7Esr+BL++52ByD85gmvY4f6ffWEtSirqYAnhnC4blU3bwl1dnbtFTWIFFUgRQB/RAlZ13TcapqvR6PNlNKfXvPK8imINFaUcHG3aEMwWEPV6+01ZM3h5QsLcg7P75gurmT5S08CAwEAAaOCAZgwggGUMFsGCCsGAQUFBwEBBE8wTTBLBggrBgEFBQcwAoY/aHR0cDovL3BraS5pbmZpbmVvbi5jb20vT3B0aWdhUnNhTWZyQ0EwMDcvT3B0aWdhUnNhTWZyQ0EwMDcuY3J0MA4GA1UdDwEB/wQEAwIAIDBYBgNVHREBAf8ETjBMpEowSDEWMBQGBWeBBQIBDAtpZDo0OTQ2NTgwMDEaMBgGBWeBBQICDA9TTEIgOTY3MCBUUE0yLjAxEjAQBgVngQUCAwwHaWQ6MDcyODAMBgNVHRMBAf8EAjAAMFAGA1UdHwRJMEcwRaBDoEGGP2h0dHA6Ly9wa2kuaW5maW5lb24uY29tL09wdGlnYVJzYU1mckNBMDA3L09wdGlnYVJzYU1mckNBMDA3LmNybDAVBgNVHSAEDjAMMAoGCCqCFABEARQBMB8GA1UdIwQYMBaAFJx99akcPUm75zeNSroS/454otdcMBAGA1UdJQQJMAcGBWeBBQgBMCEGA1UdCQQaMBgwFgYFZ4EFAhAxDTALDAMyLjACAQACAXQwDQYJKoZIhvcNAQELBQADggEBAATaII6W4g9Y10nwgaH76NxORIg9EdO9NzoDpjW+9F/8duFM+6N0Qu//yB6qpR7ZyKYBOdF5eJLsWFYpj2akRZhKuixH6xjR3XGapvimW5pTQ055+xeF5aS/s93Wa/lJVM1JzGsZk+vbqMwNlI12sX6wcaStIMkuAyKGrRdtafS8woEKBb41bTd7Y8Btb4k7gMDoMU1ekqZSNpT/fR5Ff1ob/Sgu8lwEChnFjWF22OjPle++npUyRNo/4aa6EC7+hBVitCiqA9EIPB+Dr8UJ5ZLgObpkLOmTKnlBa9HL6fpnu7EBhB/PomLSoHthZTjdql97MrPQ+XX7OFrMdUZdzO0=")
				// Get the Identity challenge request
				identityChallengeRequest, err = privacycaTpm2.GetIdentityChallengeRequest(ekCertBytes, cacert.PublicKey.(*rsa.PublicKey), identityChallengeRequest.IdentityRequest)
				Expect(err).NotTo(HaveOccurred())
				jsonData, _ := json.Marshal(identityChallengeRequest)

				req, err := http.NewRequest(
					"POST",
					"/privacyca/identity-challenge-request",
					bytes.NewBuffer(jsonData),
				)
				Expect(err).NotTo(HaveOccurred())
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(200))
			})
		})

		Context("Provide invalid ekcert in request", func() {
			It("Should get HTTP Status: 400", func() {
				pCAFileStore = controllers.NewPrivacyCAFileStore(caKeyPath, caCertPath, eCAPath, aikRequestsDir)
				certifyHostAiksController = &controllers.CertifyHostAiksController{PcaStore: pCAFileStore}
				router.Handle("/privacyca/identity-challenge-request", hvsRoutes.ErrorHandler(hvsRoutes.ResponseHandler(certifyHostAiksController.IdentityRequestGetChallenge))).Methods("POST")

				//// Mock TA Flow for generating data for identityChallengeRequest
				identityRequestBlock, _ := base64.StdEncoding.DecodeString("musrA8GOcUtcD3phno/e4XseAdzLG/Ff1qXBIZ/GWdQUKTvOQlUq5P+BJLD1ifp7bpyvXdpesnHZuhXpi4AM8D2uJYTs4MeamMJ2LKAu/zSk9IDz4Z4gnQACSGSWzqafXv8OAh6D7/EOjzUh/sjkZdTVjsKzyHGp7GbY+G+mt9/PdF1e4/TJlp41s6rQ6BAJ0mA4gNdkrJLW2iedM1MZJn2JgYWDtxej5wD6Gm7/BGD+Rn9wqyU4U6fjEsNqeXj0E0DtkreMAi9cAQuoagckvh/ru1o8psyzTM+Bk+EqpFrfg3nz4nDC+Nrz+IBjuJuFGNUUFbxC6FrdtX4c2jnQIQ==")
				aikModulus, _ := base64.StdEncoding.DecodeString("musrA8GOcUtcD3phno/e4XseAdzLG/Ff1qXBIZ/GWdQUKTvOQlUq5P+BJLD1ifp7bpyvXdpesnHZuhXpi4AM8D2uJYTs4MeamMJ2LKAu/zSk9IDz4Z4gnQACSGSWzqafXv8OAh6D7/EOjzUh/sjkZdTVjsKzyHGp7GbY+G+mt9/PdF1e4/TJlp41s6rQ6BAJ0mA4gNdkrJLW2iedM1MZJn2JgYWDtxej5wD6Gm7/BGD+Rn9wqyU4U6fjEsNqeXj0E0DtkreMAi9cAQuoagckvh/ru1o8psyzTM+Bk+EqpFrfg3nz4nDC+Nrz+IBjuJuFGNUUFbxC6FrdtX4c2jnQIQ==")
				aikBlob, _ := base64.StdEncoding.DecodeString("gQfererGAAA==")
				aikName, _ := base64.StdEncoding.DecodeString("afefAAuTbAaKYOG2opc4QXq0QzsUHFRMsV0m5lcmRK4SLrzdRffdfA==")
				identityReq := taModel.IdentityRequest{
					TpmVersion:           "2.0",
					IdentityRequestBlock: identityRequestBlock,
					AikModulus:           aikModulus,
					AikBlob:              aikBlob,
					AikName:              aikName,
				}

				privacycaTpm2, err := privacyca.NewPrivacyCA(identityReq)
				Expect(err).NotTo(HaveOccurred())
				identityChallengeRequest := taModel.IdentityChallengePayload{}
				identityChallengeRequest.IdentityRequest = identityReq
				ekCertBytes, err := base64.StdEncoding.DecodeString("MCDEnDCCA4SgAwIBAgIEKqkMMTANBgkqhkiG9w0BAQsFADCBgzELMAkGA1UEBhMCREUxITAfBgNVBAoMGEluZmluZW9uIFRlY2hub2xvZ2llcyBBRzEaMBgGA1UECwwRT1BUSUdBKFRNKSBUUE0yLjAxNTAzBgNVBAMMLEluZmluZW9uIE9QVElHQShUTSkgUlNBIE1hbnVmYWN0dXJpbmcgQ0EgMDA3MB4XDTE1MTIyMjEzMDY0NFoXDTMwMTIyMjEzMDY0NFowADCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAJGeto1E37hKCFGcDY7KV6o3eYKGdpRGtCCQutI3XdeOROfI3IVAC647apI7b75+7q8XrBqV9oHYLKHcM/xKw4m48/c8W3qRwQlrmXKfxgmeuKEbGceVqI2vrMHio4GhDRb+ppeIDN8nDOEN8w7Td+iOSL5QBNseLCtS8E2fKSviH3YLNeZZG/JSFYpB4R7iV/FaG/KX2FIR/qChg7Esr+BL++52ByD85gmvY4f6ffWEtSirqYAnhnC4blU3bwl1dnbtFTWIFFUgRQB/RAlZ13TcapqvR6PNlNKfXvPK8imINFaUcHG3aEMwWEPV6+01ZM3h5QsLcg7P75gurmT5S08CAwEAAaOCAZgwggGUMFsGCCsGAQUFBwEBBE8wTTBLBggrBgEFBQcwAoY/aHR0cDovL3BraS5pbmZpbmVvbi5jb20vT3B0aWdhUnNhTWZyQ0EwMDcvT3B0aWdhUnNhTWZyQ0EwMDcuY3J0MA4GA1UdDwEB/wQEAwIAIDBYBgNVHREBAf8ETjBMpEowSDEWMBQGBWeBBQIBDAtpZDo0OTQ2NTgwMDEaMBgGBWeBBQICDA9TTEIgOTY3MCBUUE0yLjAxEjAQBgVngQUCAwwHaWQ6MDcyODAMBgNVHRMBAf8EAjAAMFAGA1UdHwRJMEcwRaBDoEGGP2h0dHA6Ly9wa2kuaW5maW5lb24uY29tL09wdGlnYVJzYU1mckNBMDA3L09wdGlnYVJzYU1mckNBMDA3LmNybDAVBgNVHSAEDjAMMAoGCCqCFABEARQBMB8GA1UdIwQYMBaAFJx99akcPUm75zeNSroS/454otdcMBAGA1UdJQQJMAcGBWeBBQgBMCEGA1UdCQQaMBgwFgYFZ4EFAhAxDTALDAMyLjACAQACAXQwDQYJKoZIhvcNAQELBQADggEBAATaII6W4g9Y10nwgaH76NxORIg9EdO9NzoDpjW+9F/8duFM+6N0Qu//yB6qpR7ZyKYBOdF5eJLsWFYpj2akRZhKuixH6xjR3XGapvimW5pTQ055+xeF5aS/s93Wa/lJVM1JzGsZk+vbqMwNlI12sX6wcaStIMkuAyKGrRdtafS8woEKBb41bTd7Y8Btb4k7gMDoMU1ekqZSNpT/fR5Ff1ob/Sgu8lwEChnFjWF22OjPle++npUyRNo/4aa6EC7+hBVitCiqA9EIPB+Dr8UJ5ZLgObpkLOmTKnlBa9HL6fpnu7EBhB/PomLSoHthZTjdql97MrPQ+XX7OFrMdUZdzO0=")
				Expect(err).NotTo(HaveOccurred())
				// Get the Identity challenge request
				identityChallengeRequest, _ = privacycaTpm2.GetIdentityChallengeRequest(ekCertBytes, cacert.PublicKey.(*rsa.PublicKey), identityChallengeRequest.IdentityRequest)
				jsonData, err := json.Marshal(identityChallengeRequest)

				req, err := http.NewRequest(
					"POST",
					"/privacyca/identity-challenge-request",
					bytes.NewBuffer(jsonData),
				)
				Expect(err).NotTo(HaveOccurred())
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(400))
			})
		})
	})

	Describe("Create Identity Proof request response", func() {
		Context("Provide valid data in request", func() {
			It("Return Identity Proof request response", func() {
				pCAFileStore = controllers.NewPrivacyCAFileStore(caKeyPath, caCertPath, eCAPath, aikRequestsDir)
				certifyHostAiksController = &controllers.CertifyHostAiksController{PcaStore: pCAFileStore}
				router.Handle("/privacyca/identity-challenge-response", hvsRoutes.ErrorHandler(hvsRoutes.ResponseHandler(certifyHostAiksController.IdentityRequestSubmitChallengeResponse))).Methods("POST")

				// Mock TA Flow for generating data for identityChallengeRequestReponse
				identityRequestBlock, _ := base64.StdEncoding.DecodeString("musrA8GOcUtcD3phno/e4XseAdzLG/Ff1qXBIZ/GWdQUKTvOQlUq5P+BJLD1ifp7bpyvXdpesnHZuhXpi4AM8D2uJYTs4MeamMJ2LKAu/zSk9IDz4Z4gnQACSGSWzqafXv8OAh6D7/EOjzUh/sjkZdTVjsKzyHGp7GbY+G+mt9/PdF1e4/TJlp41s6rQ6BAJ0mA4gNdkrJLW2iedM1MZJn2JgYWDtxej5wD6Gm7/BGD+Rn9wqyU4U6fjEsNqeXj0E0DtkreMAi9cAQuoagckvh/ru1o8psyzTM+Bk+EqpFrfg3nz4nDC+Nrz+IBjuJuFGNUUFbxC6FrdtX4c2jnQIQ==")
				aikModulus, _ := base64.StdEncoding.DecodeString("musrA8GOcUtcD3phno/e4XseAdzLG/Ff1qXBIZ/GWdQUKTvOQlUq5P+BJLD1ifp7bpyvXdpesnHZuhXpi4AM8D2uJYTs4MeamMJ2LKAu/zSk9IDz4Z4gnQACSGSWzqafXv8OAh6D7/EOjzUh/sjkZdTVjsKzyHGp7GbY+G+mt9/PdF1e4/TJlp41s6rQ6BAJ0mA4gNdkrJLW2iedM1MZJn2JgYWDtxej5wD6Gm7/BGD+Rn9wqyU4U6fjEsNqeXj0E0DtkreMAi9cAQuoagckvh/ru1o8psyzTM+Bk+EqpFrfg3nz4nDC+Nrz+IBjuJuFGNUUFbxC6FrdtX4c2jnQIQ==")
				aikBlob, _ := base64.StdEncoding.DecodeString("gQGAAA==")
				aikName, _ := base64.StdEncoding.DecodeString("AAuTbAaKYOG2opc4QXq0QzsUHFRMsV0m5lcmRK4SLrzdRA==")
				identityReq := taModel.IdentityRequest{
					TpmVersion:           "2.0",
					IdentityRequestBlock: identityRequestBlock,
					AikModulus:           aikModulus,
					AikBlob:              aikBlob,
					AikName:              aikName,
				}

				ekCertBytes, _ := base64.StdEncoding.DecodeString("MIIEnDCCA4SgAwIBAgIEKqkMMTANBgkqhkiG9w0BAQsFADCBgzELMAkGA1UEBhMCREUxITAfBgNVBAoMGEluZmluZW9uIFRlY2hub2xvZ2llcyBBRzEaMBgGA1UECwwRT1BUSUdBKFRNKSBUUE0yLjAxNTAzBgNVBAMMLEluZmluZW9uIE9QVElHQShUTSkgUlNBIE1hbnVmYWN0dXJpbmcgQ0EgMDA3MB4XDTE1MTIyMjEzMDY0NFoXDTMwMTIyMjEzMDY0NFowADCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAJGeto1E37hKCFGcDY7KV6o3eYKGdpRGtCCQutI3XdeOROfI3IVAC647apI7b75+7q8XrBqV9oHYLKHcM/xKw4m48/c8W3qRwQlrmXKfxgmeuKEbGceVqI2vrMHio4GhDRb+ppeIDN8nDOEN8w7Td+iOSL5QBNseLCtS8E2fKSviH3YLNeZZG/JSFYpB4R7iV/FaG/KX2FIR/qChg7Esr+BL++52ByD85gmvY4f6ffWEtSirqYAnhnC4blU3bwl1dnbtFTWIFFUgRQB/RAlZ13TcapqvR6PNlNKfXvPK8imINFaUcHG3aEMwWEPV6+01ZM3h5QsLcg7P75gurmT5S08CAwEAAaOCAZgwggGUMFsGCCsGAQUFBwEBBE8wTTBLBggrBgEFBQcwAoY/aHR0cDovL3BraS5pbmZpbmVvbi5jb20vT3B0aWdhUnNhTWZyQ0EwMDcvT3B0aWdhUnNhTWZyQ0EwMDcuY3J0MA4GA1UdDwEB/wQEAwIAIDBYBgNVHREBAf8ETjBMpEowSDEWMBQGBWeBBQIBDAtpZDo0OTQ2NTgwMDEaMBgGBWeBBQICDA9TTEIgOTY3MCBUUE0yLjAxEjAQBgVngQUCAwwHaWQ6MDcyODAMBgNVHRMBAf8EAjAAMFAGA1UdHwRJMEcwRaBDoEGGP2h0dHA6Ly9wa2kuaW5maW5lb24uY29tL09wdGlnYVJzYU1mckNBMDA3L09wdGlnYVJzYU1mckNBMDA3LmNybDAVBgNVHSAEDjAMMAoGCCqCFABEARQBMB8GA1UdIwQYMBaAFJx99akcPUm75zeNSroS/454otdcMBAGA1UdJQQJMAcGBWeBBQgBMCEGA1UdCQQaMBgwFgYFZ4EFAhAxDTALDAMyLjACAQACAXQwDQYJKoZIhvcNAQELBQADggEBAATaII6W4g9Y10nwgaH76NxORIg9EdO9NzoDpjW+9F/8duFM+6N0Qu//yB6qpR7ZyKYBOdF5eJLsWFYpj2akRZhKuixH6xjR3XGapvimW5pTQ055+xeF5aS/s93Wa/lJVM1JzGsZk+vbqMwNlI12sX6wcaStIMkuAyKGrRdtafS8woEKBb41bTd7Y8Btb4k7gMDoMU1ekqZSNpT/fR5Ff1ob/Sgu8lwEChnFjWF22OjPle++npUyRNo/4aa6EC7+hBVitCiqA9EIPB+Dr8UJ5ZLgObpkLOmTKnlBa9HL6fpnu7EBhB/PomLSoHthZTjdql97MrPQ+XX7OFrMdUZdzO0=")
				identityRequestChallenge, _ := crypt.GetRandomBytes(32)

				privacycaTpm2, err := privacyca.NewPrivacyCA(identityReq)
				Expect(err).NotTo(HaveOccurred())
				identityChallengeRequest := taModel.IdentityChallengePayload{}
				identityChallengeRequest.IdentityRequest = identityReq
				identityChallengeRequest, err = privacycaTpm2.GetIdentityChallengeRequest(identityRequestChallenge, cacert.PublicKey.(*rsa.PublicKey), identityChallengeRequest.IdentityRequest)
				Expect(err).NotTo(HaveOccurred())
				// This step is usually performed by HVS for verifying identityRequestChallenge that gets created during
				// TA on requesting /rpc/identity-request-challenge api for given ekcert
				certifyHostAiksController.StoreEkCerts(identityRequestChallenge, ekCertBytes, identityChallengeRequest)
				jsonData, err := json.Marshal(identityChallengeRequest)

				req, err := http.NewRequest(
					"POST",
					"/privacyca/identity-challenge-response",
					bytes.NewBuffer(jsonData),
				)
				Expect(err).NotTo(HaveOccurred())
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(200))
			})
		})

		Context("Provide invalid ekcert in request", func() {
			It("Should get HTTP Status: 400", func() {
				pCAFileStore = controllers.NewPrivacyCAFileStore(caKeyPath, caCertPath, eCAPath, aikRequestsDir)
				certifyHostAiksController = &controllers.CertifyHostAiksController{PcaStore: pCAFileStore}
				router.Handle("/privacyca/identity-challenge-response", hvsRoutes.ErrorHandler(hvsRoutes.ResponseHandler(certifyHostAiksController.IdentityRequestSubmitChallengeResponse))).Methods("POST")

				// Mock TA Flow for generating data for identityChallengeRequestReponse
				identityRequestBlock, _ := base64.StdEncoding.DecodeString("musrA8GOcUtcD3phno/e4XseAdzLG/Ff1qXBIZ/GWdQUKTvOQlUq5P+BJLD1ifp7bpyvXdpesnHZuhXpi4AM8D2uJYTs4MeamMJ2LKAu/zSk9IDz4Z4gnQACSGSWzqafXv8OAh6D7/EOjzUh/sjkZdTVjsKzyHGp7GbY+G+mt9/PdF1e4/TJlp41s6rQ6BAJ0mA4gNdkrJLW2iedM1MZJn2JgYWDtxej5wD6Gm7/BGD+Rn9wqyU4U6fjEsNqeXj0E0DtkreMAi9cAQuoagckvh/ru1o8psyzTM+Bk+EqpFrfg3nz4nDC+Nrz+IBjuJuFGNUUFbxC6FrdtX4c2jnQIQ==")
				aikModulus, _ := base64.StdEncoding.DecodeString("musrA8GOcUtcD3phno/Ff1qXBIZ/GWdQUKTvOQlUq5P+BJLD1ifp7bpyvXdpesnHZuhXpi4AM8D2uJYTs4MeamMJ2LKAu/zSk9IDz4Z4gnQACSGSWzqafXv8OAh6D7/EOjzUh/sjkZdTVjsKzyHGp7GbY+G+mt9/PdF1e4/TJlp41s6rQ6BAJ0mA4gNdkrJLW2iedM1MZJn2JgYWDtxej5wD6Gm7/BGD+Rn9wqyU4U6fjEsNqeXj0E0DtkreMAi9cAQuoagckvh/ru1o8psyzTM+Bk+EqpFrfg3nz4nDC+Nrz+IBjuJuFGNUUFbxC6FrdtX4c2jnQIQ==")
				aikBlob, _ := base64.StdEncoding.DecodeString("agQGAAA==")
				aikName, _ := base64.StdEncoding.DecodeString("AAuTbAaKYOG2opc4QXq")
				identityReq := taModel.IdentityRequest{
					TpmVersion:           "2.0",
					IdentityRequestBlock: identityRequestBlock,
					AikModulus:           aikModulus,
					AikBlob:              aikBlob,
					AikName:              aikName,
				}

				ekCertBytes, _ := base64.StdEncoding.DecodeString("MDCEnDCCA4SgAwIBAgIEKqkMMTANBgkqhkiG9w0BAQsFADCBgzELMAkGA1UEBhMCREUxITAfBgNVBAoMGEluZmluZW9uIFRlY2hub2xvZ2llcyBBRzEaMBgGA1UECwwRT1BUSUdBKFRNKSBUUE0yLjAxNTAzBgNVBAMMLEluZmluZW9uIE9QVElHQShUTSkgUlNBIE1hbnVmYWN0dXJpbmcgQ0EgMDA3MB4XDTE1MTIyMjEzMDY0NFoXDTMwMTIyMjEzMDY0NFowADCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAJGeto1E37hKCFGcDY7KV6o3eYKGdpRGtCCQutI3XdeOROfI3IVAC647apI7b75+7q8XrBqV9oHYLKHcM/xKw4m48/c8W3qRwQlrmXKfxgmeuKEbGceVqI2vrMHio4GhDRb+ppeIDN8nDOEN8w7Td+iOSL5QBNseLCtS8E2fKSviH3YLNeZZG/JSFYpB4R7iV/FaG/KX2FIR/qChg7Esr+BL++52ByD85gmvY4f6ffWEtSirqYAnhnC4blU3bwl1dnbtFTWIFFUgRQB/RAlZ13TcapqvR6PNlNKfXvPK8imINFaUcHG3aEMwWEPV6+01ZM3h5QsLcg7P75gurmT5S08CAwEAAaOCAZgwggGUMFsGCCsGAQUFBwEBBE8wTTBLBggrBgEFBQcwAoY/aHR0cDovL3BraS5pbmZpbmVvbi5jb20vT3B0aWdhUnNhTWZyQ0EwMDcvT3B0aWdhUnNhTWZyQ0EwMDcuY3J0MA4GA1UdDwEB/wQEAwIAIDBYBgNVHREBAf8ETjBMpEowSDEWMBQGBWeBBQIBDAtpZDo0OTQ2NTgwMDEaMBgGBWeBBQICDA9TTEIgOTY3MCBUUE0yLjAxEjAQBgVngQUCAwwHaWQ6MDcyODAMBgNVHRMBAf8EAjAAMFAGA1UdHwRJMEcwRaBDoEGGP2h0dHA6Ly9wa2kuaW5maW5lb24uY29tL09wdGlnYVJzYU1mckNBMDA3L09wdGlnYVJzYU1mckNBMDA3LmNybDAVBgNVHSAEDjAMMAoGCCqCFABEARQBMB8GA1UdIwQYMBaAFJx99akcPUm75zeNSroS/454otdcMBAGA1UdJQQJMAcGBWeBBQgBMCEGA1UdCQQaMBgwFgYFZ4EFAhAxDTALDAMyLjACAQACAXQwDQYJKoZIhvcNAQELBQADggEBAATaII6W4g9Y10nwgaH76NxORIg9EdO9NzoDpjW+9F/8duFM+6N0Qu//yB6qpR7ZyKYBOdF5eJLsWFYpj2akRZhKuixH6xjR3XGapvimW5pTQ055+xeF5aS/s93Wa/lJVM1JzGsZk+vbqMwNlI12sX6wcaStIMkuAyKGrRdtafS8woEKBb41bTd7Y8Btb4k7gMDoMU1ekqZSNpT/fR5Ff1ob/Sgu8lwEChnFjWF22OjPle++npUyRNo/4aa6EC7+hBVitCiqA9EIPB+Dr8UJ5ZLgObpkLOmTKnlBa9HL6fpnu7EBhB/PomLSoHthZTjdql97MrPQ+XX7OFrMdUZdzO0=")
				identityRequestChallenge, _ := crypt.GetRandomBytes(32)
				privacycaTpm2, err := privacyca.NewPrivacyCA(identityReq)
				Expect(err).NotTo(HaveOccurred())
				identityChallengeRequest := taModel.IdentityChallengePayload{}
				identityChallengeRequest.IdentityRequest = identityReq
				identityChallengeRequest, err = privacycaTpm2.GetIdentityChallengeRequest(identityRequestChallenge, cacert.PublicKey.(*rsa.PublicKey), identityChallengeRequest.IdentityRequest)
				Expect(err).NotTo(HaveOccurred())
				// This step is usually performed by HVS for verifying identityRequestChallenge that gets created during
				// TA on requesting /rpc/identity-request-challenge api for given ekcert
				certifyHostAiksController.StoreEkCerts(identityRequestChallenge, ekCertBytes, identityChallengeRequest)
				jsonData, err := json.Marshal(identityChallengeRequest)

				req, err := http.NewRequest(
					"POST",
					"/privacyca/identity-challenge-response",
					bytes.NewBuffer(jsonData),
				)
				Expect(err).NotTo(HaveOccurred())
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(400))
			})
		})
	})
})
