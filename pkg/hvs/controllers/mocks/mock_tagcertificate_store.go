/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package mocks

import (
	"encoding/json"
	"github.com/google/uuid"
	"github.com/intel-secl/intel-secl/v3/pkg/hvs/domain/models"
	commErr "github.com/intel-secl/intel-secl/v3/pkg/lib/common/err"
	"github.com/intel-secl/intel-secl/v3/pkg/model/hvs"
	"github.com/pkg/errors"
	"reflect"
	"strings"
	"time"
)

var (
	TagCert1 = ` {"id":"fda6105d-a340-42da-bc35-0555e7a5e360","certificate":"MIICbTCB1gIBATAfoR2kGzAZMRcwFQYBaQQQAOzTq5r05xGQbgAVYKBAYqAiMCCkHjAcMRowGAYDVQQDDBFhc3NldC10YWctc2VydmljZTANBgkqhkiG9w0BAQwFAAIGAXLGSydbMCIYDzIwMjAwNjE4MDcxODMzWhgPMjAyMTA2MTgwNzE4MzNaMFEwIgYFVQSGFQIxGTAXDAhMb2NhdGlvbjALDAlOb3J0aFBvbGUwKwYFVQSGFQIxIjAgDAdDb21wYW55MBUME1NhbnRhQ2xhdXNlV29ya3Nob3AwDQYJKoZIhvcNAQEMBQADggGBACnXS2DkjCeAGTlvGFxysaVBnPzhoLU5gbUwjwsuF35HQ4x8VpbfgRRohetOy5Hpxxvxxe8vF8Wl1UrLkJlXZQanlr8ZuHw53ptgvZzjkCyFxhXK+tqnaY5RmctEOtxTqTZYDIHDcGOvIDiXtof6wncGGmb+i5UMaTQzOEfkdGJlUkulSHPpN/p+bCOjFBhLQ9LD5VYMsev8DrV1Y1y7p19c48zOgKnr2ASbj2n9nMrt1OjVDOEj2+2H42l+dhq2MQ5vbzAdd674Nu/00Thc9sZPsZlToDNOgQvplZCfs9GW72sxSa0TK+8LXg+TSlctlPn3lBZOANnAdVakzqWFvFwDX8dJu9P6DDgBmbgKzbsu+0bzaZeai+zR2CFOe6FlUZ542/ZGLVvihjkn8EqG7NdIBd0kANci+lFBlgPOXrBRLJvYh9NjI8mkyCF6R9rpNsva4iLZKrVk8+u1fd/rb6Dw26on25ZQo7jJ7sdQepvupWARiXX3DNeSRvoKlCWPWQ==","subject":"00ecd3ab-9af4-e711-906e-001560a04062","issuer":"CN=asset-tag-service","not_before":"` + time.Now().Add(-TimeDuration30Mins).Format(time.RFC3339) + `","not_after":"` + time.Now().AddDate(1, 0, 0).Format(time.RFC3339) + `","hardware_uuid":"80ecce40-04b8-e811-906e-00163566263e"}`
	TagCert2 = ` {"id":"3966e9e8-4f44-4a9e-9231-b4a83743de55","certificate":"MIICbTCB1gIBATAfoR2kGzAZMRcwFQYBaQQQAOzTq5r05xGQbgAVYKBAYqAiMCCkHjAcMRowGAYDVQQDDBFhc3NldC10YWctc2VydmljZTANBgkqhkiG9w0BAQwFAAIGAXLGSydbMCIYDzIwMjAwNjE4MDcxODMzWhgPMjAyMTA2MTgwNzE4MzNaMFEwIgYFVQSGFQIxGTAXDAhMb2NhdGlvbjALDAlOb3J0aFBvbGUwKwYFVQSGFQIxIjAgDAdDb21wYW55MBUME1NhbnRhQ2xhdXNlV29ya3Nob3AwDQYJKoZIhvcNAQEMBQADggGBACnXS2DkjCeAGTlvGFxysaVBnPzhoLU5gbUwjwsuF35HQ4x8VpbfgRRohetOy5Hpxxvxxe8vF8Wl1UrLkJlXZQanlr8ZuHw53ptgvZzjkCyFxhXK+tqnaY5RmctEOtxTqTZYDIHDcGOvIDiXtof6wncGGmb+i5UMaTQzOEfkdGJlUkulSHPpN/p+bCOjFBhLQ9LD5VYMsev8DrV1Y1y7p19c48zOgKnr2ASbj2n9nMrt1OjVDOEj2+2H42l+dhq2MQ5vbzAdd674Nu/00Thc9sZPsZlToDNOgQvplZCfs9GW72sxSa0TK+8LXg+TSlctlPn3lBZOANnAdVakzqWFvFwDX8dJu9P6DDgBmbgKzbsu+0bzaZeai+zR2CFOe6FlUZ542/ZGLVvihjkn8EqG7NdIBd0kANci+lFBlgPOXrBRLJvYh9NjI8mkyCF6R9rpNsva4iLZKrVk8+u1fd/rb6Dw26on25ZQo7jJ7sdQepvupWARiXX3DNeSRvoKlCWPWQ==","subject":"00ecd3ab-9af4-e711-906e-001560a04062","issuer":"CN=asset-tag-service","not_before":"` + time.Now().Add(-TimeDuration30Mins).Format(time.RFC3339) + `","not_after":"` + time.Now().AddDate(1, 0, 0).Format(time.RFC3339) + `","hardware_uuid":"80ecce40-04b8-e811-906e-00163566263e"}`
	TagCert3 = ` {"id":"a4b46350-d60b-44db-88e8-6d1ada16e282","certificate":"MIICazCB1AIBATAfoR2kGzAZMRcwFQYBaQQQAOzTq5r05xGQbgAVYKBAYqAiMCCkHjAcMRowGAYDVQQDDBFhc3NldC10YWctc2VydmljZTANBgkqhkiG9w0BAQwFAAIGAXLGRFmUMCIYDzIwMjAwNjE4MDcxMTA3WhgPMjAyMTA2MTgwNzExMDdaME8wIwYFVQSGFQIxGjAYDAhMb2NhdGlvbjAMDApTYW50YUNsYXJhMCgGBVUEhhUCMR8wHQwHQ29tcGFueTASDBBJbnRlbENvcnBvcmF0aW9uMA0GCSqGSIb3DQEBDAUAA4IBgQBy31oki3WdYEfdH/j3Sajqbffqa6+uzZiq7o+ggewxhahOGc9vTVHT7EPS6naVUIlmFTHLKa+mfuWGLfcYnswrLG5wPMeD3XIlmM5hRK/HuhR9cTTuXivX9azVT4QGQAHfVjpNq/dXGza68ZYo4JDnNx2LVCFBKVt3jbhYigweC/0xHYXuK7XL4jBcS+HGIGCHdQnJKYgMbW+tO6FFN2lw43FhHxY4Cp864tlje/iIxaUrjQbSOi5iTAj+oWawNYoP5FfzYtAowkDGyYdE6f1fFxiI6+GGy7XLE+hqEqqbQhTIvCB74YC96pZmanVmy9mnYrZEwdxg2Q/aua+TMnWLzgXaOsousWFuq63cFUVepKk/0W2lVTl9BzrNmRtdUmyPkcvMMxcJquZI0YzLFTLGqJ1RSxg3p/wppGdSkwIWmdYmBMmhsuOYm7X0AqnSdB+/mweCUEyo5FO/mYUV4hxUFGi8f9I7LJSeP2h5i7nX8Dkkngcq9Msa41BYSMESOO4=","subject":"80ecce40-04b8-e811-906e-00163566263e","issuer":"CN=asset-tag-service","not_before":"` + time.Now().AddDate(-1, 0, 0).Format(time.RFC3339) + `","not_after":"` + time.Now().AddDate(0, 6, 0).Format(time.RFC3339) + `","hardware_uuid":"af937bc3-c381-42a6-bd17-bfe054c023aa"}`
	TagCert4 = ` {"id":"dbed7b6b-3d01-4e53-82e7-d1c62f8b6a5c","certificate":"MIICazCB1AIBATAfoR2kGzAZMRcwFQYBaQQQAOzTq5r05xGQbgAVYKBAYqAiMCCkHjAcMRowGAYDVQQDDBFhc3NldC10YWctc2VydmljZTANBgkqhkiG9w0BAQwFAAIGAXLGRFmUMCIYDzIwMjAwNjE4MDcxMTA3WhgPMjAyMTA2MTgwNzExMDdaME8wIwYFVQSGFQIxGjAYDAhMb2NhdGlvbjAMDApTYW50YUNsYXJhMCgGBVUEhhUCMR8wHQwHQ29tcGFueTASDBBJbnRlbENvcnBvcmF0aW9uMA0GCSqGSIb3DQEBDAUAA4IBgQBy31oki3WdYEfdH/j3Sajqbffqa6+uzZiq7o+ggewxhahOGc9vTVHT7EPS6naVUIlmFTHLKa+mfuWGLfcYnswrLG5wPMeD3XIlmM5hRK/HuhR9cTTuXivX9azVT4QGQAHfVjpNq/dXGza68ZYo4JDnNx2LVCFBKVt3jbhYigweC/0xHYXuK7XL4jBcS+HGIGCHdQnJKYgMbW+tO6FFN2lw43FhHxY4Cp864tlje/iIxaUrjQbSOi5iTAj+oWawNYoP5FfzYtAowkDGyYdE6f1fFxiI6+GGy7XLE+hqEqqbQhTIvCB74YC96pZmanVmy9mnYrZEwdxg2Q/aua+TMnWLzgXaOsousWFuq63cFUVepKk/0W2lVTl9BzrNmRtdUmyPkcvMMxcJquZI0YzLFTLGqJ1RSxg3p/wppGdSkwIWmdYmBMmhsuOYm7X0AqnSdB+/mweCUEyo5FO/mYUV4hxUFGi8f9I7LJSeP2h5i7nX8Dkkngcq9Msa41BYSMESOO4=","subject":"80ecce40-04b8-e811-906e-00163566263e","issuer":"CN=asset-tag-service","not_before":"` + time.Now().AddDate(-1, 0, 0).Format(time.RFC3339) + `","not_after":"` + time.Now().AddDate(1, 4, 15).Format(time.RFC3339) + `","hardware_uuid":"af937bc3-c381-42a6-bd17-bfe054c023aa"}`
)

// MockTagCertificateStore provides a mocked implementation of interface hvs.TagCertificateStore
type MockTagCertificateStore struct {
	TagCertificateStore map[uuid.UUID]*hvs.TagCertificate
}

// Create inserts a TagCertificate into the store
func (store *MockTagCertificateStore) Create(tc *hvs.TagCertificate) (*hvs.TagCertificate, error) {
	store.TagCertificateStore[tc.ID] = tc
	return tc, nil
}

// Retrieve returns a single TagCertificate record from the store
func (store *MockTagCertificateStore) Retrieve(id uuid.UUID) (*hvs.TagCertificate, error) {
	if tc, ok := store.TagCertificateStore[id]; ok {
		return tc, nil
	}
	return nil, errors.New(commErr.RowsNotFound)
}

// Delete deletes TagCertificate from the store
func (store *MockTagCertificateStore) Delete(tagCertId uuid.UUID) error {
	if _, ok := store.TagCertificateStore[tagCertId]; ok {
		delete(store.TagCertificateStore, tagCertId)
		return nil
	}
	return errors.New(commErr.RowsNotFound)
}

// Search returns a filtered list of TagCertificates per the provided TagCertificateFilterCriteria
func (store *MockTagCertificateStore) Search(criteria *models.TagCertificateFilterCriteria) ([]*hvs.TagCertificate, error) {

	var tcc []*hvs.TagCertificate
	// start with all rows
	for _, tc := range store.TagCertificateStore {
		tcc = append(tcc, tc)
	}

	// TagCertificate filter is false
	if criteria == nil || reflect.DeepEqual(*criteria, models.TagCertificateFilterCriteria{}) {
		return tcc, nil
	}

	// TagCertificate ID filter
	if criteria.ID != uuid.Nil {
		var tcFiltered []*hvs.TagCertificate
		for _, tc := range tcc {
			if tc.ID == criteria.ID {
				tcFiltered = append(tcFiltered, tc)
			}
		}
		tcc = tcFiltered
	}

	// HostHardwareID filter
	if criteria.HardwareUUID != uuid.Nil {
		var tcFiltered []*hvs.TagCertificate
		for _, tc := range tcc {
			if tc.HardwareUUID == criteria.HardwareUUID {
				tcFiltered = append(tcFiltered, tc)
			}
		}
		tcc = tcFiltered
	}

	// SubjectEqualTo filter
	if criteria.SubjectEqualTo != "" {
		var tcFiltered []*hvs.TagCertificate
		for _, tc := range tcc {
			if tc.Subject == criteria.SubjectEqualTo {
				tcFiltered = append(tcFiltered, tc)
			}
		}
		tcc = tcFiltered
	}

	// SubjectContains filter
	if criteria.SubjectContains != "" {
		var tcFiltered []*hvs.TagCertificate
		for _, tc := range tcc {
			if strings.Contains(tc.Subject, criteria.SubjectContains) {
				tcFiltered = append(tcFiltered, tc)
			}
		}
		tcc = tcFiltered
	}

	// IssuerEqualTo filter
	if criteria.IssuerEqualTo != "" {
		var tcFiltered []*hvs.TagCertificate
		for _, tc := range tcc {
			if strings.ToLower(tc.Issuer) == strings.ToLower(criteria.IssuerEqualTo) {
				tcFiltered = append(tcFiltered, tc)
			}
		}
		tcc = tcFiltered
	}

	// IssuerContains filter
	if criteria.IssuerContains != "" {
		var tcFiltered []*hvs.TagCertificate
		for _, tc := range tcc {
			if strings.Contains(strings.ToLower(tc.Issuer), strings.ToLower(criteria.IssuerContains)) {
				tcFiltered = append(tcFiltered, tc)
			}
		}
		tcc = tcFiltered
	}

	// ValidOn
	if !criteria.ValidOn.IsZero() {
		var tcFiltered []*hvs.TagCertificate

		for _, tc := range tcc {
			if tc.NotBefore.Before(criteria.ValidOn) && tc.NotAfter.After(criteria.ValidOn) {
				tcFiltered = append(tcFiltered, tc)
			}
		}
		tcc = tcFiltered
	}

	// ValidBefore
	if !criteria.ValidAfter.IsZero() {
		var tcFiltered []*hvs.TagCertificate
		for _, tc := range tcc {
			if tc.NotBefore.After(criteria.ValidAfter) && tc.NotAfter.After(criteria.ValidAfter) {
				tcFiltered = append(tcFiltered, tc)
			}
		}
		tcc = tcFiltered
	}

	// ValidAfter
	if !criteria.ValidBefore.IsZero() {
		var tcFiltered []*hvs.TagCertificate
		for _, tc := range tcc {
			if tc.NotBefore.Before(criteria.ValidAfter) && tc.NotAfter.Before(criteria.ValidAfter) {
				tcFiltered = append(tcFiltered, tc)
			}
		}
		tcc = tcFiltered
	}

	return tcc, nil
}

// NewFakeTagCertificateStore loads dummy data into MockTagCertificateStore
func NewFakeTagCertificateStore() *MockTagCertificateStore {
	store := &MockTagCertificateStore{}

	store.TagCertificateStore = make(map[uuid.UUID]*hvs.TagCertificate)

	// unmarshal the fixed host status
	var tc1, tc2, tc3, tc4 hvs.TagCertificate
	json.Unmarshal([]byte(TagCert1), &tc1)
	json.Unmarshal([]byte(TagCert2), &tc2)
	json.Unmarshal([]byte(TagCert3), &tc3)
	json.Unmarshal([]byte(TagCert4), &tc4)

	// add to store
	store.Create(&tc1)
	store.Create(&tc2)
	store.Create(&tc3)
	store.Create(&tc4)

	return store
}
