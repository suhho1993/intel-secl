/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package mocks

import (
	"github.com/google/uuid"
	"github.com/intel-secl/intel-secl/v3/pkg/model/hvs"
	"github.com/pkg/errors"
	"strconv"
	"strings"
)

// MockTlsPolicyStore provides a mocked implementation of interface hvs.TlsPolicyStore
type MockTlsPolicyStore struct {
	tlsPolicyStore []*hvs.TlsPolicy
}

// Create inserts a TlsPolicy
func (store *MockTlsPolicyStore) Create(tlsPolicy *hvs.TlsPolicy) (*hvs.TlsPolicy, error) {
	store.tlsPolicyStore = append(store.tlsPolicyStore, tlsPolicy)
	return tlsPolicy, nil
}

// Retrieve returns TlsPolicy
func (store *MockTlsPolicyStore) Retrieve(id uuid.UUID) (*hvs.TlsPolicy, error) {
	for _, tlsPolicy := range store.tlsPolicyStore {
		if tlsPolicy.Id == id {
			return tlsPolicy, nil
		}
	}
	return nil, errors.New("no rows in result set")
}

// Update modifies a TlsPolicy
func (store *MockTlsPolicyStore) Update(tlsPolicy *hvs.TlsPolicy) (*hvs.TlsPolicy, error) {
	for i, t := range store.tlsPolicyStore {
		if t.Id == tlsPolicy.Id {
			store.tlsPolicyStore[i] = tlsPolicy
			return tlsPolicy, nil
		}
	}
	return nil, errors.New("record not found")
}

// Delete deletes TlsPolicy
func (store *MockTlsPolicyStore) Delete(id uuid.UUID)  error {
	for i, t := range store.tlsPolicyStore {
		if t.Id == id {
			store.tlsPolicyStore = append(store.tlsPolicyStore[:i], store.tlsPolicyStore[i+1:]...)
			return nil
		}
	}
	return errors.New("record not found")
}

// Search returns a collection of TlsPolicies filtered as per TlsPolicyFilterCriteria
func (store *MockTlsPolicyStore) Search(criteria *hvs.TlsPolicyFilterCriteria) (*hvs.TlsPolicyCollection, error) {
	if criteria == nil {
		return &hvs.TlsPolicyCollection{TlsPolicies: store.tlsPolicyStore}, nil
	}

	var tlsPolicies []*hvs.TlsPolicy
	if criteria.Id != "" {
		id := uuid.MustParse(criteria.Id)
		t, _ := store.Retrieve(id)
		tlsPolicies = append(tlsPolicies, t)
	}  else if criteria.HostId != "" {
		for _, t := range store.tlsPolicyStore {
			if t.Name == criteria.HostId && t.PrivateScope {
				tlsPolicies =  append(tlsPolicies, t)
			}
		}
	}  else if criteria.PrivateEqualTo != "" {
		private, _ := strconv.ParseBool(criteria.PrivateEqualTo)
		for _, t := range store.tlsPolicyStore {
			if t.PrivateScope == private {
				tlsPolicies =  append(tlsPolicies, t)
			}
		}
	} else if criteria.NameEqualTo != "" {
		for _, t := range store.tlsPolicyStore {
			if t.Name == criteria.NameEqualTo {
				tlsPolicies = append(tlsPolicies, t)
			}
		}
	} else if criteria.NameContains != "" {
		for _, t := range store.tlsPolicyStore {
			if strings.Contains(t.Name, criteria.NameContains) {
				tlsPolicies =  append(tlsPolicies, t)
			}
		}
	} else if criteria.CommentEqualTo != "" {
		for _, t := range store.tlsPolicyStore {
			if t.Name == criteria.CommentEqualTo {
				tlsPolicies = append(tlsPolicies, t)
			}
		}
	} else if criteria.CommentContains != "" {
		for _, t := range store.tlsPolicyStore {
			if strings.Contains(t.Name, criteria.CommentContains) {
				tlsPolicies =  append(tlsPolicies, t)
			}
		}
	}
	return &hvs.TlsPolicyCollection{TlsPolicies: tlsPolicies}, nil
}

// NewMockTlsPolicyStore provides two dummy data for TlsPolicies
func NewMockTlsPolicyStore() *MockTlsPolicyStore {
	store := &MockTlsPolicyStore{}

	store.Create(&hvs.TlsPolicy{
		Id: uuid.MustParse("ee37c360-7eae-4250-a677-6ee12adce8e2"),
		Name:         "hvs_tlspolicy_test1",
		PrivateScope: true,
		Descriptor:   &hvs.TlsPolicyDescriptor{
			PolicyType: "certificate",
			Metadata:   map[string]string{"encoding" : "base64"},
			Data:       []string{"MIIBwzCCASygAwIBAgIJANE6wc0/mOjZMA0GCSqGSIb3DQEBCwUAMBExDzANBgNVBAMTBnRlc3RjYTAeFw0xNDA2MjQyMDQ1MjdaFw0xNDA3MjQyMDQ1MjdaMBExDzANBgNVBAMTBnRlc3RjYTCBnzANBgkqhkiG9w0BAQEFAAOBjQAwgYkCgYEAt9EmIilK3qSRGMRxEtcGj42dsJUf5h2OZIG25Er7dDxJbdw6KrOQhVUUx+2DUOQLMsr3sJt9D5eyWC4+vhoiNRMUjamR52/hjIBosr2XTfWKdKG8NsuDzwljHkB/6uv3P+AfQQ/eStXc42cv8J6vZXeQF6QMf63roW8i6SNYHwMCAwEAAaMjMCEwDgYDVR0PAQH/BAQDAgIEMA8GA1UdEwEB/wQFMAMBAf8wDQYJKoZIhvcNAQELBQADgYEAXov/vFVOMAznD+BT8tBfAT1R/nWFmrFB7os4Ry1mYjbr0lrW2vtUzA2XFx6nUzafYdyL1L4PnI7LGYqRqicT6WzGb1grNTJUJhrI7FkGg6TXQ4QSf6EmcEwsTlGHk9rxp9YySJt/xrhboP33abdXMHUWOXnJEHu4la8tnuzwSvM="},
		},
	})

	store.Create(&hvs.TlsPolicy{
		Id: uuid.MustParse("e57e5ea0-d465-461e-882d-1600090caa0d"),
		Name:         "hvs_tlspolicy_test2",
		PrivateScope: true,
		Descriptor:   &hvs.TlsPolicyDescriptor{
			PolicyType: "certificate",
			Metadata:   map[string]string{"encoding" : "base64"},
			Data:       []string{"MIIBwzCCASygAwIBAgIJANE6wc0/mOjZMA0GCSqGSIb3DQEBCwUAMBExDzANBgNVBAMTBnRlc3RjYTAeFw0xNDA2MjQyMDQ1MjdaFw0xNDA3MjQyMDQ1MjdaMBExDzANBgNVBAMTBnRlc3RjYTCBnzANBgkqhkiG9w0BAQEFAAOBjQAwgYkCgYEAt9EmIilK3qSRGMRxEtcGj42dsJUf5h2OZIG25Er7dDxJbdw6KrOQhVUUx+2DUOQLMsr3sJt9D5eyWC4+vhoiNRMUjamR52/hjIBosr2XTfWKdKG8NsuDzwljHkB/6uv3P+AfQQ/eStXc42cv8J6vZXeQF6QMf63roW8i6SNYHwMCAwEAAaMjMCEwDgYDVR0PAQH/BAQDAgIEMA8GA1UdEwEB/wQFMAMBAf8wDQYJKoZIhvcNAQELBQADgYEAXov/vFVOMAznD+BT8tBfAT1R/nWFmrFB7os4Ry1mYjbr0lrW2vtUzA2XFx6nUzafYdyL1L4PnI7LGYqRqicT6WzGb1grNTJUJhrI7FkGg6TXQ4QSf6EmcEwsTlGHk9rxp9YySJt/xrhboP33abdXMHUWOXnJEHu4la8tnuzwSvM="},
		},
	})

	return store
}
