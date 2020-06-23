/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package mocks

import (
	"github.com/google/uuid"
	"github.com/intel-secl/intel-secl/v3/pkg/hvs/domain/models"
	"github.com/intel-secl/intel-secl/v3/pkg/model/hvs"
	"github.com/pkg/errors"
	"strings"
)

// MockHostStore provides a mocked implementation of interface domain.HostStore
type MockHostStore struct {
	hostStore []*hvs.Host
}

// Create inserts a Host
func (store *MockHostStore) Create(host *hvs.Host) (*hvs.Host, error) {
	store.hostStore = append(store.hostStore, host)
	return host, nil
}

// Retrieve returns Host
func (store *MockHostStore) Retrieve(id uuid.UUID) (*hvs.Host, error) {
	for _, host := range store.hostStore {
		if host.Id == id {
			return host, nil
		}
	}
	return nil, errors.New("no rows in result set")
}

// Update modifies a Host
func (store *MockHostStore) Update(host *hvs.Host) (*hvs.Host, error) {
	for i, t := range store.hostStore {
		if t.Id == host.Id {
			store.hostStore[i] = host
			return host, nil
		}
	}
	return nil, errors.New("record not found")
}

// Delete deletes Host
func (store *MockHostStore) Delete(id uuid.UUID)  error {
	for i, t := range store.hostStore {
		if t.Id == id {
			store.hostStore = append(store.hostStore[:i], store.hostStore[i+1:]...)
			return nil
		}
	}
	return errors.New("record not found")
}

// Search returns a collection of Hosts filtered as per HostFilterCriteria
func (store *MockHostStore) Search(criteria *models.HostFilterCriteria) (*hvs.HostCollection, error) {
	if criteria == nil {
		return &hvs.HostCollection{Hosts: store.hostStore}, nil
	}

	var hosts []*hvs.Host
	if criteria.Id != "" {
		id := uuid.MustParse(criteria.Id)
		t, _ := store.Retrieve(id)
		hosts = append(hosts, t)
	}  else if criteria.HostHardwareId != "" {
		hwid := uuid.MustParse(criteria.HostHardwareId)
		for _, t := range store.hostStore {
			if t.HardwareUuid == hwid {
				hosts =  append(hosts, t)
			}
		}
	} else if criteria.NameEqualTo != "" {
		for _, t := range store.hostStore {
			if t.HostName == criteria.NameEqualTo {
				hosts = append(hosts, t)
			}
		}
	} else if criteria.NameContains != "" {
		for _, t := range store.hostStore {
			if strings.Contains(t.HostName, criteria.NameContains) {
				hosts =  append(hosts, t)
			}
		}
	}

	return &hvs.HostCollection{Hosts: hosts}, nil
}

// NewMockHostStore provides two dummy data for Hosts
func NewMockHostStore() *MockHostStore {
	store := &MockHostStore{}

	store.Create(&hvs.Host{
		Id: uuid.MustParse("ee37c360-7eae-4250-a677-6ee12adce8e2"),
		HostName:         "localhost1",
		ConnectionString: "intel:https://ta.ip.com:1443",
		Description:      "Intel Host",
	})

	store.Create(&hvs.Host{
		Id: uuid.MustParse("e57e5ea0-d465-461e-882d-1600090caa0d"),
		HostName:         "localhost2",
		ConnectionString: "vmware:https://vsphere.com:443/sdk;h=hostName;u=admin.local;p=password",
		Description:      "Vmware Host",
	})

	return store
}
