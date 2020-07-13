/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package mocks

import (
	"github.com/google/uuid"
	"github.com/intel-secl/intel-secl/v3/pkg/hvs/domain/models"
	commErr "github.com/intel-secl/intel-secl/v3/pkg/lib/common/err"
	"github.com/intel-secl/intel-secl/v3/pkg/model/hvs"
	"github.com/pkg/errors"
	"reflect"
	"strings"
)

// MockHostStore provides a mocked implementation of interface domain.HostStore
type MockHostStore struct {
	hostStore            []*hvs.Host
	HostFlavorgroupStore []*hvs.HostFlavorgroup
}

// Create inserts a Host
func (store *MockHostStore) Create(host *hvs.Host) (*hvs.Host, error) {
	store.hostStore = append(store.hostStore, host)
	return host, nil
}

// Retrieve returns Host
func (store *MockHostStore) Retrieve(id uuid.UUID) (*hvs.Host, error) {
	for _, h := range store.hostStore {
		if h.Id == id {
			return h, nil
		}
	}
	return nil, errors.New(commErr.RowsNotFound)
}

// Update modifies a Host
func (store *MockHostStore) Update(host *hvs.Host) (*hvs.Host, error) {
	for i, h := range store.hostStore {
		if h.Id == host.Id {
			store.hostStore[i] = host
			return host, nil
		}
	}
	return nil, errors.New(commErr.RecordNotFound)
}

// Delete deletes Host
func (store *MockHostStore) Delete(id uuid.UUID) error {
	for i, h := range store.hostStore {
		if h.Id == id {
			store.hostStore[i] = &hvs.Host{}
			return nil
		}
	}
	return errors.New(commErr.RecordNotFound)
}

// Search returns a collection of Hosts filtered as per HostFilterCriteria
func (store *MockHostStore) Search(criteria *models.HostFilterCriteria) ([]*hvs.Host, error) {
	if criteria == nil || reflect.DeepEqual(*criteria, models.HostFilterCriteria{}) {
		return store.hostStore, nil
	}

	var hosts []*hvs.Host
	if criteria.Id != uuid.Nil {
		h, _ := store.Retrieve(criteria.Id)
		hosts = append(hosts, h)
	}  else if criteria.HostHardwareId != uuid.Nil {
		for _, h := range store.hostStore {
			if h.HardwareUuid == criteria.HostHardwareId {
				hosts =  append(hosts, h)
			}
		}
	} else if criteria.NameEqualTo != "" {
		for _, h := range store.hostStore {
			if h.HostName == criteria.NameEqualTo {
				hosts = append(hosts, h)
			}
		}
	} else if criteria.NameContains != "" {
		for _, h := range store.hostStore {
			if strings.Contains(h.HostName, criteria.NameContains) {
				hosts = append(hosts, h)
			}
		}
	}

	return hosts, nil
}

// AddFlavorgroups associate a Host with specified flavorgroups
func (store *MockHostStore) AddFlavorgroups(hId uuid.UUID, fgIds []uuid.UUID) error {
	for _, fgId := range fgIds {
		store.HostFlavorgroupStore = append(store.HostFlavorgroupStore, &hvs.HostFlavorgroup{
			HostId:        hId,
			FlavorgroupId: fgId,
		})
	}
	return nil
}

// RetrieveFlavorgroup returns Host Flavorgroup association
func (store *MockHostStore) RetrieveFlavorgroup(hId, fgId uuid.UUID) (*hvs.HostFlavorgroup, error) {
	for _, hf := range store.HostFlavorgroupStore {
		if hf.HostId == hId && hf.FlavorgroupId == fgId {
			return hf, nil
		}
	}
	return nil, errors.New(commErr.RowsNotFound)
}

// RemoveFlavorgroups delete Host Flavorgroup associations
func (store *MockHostStore) RemoveFlavorgroups(hId uuid.UUID, fgIds []uuid.UUID) error {
	for i, hf := range store.HostFlavorgroupStore {
		if hf.HostId == hId {
			for _, fgId := range fgIds {
				if hf.FlavorgroupId == fgId {
					store.HostFlavorgroupStore[i] = &hvs.HostFlavorgroup{}
					return nil
				}
			}
		}
	}
	return errors.New(commErr.RecordNotFound)
}

// SearchFlavorgroups returns a collection of flavorgroup Ids associated with host Id
func (store *MockHostStore) SearchFlavorgroups(hId uuid.UUID) ([]uuid.UUID, error) {
	var fgIds []uuid.UUID
	for _, hf := range store.HostFlavorgroupStore {
		if hf.HostId == hId {
			fgIds = append(fgIds, hf.FlavorgroupId)
		}
	}
	return fgIds, nil
}

func (store *MockHostStore) AddTrustCacheFlavors(hId uuid.UUID, fIds []uuid.UUID) ([]uuid.UUID, error){
	// TODO: to be implemented
	return nil, nil
}

func (store *MockHostStore) RemoveTrustCacheFlavors(hId uuid.UUID, fId []uuid.UUID) (error) {
	// TODO: to be implemented
	return nil
}

func (store *MockHostStore) RetrieveTrustCacheFlavors(hId ,fgId uuid.UUID) ([]uuid.UUID, error) {
	// TODO: to be implemented
	return nil, nil
}

// NewMockHostStore provides two dummy data for Hosts
func NewMockHostStore() *MockHostStore {
	store := &MockHostStore{}

	store.Create(&hvs.Host{
		Id:               uuid.MustParse("ee37c360-7eae-4250-a677-6ee12adce8e2"),
		HostName:         "localhost1",
		ConnectionString: "intel:https://ta.ip.com:1443",
		Description:      "Intel Host",
	})

	store.Create(&hvs.Host{
		Id:               uuid.MustParse("e57e5ea0-d465-461e-882d-1600090caa0d"),
		HostName:         "localhost2",
		ConnectionString: "vmware:https://vsphere.com:443/sdk;h=hostName;u=admin.local;p=password",
		Description:      "Vmware Host",
	})

	var fgIds []uuid.UUID
	hostId := uuid.MustParse("ee37c360-7eae-4250-a677-6ee12adce8e2")
	fgIds = append(fgIds, uuid.MustParse("ee37c360-7eae-4250-a677-6ee12adce8e2"))
	fgIds = append(fgIds, uuid.MustParse("e57e5ea0-d465-461e-882d-1600090caa0d"))

	store.AddFlavorgroups(hostId, fgIds)

	return store
}
