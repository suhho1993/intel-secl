/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */

package mocks

import (
	"errors"
	"github.com/google/uuid"
	"github.com/intel-secl/intel-secl/v3/pkg/hvs/domain"
	"github.com/intel-secl/intel-secl/v3/pkg/hvs/domain/models"
	"github.com/intel-secl/intel-secl/v3/pkg/model/hvs"
)

type hostStore struct {
	m map[uuid.UUID]hvs.Host
}

func NewHostStore() domain.HostStore {

	return &hostStore{make(map[uuid.UUID]hvs.Host)}
}

func (hs *hostStore) Create(host *hvs.Host) (*hvs.Host, error) {
	rec := *host
	rec.Id = uuid.New()
	copy(rec.FlavorgroupNames, host.FlavorgroupNames)
	hs.m[rec.Id] = rec
	cp := rec
	return &cp, nil
}

func (hs *hostStore) Retrieve(uuid uuid.UUID) (*hvs.Host, error) {
	if _, ok := hs.m[uuid]; ok {
		cp := hs.m[uuid]
		return &cp, nil
	}
	return nil, errors.New("Record not fouund")
}

func (hs *hostStore) Update(host *hvs.Host) (*hvs.Host, error) {
	if rec, ok := hs.m[host.Id]; ok {

		if len(host.FlavorgroupNames) > 0 {
			rec.FlavorgroupNames = append([]string{}, host.FlavorgroupNames...)
		}
		if host.ConnectionString != "" {
			rec.ConnectionString = host.ConnectionString
		}
		if host.Description != "" {
			rec.Description = host.Description
		}
		if host.HardwareUuid != uuid.Nil {
			rec.HardwareUuid = host.HardwareUuid
		}
		hs.m[host.Id] = rec
		cp := rec
		return &cp, nil
	}
	return nil, errors.New("Record not found")
}

func (hs *hostStore) Delete(uuid uuid.UUID) error {
	if _, ok := hs.m[uuid]; ok {
		delete(hs.m, uuid)
		return nil
	}
	return errors.New("Record not found")
}

func (hs *hostStore) Search(criteria *models.HostFilterCriteria) ([]*hvs.Host, error) {
	if criteria.Id == uuid.Nil {
		result := make([]*hvs.Host, 0, len(hs.m))
		for _, v := range hs.m {
			result = append(result, &v)
		}
		return result, nil
	}
	if _, ok := hs.m[criteria.Id]; ok {
		cp := hs.m[criteria.Id]
		return []*hvs.Host{&cp}, nil
	}
	return nil, errors.New("No Records fouund")
}

func (store *hostStore) AddFlavorgroups(hId uuid.UUID, fgIds []uuid.UUID) error {
	return nil
}

func (store *hostStore) RetrieveFlavorgroup(hId, fgId uuid.UUID) (*hvs.HostFlavorgroup, error) {
	return &hvs.HostFlavorgroup{}, nil
}

func (store *hostStore) RemoveFlavorgroup(hId, fgId uuid.UUID) error {
	return nil
}

func (store *hostStore) SearchFlavorgroups(criteria *models.HostFlavorgroupFilterCriteria) ([]*hvs.HostFlavorgroup, error) {
	var hostFlavorgroups []*hvs.HostFlavorgroup
	return hostFlavorgroups, nil
}

func (hs *hostStore) AddTrustCacheFlavors(hId uuid.UUID, fIds []uuid.UUID) ([]uuid.UUID, error){
	// TODO: to be implemented
	return nil, nil
}

func (hs *hostStore) RemoveTrustCacheFlavors(hId uuid.UUID, fIds []uuid.UUID) (error) {
	// TODO: to be implemented
	return nil
}

func (hs *hostStore) RetrieveTrustCacheFlavors(hId , fgId uuid.UUID) ([]uuid.UUID, error) {
	// TODO: to be implemented
	return nil, nil
}
