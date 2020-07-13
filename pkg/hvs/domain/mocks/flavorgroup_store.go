/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package mocks

import (
	"github.com/google/uuid"
	"github.com/intel-secl/intel-secl/v3/pkg/hvs/domain/models"
	commErr "github.com/intel-secl/intel-secl/v3/pkg/lib/common/err"
	cf "github.com/intel-secl/intel-secl/v3/pkg/lib/flavor/common"
	"github.com/intel-secl/intel-secl/v3/pkg/model/hvs"
	"github.com/pkg/errors"
	"strings"
)

// MockFlavorgroupStore provides a mocked implementation of interface hvs.FlavorGroupStore
type MockFlavorgroupStore struct {
	FlavorgroupStore       map[uuid.UUID]*hvs.FlavorGroup
	FlavorFlavorGroupStore []*flavorFlavorGroupStore
	HostFlavorgroupStore   []*hvs.HostFlavorgroup
}

// Delete Flavorgroup
func (store *MockFlavorgroupStore) Delete(id uuid.UUID) error {

	if _, ok := store.FlavorgroupStore[id]; ok {
		delete(store.FlavorgroupStore, id)
		return nil
	}
	return errors.New(commErr.RowsNotFound)
}

// Retrieve returns FlavorGroup
func (store *MockFlavorgroupStore) Retrieve(id uuid.UUID) (*hvs.FlavorGroup, error) {
	if _, ok := store.FlavorgroupStore[id]; ok {
		return store.FlavorgroupStore[id], nil
	}
	return nil, errors.New(commErr.RowsNotFound)
}

// Search returns all FlavorGroups
func (store *MockFlavorgroupStore) Search(criteria *models.FlavorGroupFilterCriteria) (*hvs.FlavorgroupCollection, error) {

	var flvrGroups []*hvs.FlavorGroup
	for _, fg := range store.FlavorgroupStore {
		flvrGroups = append(flvrGroups, fg)
	}

	if criteria == nil {
		return &hvs.FlavorgroupCollection{Flavorgroups: flvrGroups}, nil
	} else if criteria.Id != "" {
		id := uuid.MustParse(criteria.Id)
		fg, _ := store.Retrieve(id)
		return &hvs.FlavorgroupCollection{Flavorgroups: []*hvs.FlavorGroup{fg}}, nil
	} else if criteria.NameEqualTo != "" {
		for _, fg := range store.FlavorgroupStore {
			if fg.Name == criteria.NameEqualTo {
				return &hvs.FlavorgroupCollection{Flavorgroups: []*hvs.FlavorGroup{fg}}, nil
			}
		}
	} else if criteria.NameContains != "" {
		var flavorgroups []*hvs.FlavorGroup
		for _, fg := range store.FlavorgroupStore {
			if strings.Contains(fg.Name, criteria.NameContains) {
				flavorgroups = append(flavorgroups, fg)
			}
		}
		return &hvs.FlavorgroupCollection{Flavorgroups: flavorgroups}, nil
	} else if criteria.HostId != "" {
		var flavorgroups []*hvs.FlavorGroup
		for _, hsFg := range store.HostFlavorgroupStore {
			if criteria.HostId == hsFg.HostId.String() {
				flavorgroup, _ := store.Retrieve(hsFg.FlavorgroupId)
				flavorgroups = append(flavorgroups, flavorgroup)
			}
		}
		return &hvs.FlavorgroupCollection{Flavorgroups: flavorgroups}, nil
	}
	return nil, nil
}

// Create inserts a Flavorgroup
func (store *MockFlavorgroupStore) Create(flavorgroup *hvs.FlavorGroup) (*hvs.FlavorGroup, error) {
	store.FlavorgroupStore[flavorgroup.ID] = flavorgroup
	return flavorgroup, nil
}

func (store *MockFlavorgroupStore) AddFlavors(fgId uuid.UUID, fIds []uuid.UUID) ([]uuid.UUID, error) {

	for _, fId := range fIds {
		store.FlavorFlavorGroupStore = append(store.FlavorFlavorGroupStore, &flavorFlavorGroupStore{fId: fId, fgId: fgId})
	}
	return fIds, nil
}

func (store *MockFlavorgroupStore) RemoveFlavors(fgId uuid.UUID, fId []uuid.UUID) error {
	// TODO: to be implemented
	return nil
}

func (store *MockFlavorgroupStore) SearchFlavors(fgId uuid.UUID) ([]uuid.UUID, error) {
	// TODO: to be implemented
	return nil, nil
}

// NewFakeFlavorgroupStore provides two dummy data for Flavorgroups
func NewFakeFlavorgroupStore() *MockFlavorgroupStore {
	store := &MockFlavorgroupStore{
		FlavorgroupStore: make(map[uuid.UUID]*hvs.FlavorGroup),
	}
	store.Create(&hvs.FlavorGroup{
		ID:   uuid.MustParse("ee37c360-7eae-4250-a677-6ee12adce8e2"),
		Name: "hvs_flavorgroup_test1",
		MatchPolicies: []hvs.FlavorMatchPolicy{
			{
				FlavorPart: cf.FlavorPartOs,
				MatchPolicy: hvs.MatchPolicy{
					MatchType: hvs.MatchTypeAnyOf,
					Required:  hvs.FlavorRequired,
				},
			},
			{
				FlavorPart: cf.FlavorPartPlatform,
				MatchPolicy: hvs.MatchPolicy{
					MatchType: hvs.MatchTypeAnyOf,
					Required:  hvs.FlavorRequired,
				},
			},
			{
				FlavorPart: cf.FlavorPartSoftware,
				MatchPolicy: hvs.MatchPolicy{
					MatchType: hvs.MatchTypeAllOf,
					Required:  hvs.FlavorRequiredIfDefined,
				},
			},
		},
	})

	store.Create(&hvs.FlavorGroup{
		ID:   uuid.MustParse("e57e5ea0-d465-461e-882d-1600090caa0d"),
		Name: "hvs_flavorgroup_test2",
		MatchPolicies: []hvs.FlavorMatchPolicy{
			{
				FlavorPart: cf.FlavorPartHostUnique,
				MatchPolicy: hvs.MatchPolicy{
					MatchType: hvs.MatchTypeAllOf,
					Required:  hvs.FlavorRequired,
				},
			},
		},
	})

	return store
}
