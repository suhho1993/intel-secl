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
	flavorgroupStore []*hvs.FlavorGroup
}

// Delete Flavorgroup
func (store *MockFlavorgroupStore) Delete(id *uuid.UUID) error {
	for i, fg := range store.flavorgroupStore {
		if fg.ID == *id {
			store.flavorgroupStore[i] = &hvs.FlavorGroup{}
			return nil
		}
	}
	return errors.New(commErr.RowsNotFound)
}

// Retrieve returns FlavorGroup
func (store *MockFlavorgroupStore) Retrieve(id *uuid.UUID) (*hvs.FlavorGroup, error) {
	for _, fg := range store.flavorgroupStore {
		if fg.ID == *id {
			return fg, nil
		}
	}
	return nil, errors.New(commErr.RowsNotFound)
}

// Search returns all FlavorGroups
func (store *MockFlavorgroupStore) Search(criteria *models.FlavorGroupFilterCriteria) (*hvs.FlavorgroupCollection, error) {
	if criteria == nil {
		return &hvs.FlavorgroupCollection{Flavorgroups: store.flavorgroupStore}, nil
	} else if criteria.Id != "" {
		id := uuid.MustParse(criteria.Id)
		fg, _ := store.Retrieve(&id)
		return &hvs.FlavorgroupCollection{Flavorgroups: []*hvs.FlavorGroup{fg}}, nil
	} else if criteria.NameEqualTo != "" {
		for _, fg := range store.flavorgroupStore {
			if fg.Name == criteria.NameEqualTo {
				return &hvs.FlavorgroupCollection{Flavorgroups: []*hvs.FlavorGroup{fg}}, nil
			}
		}
	} else if criteria.NameContains != "" {
		var flavorgroups []*hvs.FlavorGroup
		for _, fg := range store.flavorgroupStore {
			if strings.Contains(fg.Name, criteria.NameContains) {
				flavorgroups = append(flavorgroups, fg)
			}
		}
		return &hvs.FlavorgroupCollection{Flavorgroups: flavorgroups}, nil
	}
	return nil, nil
}

// Create inserts a Flavorgroup
func (store *MockFlavorgroupStore) Create(flavorgroup *hvs.FlavorGroup) (*hvs.FlavorGroup, error) {
	store.flavorgroupStore = append(store.flavorgroupStore, flavorgroup)
	return flavorgroup, nil
}

// NewFakeFlavorgroupStore provides two dummy data for Flavorgroups
func NewFakeFlavorgroupStore() *MockFlavorgroupStore {
	store := &MockFlavorgroupStore{}

	store.Create(&hvs.FlavorGroup{
		ID:   uuid.MustParse("ee37c360-7eae-4250-a677-6ee12adce8e2"),
		Name: "hvs_flavorgroup_test1",
		FlavorMatchPolicyCollection: hvs.FlavorMatchPolicyCollection{
			FlavorMatchPolicies: []hvs.FlavorMatchPolicy{
				{
					FlavorPart: cf.FlavorPartOs,
					MatchPolicy: hvs.MatchPolicy{
						MatchType: hvs.MatchTypeAllOf,
						Required:  hvs.FlavorRequired,
					},
				},
				{
					FlavorPart: cf.FlavorPartPlatform,
					MatchPolicy: hvs.MatchPolicy{
						MatchType: hvs.MatchTypeAnyOf,
						Required:  hvs.FlavorRequiredIfDefined,
					},
				},
			},
		},
	})

	store.Create(&hvs.FlavorGroup{
		ID:   uuid.MustParse("e57e5ea0-d465-461e-882d-1600090caa0d"),
		Name: "hvs_flavorgroup_test2",
		FlavorMatchPolicyCollection: hvs.FlavorMatchPolicyCollection{
			FlavorMatchPolicies: []hvs.FlavorMatchPolicy{
				{
					FlavorPart: cf.FlavorPartHostUnique,
					MatchPolicy: hvs.MatchPolicy{
						MatchType: hvs.MatchTypeAllOf,
						Required:  hvs.FlavorRequired,
					},
				},
			},
		},
	})

	return store
}
