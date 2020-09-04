/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package directory

import (
	"encoding/json"
	"io/ioutil"
	"os"
	"path/filepath"
	"reflect"

	"github.com/google/uuid"
	"github.com/intel-secl/intel-secl/v3/pkg/kbs/domain/models"
	"github.com/pkg/errors"
)

type KeyStore struct {
	Dir string
}

func NewKeyStore(dir string) *KeyStore {
	return &KeyStore{dir}
}

func (ks *KeyStore) Create(key *models.KeyAttributes) (*models.KeyAttributes, error) {
	defaultLog.Trace("directory/key_store:Create() Entering")
	defer defaultLog.Trace("directory/key_store:Create() Leaving")

	bytes, err := json.Marshal(key)
	if err != nil {
		return nil, errors.Wrap(err, "directory/key_store:Create() Failed to marshal key attributes")
	}

	err = ioutil.WriteFile(filepath.Join(ks.Dir, key.ID.String()), bytes, 0644)
	if err != nil {
		return nil, errors.Wrap(err, "directory/key_store:Create() Failed to store key attributes in file")
	}

	return key, nil
}

func (ks *KeyStore) Retrieve(id uuid.UUID) (*models.KeyAttributes, error) {
	defaultLog.Trace("directory/key_store:Retrieve() Entering")
	defer defaultLog.Trace("directory/key_store:Retrieve() Leaving")

	bytes, err := ioutil.ReadFile(filepath.Join(ks.Dir, id.String()))
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		} else {
			return nil, errors.Wrapf(err, "directory/key_store:Retrieve() Unable to read key with ID : %s", id.String())
		}
	}

	var key models.KeyAttributes
	err = json.Unmarshal(bytes, &key)
	if err != nil {
		return nil, errors.Wrap(err, "directory/key_store:Retrieve() Failed to unmarshal key attributes")
	}

	return &key, nil
}

func (ks *KeyStore) Delete(id uuid.UUID) error {
	defaultLog.Trace("directory/key_store:Delete() Entering")
	defer defaultLog.Trace("directory/key_store:Delete() Leaving")

	if err := os.Remove(filepath.Join(ks.Dir, id.String())); err != nil {
		return err
	}
	return nil
}

func (ks *KeyStore) Search(criteria *models.KeyFilterCriteria) ([]models.KeyAttributes, error) {
	defaultLog.Trace("directory/key_store:Search() Entering")
	defer defaultLog.Trace("directory/key_store:Search() Leaving")

	var keys []models.KeyAttributes
	keyFiles, err := ioutil.ReadDir(ks.Dir)
	if err != nil {
		return nil, errors.Wrapf(err, "directory/key_store:Search() Error in reading the keys directory : %s", ks.Dir)
	}

	for _, keyFile := range keyFiles {
		key, err := ks.Retrieve(uuid.MustParse(keyFile.Name()))
		if err != nil {
			return nil, err
		}

		keys = append(keys, *key)
	}

	if len(keys) > 0 {
		keys = filterKeys(keys, criteria)
	}

	return keys, nil
}

// helper function to filter the keys based on given filter criteria.
func filterKeys(keys []models.KeyAttributes, criteria *models.KeyFilterCriteria) []models.KeyAttributes {
	defaultLog.Trace("directory/key_store:filterKeys() Entering")
	defer defaultLog.Trace("directory/key_store:filterKeys() Leaving")

	if keys == nil {
		return nil
	}

	if criteria == nil || reflect.DeepEqual(*criteria, models.KeyFilterCriteria{}) {
		return keys
	}

	// AlgorithmEqualTo filter
	if criteria.AlgorithmEqualTo != "" {
		var filteredKeys []models.KeyAttributes
		for _, key := range keys {
			if key.Algorithm == criteria.AlgorithmEqualTo {
				filteredKeys = append(filteredKeys, key)
			}
		}
		keys = filteredKeys
	}

	// KeyLengthEqualTo filter
	if criteria.KeyLengthEqualTo != 0 {
		var filteredKeys []models.KeyAttributes
		for _, key := range keys {
			if key.KeyLength == criteria.KeyLengthEqualTo {
				filteredKeys = append(filteredKeys, key)
			}
		}
		keys = filteredKeys
	}

	// TransferPolicyId filter
	if criteria.TransferPolicyId != uuid.Nil {
		var filteredKeys []models.KeyAttributes
		for _, key := range keys {
			if key.TransferPolicyId == criteria.TransferPolicyId {
				filteredKeys = append(filteredKeys, key)
			}
		}
		keys = filteredKeys
	}

	return keys
}
