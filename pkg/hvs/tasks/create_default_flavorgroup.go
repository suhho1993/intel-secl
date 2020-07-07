/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package tasks

import (
	"fmt"
	"io"

	"github.com/intel-secl/intel-secl/v3/pkg/hvs/constants"
	"github.com/intel-secl/intel-secl/v3/pkg/hvs/domain/models"
	"github.com/intel-secl/intel-secl/v3/pkg/hvs/postgres"
	commConfig "github.com/intel-secl/intel-secl/v3/pkg/lib/common/config"
	"github.com/intel-secl/intel-secl/v3/pkg/lib/common/setup"
	"github.com/intel-secl/intel-secl/v3/pkg/model/hvs"
	"github.com/pkg/errors"
)

type CreateDefaultFlavor struct {
	commConfig.DBConfig

	commandName      string
	flvGroupStorePtr *postgres.FlavorGroupStore
}

func (t *CreateDefaultFlavor) Run() error {
	fgStore, err := t.flvGroupStore()
	if err != nil {
		return err
	}
	for _, fg := range defaultFlavorGroups() {
		_, err := fgStore.Create(&fg)
		if err != nil {
			return errors.Wrap(err, "failed to create default flavor group \""+fg.Name+"\"")
		}
	}
	return nil
}

func (t *CreateDefaultFlavor) Validate() error {
	fgStore, err := t.flvGroupStore()
	if err != nil {
		return err
	}
	for _, n := range defaultFlavorGroupsNames {
		searchFilter := models.FlavorGroupFilterCriteria{
			NameEqualTo: n,
		}
		fgCollection, err := fgStore.Search(&searchFilter)
		if err != nil {
			return errors.Wrap(err, "Failed to validate "+t.commandName)
		}
		if len(fgCollection.Flavorgroups) == 0 {
			return errors.New(t.commandName + ": default flavor \"" + n + "\" not created")
		}
	}
	return nil
}

func (t *CreateDefaultFlavor) PrintHelp(w io.Writer) {
	setup.PrintEnvHelp(w, dbEnvHelpPrompt, "", dbEnvHelp)
	fmt.Fprintln(w, "")
}

func (t *CreateDefaultFlavor) SetName(n, e string) {
	t.commandName = n
}

func (t *CreateDefaultFlavor) flvGroupStore() (*postgres.FlavorGroupStore, error) {
	if t.flvGroupStorePtr == nil {
		conf := postgres.Config{
			Vendor:            constants.DBTypePostgres,
			Host:              t.Host,
			Port:              t.Port,
			User:              t.Username,
			Password:          t.Password,
			Dbname:            t.DBName,
			SslMode:           t.SSLMode,
			SslCert:           t.SSLCert,
			ConnRetryAttempts: t.ConnectionRetryAttempts,
			ConnRetryTime:     t.ConnectionRetryTime,
		}
		dataStore, err := postgres.New(&conf)
		if err != nil {
			return nil, errors.Wrap(err, "failed to connect database")
		}
		t.flvGroupStorePtr = postgres.NewFlavorGroupStore(dataStore)
	}
	if t.flvGroupStorePtr == nil {
		return nil, errors.New("failed to create FlavorGroupStore")
	}
	return t.flvGroupStorePtr, nil
}

func defaultFlavorGroups() []hvs.FlavorGroup {
	var ret []hvs.FlavorGroup
	for _, fgStr := range defaultFlavorGroupsRaw {
		fg := hvs.FlavorGroup{}
		fg.UnmarshalJSON([]byte(fgStr))
		ret = append(ret, fg)
	}
	return ret
}

var defaultFlavorGroupsNames = []string{
	"automatic",
	"platform_software",
	"workload_software",
	"host_unique",
}

var defaultFlavorGroupsRaw = []string{
	`{
		"name": "automatic",
		"flavor_match_policy_collection": {
			"flavor_match_policies": [
				{
					"flavor_part": "PLATFORM",
					"match_policy": {
						"match_type": "ANY_OF",
						"required": "REQUIRED"
					}
				},
				{
					"flavor_part": "OS",
					"match_policy": {
						"match_type": "ANY_OF",
						"required": "REQUIRED"
					}
				},
				{
					"flavor_part": "SOFTWARE",
					"match_policy": {
						"match_type": "ALL_OF",
						"required": "REQUIRED_IF_DEFINED"
					}
				},
				{
					"flavor_part": "ASSET_TAG",
					"match_policy": {
						"match_type": "LATEST",
						"required": "REQUIRED_IF_DEFINED"
					}
				},
				{
					"flavor_part": "HOST_UNIQUE",
					"match_policy": {
						"match_type": "LATEST",
						"required": "REQUIRED_IF_DEFINED"
					}
				}
			]
		}
	}`,
	`{
		"name": "platform_software",
		"flavor_match_policy_collection": {
			"flavor_match_policies": [
				{
					"flavor_part": "SOFTWARE",
					"match_policy": {
						"match_type": "ANY_OF",
						"required": "REQUIRED"
					}
				}
			]
		}
	}`,
	`{
		"name": "workload_software",
		"flavor_match_policy_collection": {
			"flavor_match_policies": [
				{
					"flavor_part": "SOFTWARE",
					"match_policy": {
						"match_type": "ANY_OF",
						"required": "REQUIRED"
					}
				}
			]
		}
	}`,
	`{
		"name": "host_unique"
	}`,
}
