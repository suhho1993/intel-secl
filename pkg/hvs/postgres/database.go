/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package postgres

import (
	"github.com/intel-secl/intel-secl/v3/pkg/hvs/config"
	"github.com/intel-secl/intel-secl/v3/pkg/hvs/constants"
	"github.com/pkg/errors"
)

func InitDatabase(cfg *config.Configuration) *DataStore {
	defaultLog.Trace("postgres/database:InitDatabase() Entering")
	defer defaultLog.Trace("postgres/database:InitDatabase() Leaving")

	// Create conf for DBTypePostgres
	conf := Config{
		Vendor:            constants.DBTypePostgres,
		Host:              cfg.DB.Host,
		Port:              cfg.DB.Port,
		User:              cfg.DB.Username,
		Password:          cfg.DB.Password,
		Dbname:            cfg.DB.DBName,
		SslMode:           cfg.DB.SSLMode,
		SslCert:           cfg.DB.SSLCert,
		ConnRetryAttempts: cfg.DB.ConnectionRetryAttempts,
		ConnRetryTime:     cfg.DB.ConnectionRetryTime,
	}

	// Creates a DBTypePostgres DB instance
	dataStore, err := NewDataStore(&conf)
	if err != nil {
		panic(err)
	}
	defaultLog.Info("Migrating Database")
	dataStore.Migrate()

	return dataStore
}

func NewDataStore(config *Config) (*DataStore, error) {
	if config.Vendor == constants.DBTypePostgres {
		return New(config)
	}
	return nil, errors.Errorf("Unsupported database vendor")
}
