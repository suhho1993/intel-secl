/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package tasks

import (
	"flag"
	"fmt"
	"github.com/intel-secl/intel-secl/v3/pkg/hvs/config"
	"github.com/intel-secl/intel-secl/v3/pkg/hvs/constants"
	"github.com/intel-secl/intel-secl/v3/pkg/hvs/postgres"
	"github.com/intel-secl/intel-secl/v3/pkg/hvs/router"
	cos "github.com/intel-secl/intel-secl/v3/pkg/lib/common/os"
	"github.com/intel-secl/intel-secl/v3/pkg/lib/common/setup"
	"github.com/intel-secl/intel-secl/v3/pkg/lib/common/validation"
	"io"
	"os"
	"strconv"
	"strings"

	"github.com/pkg/errors"
)

type Database struct {
	Flags         []string
	Config        *config.Configuration
	ConsoleWriter io.Writer
}

func (db Database) Run(c setup.Context) error {
	defaultLog.Trace("tasks/database:Run() Entering")
	defer defaultLog.Trace("tasks/database:Run() Leaving")

	fmt.Fprintln(db.ConsoleWriter, "Running database setup...")

	envHost, _ := c.GetenvString("HVS_DB_HOSTNAME", "Database Hostname")
	envPort, _ := c.GetenvInt("HVS_DB_PORT", "Database Port")
	envUser, _ := c.GetenvString("HVS_DB_USERNAME", "Database Username")
	envPass, _ := c.GetenvSecret("HVS_DB_PASSWORD", "Database Password")
	envDB, _ := c.GetenvString("HVS_DB_NAME", "Database Name")
	envDBSSLMode, _ := c.GetenvString("HVS_DB_SSLMODE", "Database SSLMode")
	envDBSSLCert, _ := c.GetenvString("HVS_DB_SSLCERT", "Database SSL Certificate")
	envDBSSLCertSrc, _ := c.GetenvString("HVS_DB_SSLCERTSRC", "Database SSL Cert file source file")

	fs := flag.NewFlagSet("database", flag.ContinueOnError)
	fs.StringVar(&db.Config.Postgres.Hostname, "db-host", envHost, "Database Hostname")
	fs.IntVar(&db.Config.Postgres.Port, "db-port", envPort, "Database Port")
	fs.StringVar(&db.Config.Postgres.Username, "db-user", envUser, "Database Username")
	fs.StringVar(&db.Config.Postgres.Password, "db-pass", envPass, "Database Password")
	fs.StringVar(&db.Config.Postgres.DBName, "db-name", envDB, "Database Name")
	fs.StringVar(&db.Config.Postgres.SSLMode, "db-sslmode", envDBSSLMode, "SSL mode of connection to database")
	fs.StringVar(&db.Config.Postgres.SSLCert, "db-sslcert", envDBSSLCert, "SSL certificate of database")
	fs.StringVar(&envDBSSLCertSrc, "db-sslcertsrc", envDBSSLCertSrc, "DB SSL certificate to be copied from")
	err := fs.Parse(db.Flags)
	if err != nil {
		return errors.Wrap(err, "setup database: failed to parse cmd flags")
	}

	var validErr error

	validErr = validation.ValidateHostname(db.Config.Postgres.Hostname)
	if validErr != nil {
		return errors.Wrap(validErr, "setup database: Validation fail")
	}
	validErr = validation.ValidateAccount(db.Config.Postgres.Username, db.Config.Postgres.Password)
	if validErr != nil {
		return errors.Wrap(validErr, "setup database: Validation fail")
	}
	validErr = validation.ValidateIdentifier(db.Config.Postgres.DBName)
	if validErr != nil {
		return errors.Wrap(validErr, "setup database: Validation fail")
	}

	db.Config.Postgres.SSLMode, db.Config.Postgres.SSLCert, validErr = configureDBSSLParams(
		db.Config.Postgres.SSLMode, envDBSSLCertSrc,
		db.Config.Postgres.SSLCert)
	if validErr != nil {
		return errors.Wrap(validErr, "setup database: Validation fail")
	}

	db.Config.Postgres.ConnRetryAttempts = constants.DefaultDbConnRetryAttempts
	db.Config.Postgres.ConnRetryTime = constants.DefaultDbConnRetryTime
	pg := db.Config.Postgres
	p, err := router.NewDataStore(&postgres.Config{
		Vendor:            constants.DBTypePostgres,
		Host:              pg.Hostname,
		Port:              strconv.Itoa(pg.Port),
		Dbname:            pg.DBName,
		User:              pg.Username,
		Password:          pg.Password,
		SslMode:           pg.SSLMode,
		SslCert:           pg.SSLCert,
		ConnRetryAttempts: pg.ConnRetryAttempts,
		ConnRetryTime:     pg.ConnRetryTime,
	})
	if err != nil {
		return errors.Wrap(err, "setup database: failed to open database")
	}
	p.Migrate()

	err = db.Config.Save()
	if err != nil {
		return errors.Wrap(err, "setup database: failed to save config")
	}
	return nil
}

func configureDBSSLParams(sslMode, sslCertSrc, sslCert string) (string, string, error) {
	defaultLog.Trace("tasks/database:configureDBSSLParams() Entering")
	defer defaultLog.Trace("tasks/database:configureDBSSLParams() Leaving")

	sslMode = strings.TrimSpace(strings.ToLower(sslMode))
	sslCert = strings.TrimSpace(sslCert)
	sslCertSrc = strings.TrimSpace(sslCertSrc)

	if sslMode != constants.SslModeAllow && sslMode != constants.SslModePrefer &&
		sslMode != constants.SslModeVerifyCa && sslMode != constants.SslModeRequire {
		sslMode = constants.SslModeVerifyFull
	}

	if sslMode == constants.SslModeVerifyCa || sslMode == constants.SslModeVerifyFull {
		// cover different scenarios
		if sslCertSrc == "" && sslCert != "" {
			if _, err := os.Stat(sslCert); os.IsNotExist(err) {
				return "", "", errors.Wrapf(err, "certificate source file not specified and sslcert %s does not exist", sslCert)
			}
			return sslMode, sslCert, nil
		}
		if sslCertSrc == "" {
			return "", "", errors.New("verify-ca or verify-full needs a source cert file to copy from unless db-sslcert exists")
		} else {
			if _, err := os.Stat(sslCertSrc); os.IsNotExist(err) {
				return "", "", errors.Wrapf(err, "certificate source file not specified and sslcert %s does not exist", sslCertSrc)
			}
		}
		// at this point if sslCert destination is not passed it, lets set to default
		if sslCert == "" {
			sslCert = constants.DefaultSSLCertFilePath
		}
		// lets try to copy the file now. If copy does not succeed return the file copy error
		if err := cos.Copy(sslCertSrc, sslCert); err != nil {
			return "", "", errors.Wrap(err, "failed to copy file")
		}
		// set permissions so that non root users can read the copied file
		if err := os.Chmod(sslCert, 0644); err != nil {
			return "", "", errors.Wrapf(err, "could not apply permissions to %s", sslCert)
		}
	}
	return sslMode, sslCert, nil
}

func (db Database) Validate(c setup.Context) error {
	defaultLog.Trace("tasks/database:Validate() Entering")
	defer defaultLog.Trace("tasks/database:Validate() Leaving")

	if db.Config.Postgres.Hostname == "" {
		return errors.New("Hostname is not set")
	}
	if db.Config.Postgres.Port == 0 {
		return errors.New("Port is not set")
	}
	if db.Config.Postgres.Username == "" {
		return errors.New("Username is not set")
	}
	if db.Config.Postgres.Password == "" {
		return errors.New("Password is not set")
	}
	if db.Config.Postgres.DBName == "" {
		return errors.New("Schema is not set")
	}
	return nil
}
