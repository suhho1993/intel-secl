/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package tasks

import (
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/intel-secl/intel-secl/v3/pkg/hvs/constants"
	"github.com/intel-secl/intel-secl/v3/pkg/hvs/postgres"
	commConfig "github.com/intel-secl/intel-secl/v3/pkg/lib/common/config"
	cos "github.com/intel-secl/intel-secl/v3/pkg/lib/common/os"
	"github.com/intel-secl/intel-secl/v3/pkg/lib/common/setup"
	"github.com/intel-secl/intel-secl/v3/pkg/lib/common/validation"

	"github.com/pkg/errors"
)

type DBSetup struct {
	// embedded structure for holding new configuation
	commConfig.DBConfig
	SSLCertSource string

	// the pointer to configuration structure
	DBConfigPtr   *commConfig.DBConfig
	ConsoleWriter io.Writer

	envPrefix   string
	commandName string
}

// this is only used here, better don't put in constants package
const defaultSSLCertFilePath = constants.ConfigDir + "hvsdbsslcert.pem"

const dbEnvHelpPrompt = "Following environment variables are required for Database related setups:"

var dbEnvHelp = map[string]string{
	"DATABASE_VENDOR":              "Vendor of database",
	"DATABASE_HOST":                "Database host name",
	"DATABASE_PORT":                "Database port",
	"DATABASE_DB_NAME":             "Database name",
	"DATABASE_USERNAME":            "Database username",
	"DATABASE_PASSWORD":            "Database password",
	"DATABASE_SSL_MODE":            "Database SSL mode",
	"DATABASE_SSL_CERT":            "Database SSL certificate",
	"DATABASE_SSL_CERT_SOURCE":     "Database SSL certificate to be copied from",
	"DATABASE_CONN_RETRY_ATTEMPTS": "Database connection retry attempts",
	"DATABASE_CONN_RETRY_TIME":     "Database connection retry time",
}

func (t *DBSetup) Run() error {
	// populates the configuration structure
	if t.DBConfigPtr == nil {
		return errors.New("Pointer to configuration structure can not be nil")
	}
	// validate input values
	if t.Vendor == "" {
		return errors.New("DATABASE_VENDOR is not set")
	}
	if t.Host == "" {
		return errors.New("DATABASE_HOST is not set")
	}
	if t.Port == "" {
		return errors.New("DATABASE_PORT is not set")
	}
	if t.DBName == "" {
		return errors.New("DATABASE_DB_NAME is not set")
	}
	if t.Username == "" {
		return errors.New("DATABASE_USERNAME is not set")
	}
	if t.Password == "" {
		return errors.New("DATABASE_PASSWORD is not set")
	}
	if t.SSLMode == "" {
		t.SSLMode = constants.SslModeAllow
	}
	if t.ConnectionRetryAttempts < 0 {
		t.ConnectionRetryAttempts = constants.DefaultDbConnRetryAttempts
	}
	if t.ConnectionRetryTime < 0 {
		t.ConnectionRetryTime = constants.DefaultDbConnRetryTime
	}
	// set to default value
	if t.SSLCert == "" {
		t.SSLCert = defaultSSLCertFilePath
	}
	t.DBConfigPtr.Vendor = t.Vendor
	t.DBConfigPtr.Host = t.Host
	t.DBConfigPtr.Port = t.Port
	t.DBConfigPtr.DBName = t.DBName
	t.DBConfigPtr.Username = t.Username
	t.DBConfigPtr.Password = t.Password

	t.DBConfigPtr.ConnectionRetryAttempts = t.ConnectionRetryAttempts
	t.DBConfigPtr.ConnectionRetryTime = t.ConnectionRetryTime

	var validErr error
	validErr = validation.ValidateHostname(t.DBConfig.Host)
	if validErr != nil {
		return errors.Wrap(validErr, "setup database: Validation failed on db host")
	}
	validErr = validation.ValidateAccount(t.DBConfig.Username, t.DBConfig.Password)
	if validErr != nil {
		return errors.Wrap(validErr, "setup database: Validation failed on db credentials")
	}
	validErr = validation.ValidateIdentifier(t.DBConfig.DBName)
	if validErr != nil {
		return errors.Wrap(validErr, "setup database: Validation failed on db name")
	}

	t.DBConfigPtr.SSLMode, t.DBConfigPtr.SSLCert, validErr = configureDBSSLParams(
		t.SSLMode, t.SSLCertSource, t.SSLCert)
	if validErr != nil {
		return errors.Wrap(validErr, "setup database: Validation failed on ssl settings")
	}
	return nil
}

func (t *DBSetup) Validate() error {
	fmt.Fprintln(t.ConsoleWriter, "Validating DB args")
	// check if SSL certificate exists
	if t.DBConfigPtr == nil {
		return errors.New("Pointer to configuration structure can not be nil")
	}
	if t.DBConfigPtr.SSLMode == constants.SslModeVerifyCa ||
		t.DBConfigPtr.SSLMode == constants.SslModeVerifyFull {
		_, err := os.Stat(t.SSLCert)
		return err
	}
	fmt.Fprintln(t.ConsoleWriter, "Connecting to DB and create schemas")
	// Create conf for DBTypePostgres
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
	// test connection and create schemas
	dataStore, err := postgres.New(&conf)
	if err != nil {
		return errors.Wrap(err, "Failed to connect database")
	}
	err = dataStore.Migrate()
	if err != nil {
		return errors.Wrap(err, "Failed to create database tables")
	}
	return nil
}

func (t *DBSetup) PrintHelp(w io.Writer) {
	setup.PrintEnvHelp(w, dbEnvHelpPrompt, t.envPrefix, dbEnvHelp)
	fmt.Fprintln(w, "")
}

func (t *DBSetup) SetName(n, e string) {
	t.commandName = n
	t.envPrefix = prefixUnderscroll(e)
}

func configureDBSSLParams(sslMode, sslCertSrc, sslCert string) (string, string, error) {
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
			sslCert = defaultSSLCertFilePath
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

func prefixUnderscroll(e string) string {
	if e != "" &&
		!strings.HasSuffix(e, "_") {
		e += "_"
	}
	return e
}
