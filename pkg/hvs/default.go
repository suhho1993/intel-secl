/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package hvs

import (
	"github.com/intel-secl/intel-secl/v3/pkg/hvs/config"
	"github.com/intel-secl/intel-secl/v3/pkg/hvs/constants"
	"github.com/intel-secl/intel-secl/v3/pkg/hvs/services/hrrs"
	commConfig "github.com/intel-secl/intel-secl/v3/pkg/lib/common/config"
	"github.com/spf13/viper"
)

const (
	fvsNumberOfVerifiers    = "fvs-number-of-verifiers"
	fvsNumberOfDataFetchers = "fvs-number-of-data-fetchers"
	hrrsRefreshPeriod       = "hrrs-refresh-period"
	hrrsRefreshLookAhead    = "hrrs-refresh-look-ahead"
)

// this func sets the default values for viper keys
func init() {
	// set default values for tls
	viper.SetDefault("tls-cert-file", constants.DefaultTLSCertFile)
	viper.SetDefault("tls-key-file", constants.DefaultTLSKeyFile)
	viper.SetDefault("tls-common-name", constants.DefaultHvsTlsCn)
	viper.SetDefault("tls-san-list", constants.DefaultHvsTlsSan)

	// set default values for all other certs
	viper.SetDefault("saml-cert-file", constants.SAMLCertFile)
	viper.SetDefault("saml-key-file", constants.SAMLKeyFile)
	viper.SetDefault("saml-common-name", constants.DefaultCN)

	viper.SetDefault("flavor-signing-cert-file", constants.FlavorSigningCertFile)
	viper.SetDefault("flavor-signing-key-file", constants.FlavorSigningKeyFile)
	viper.SetDefault("flavor-signing-common-name", constants.DefaultCN)

	viper.SetDefault("privacy-ca-cert-file", constants.PrivacyCACertFile)
	viper.SetDefault("privacy-ca-key-file", constants.PrivacyCAKeyFile)
	viper.SetDefault("privacy-ca-common-name", constants.DefaultCN)
	viper.SetDefault("privacy-ca-issuer", constants.DefaultCertIssuer)
	viper.SetDefault("privacy-ca-validity-days", constants.DefaultCertValidity)

	viper.SetDefault("endorsement-ca-cert-file", constants.SelfEndorsementCACertFile)
	viper.SetDefault("endorsement-ca-key-file", constants.EndorsementCAKeyFile)
	viper.SetDefault("endorsement-ca-common-name", constants.DefaultCN)
	viper.SetDefault("endorsement-ca-issuer", constants.DefaultCertIssuer)
	viper.SetDefault("endorsement-ca-validity-days", constants.DefaultCertValidity)

	viper.SetDefault("tag-ca-cert-file", constants.TagCACertFile)
	viper.SetDefault("tag-ca-key-file", constants.TagCAKeyFile)
	viper.SetDefault("tag-ca-common-name", constants.DefaultCN)
	viper.SetDefault("tag-ca-issuer", constants.DefaultCertIssuer)
	viper.SetDefault("tag-ca-validity-days", constants.DefaultCertValidity)

	// set default values for log
	viper.SetDefault("log-max-length", constants.DefaultLogEntryMaxlength)
	viper.SetDefault("log-enable-stdout", true)
	viper.SetDefault("log-level", "info")

	// set default values for privacy ca
	viper.SetDefault("privacy-ca-cert-validity", constants.DefaultPrivacyCACertValidity)
	viper.SetDefault("privacy-ca-id-issuer", constants.DefaultPrivacyCaIdentityIssuer)

	// set default values for server
	viper.SetDefault("server-port", constants.DefaultHVSListenerPort)
	viper.SetDefault("server-read-timeout", constants.DefaultReadTimeout)
	viper.SetDefault("server-read-header-timeout", constants.DefaultReadHeaderTimeout)
	viper.SetDefault("server-write-timeout", constants.DefaultWriteTimeout)
	viper.SetDefault("server-idle-timeout", constants.DefaultIdleTimeout)
	viper.SetDefault("server-max-header-bytes", constants.DefaultMaxHeaderBytes)

	// set default for database ssl certificate
	viper.SetDefault("database-db-vendor", "postgres")
	viper.SetDefault("database-db-host", "localhost")
	viper.SetDefault("database-db-port", "5432")
	viper.SetDefault("database-db-name", "hvs_db")
	viper.SetDefault("database-ssl-mode", constants.SslModeVerifyFull)
	viper.SetDefault("database-ssl-cert", constants.ConfigDir+"hvsdbsslcert.pem")
	viper.SetDefault("database-conn-retry-attempts", constants.DefaultDbConnRetryAttempts)
	viper.SetDefault("database-conn-retry-time", constants.DefaultDbConnRetryTime)

	// set default for fvs
	viper.SetDefault(fvsNumberOfVerifiers, constants.DefaultFvsNumberOfVerifiers)
	viper.SetDefault(fvsNumberOfDataFetchers, constants.DefaultFvsNumberOfDataFetchers)

	// set default for saml
	viper.SetDefault("saml-issuer-name", constants.DefaultSamlCertIssuer)
	viper.SetDefault("saml-validity-days", constants.DefaultSamlCertValidity)

	viper.SetDefault(hrrsRefreshPeriod, hrrs.DefaultRefreshPeriod)
	viper.SetDefault(hrrsRefreshLookAhead, hrrs.DefaultRefreshLookAhead)
}

func defaultConfig() *config.Configuration {
	return &config.Configuration{
		AASApiUrl:        viper.GetString("aas-base-url"),
		CMSBaseURL:       viper.GetString("cms-base-url"),
		CmsTlsCertDigest: viper.GetString("cms-tls-cert-sha384"),
		HVS: config.HVSConfig{
			Username: viper.GetString("hvs-username"),
			Password: viper.GetString("hvs-password"),
			Dek:      viper.GetString("hvs-data-encryption-key"),
		},
		TLS: commConfig.TLSCertConfig{
			CertFile:   viper.GetString("tls-cert-file"),
			KeyFile:    viper.GetString("tls-key-file"),
			CommonName: viper.GetString("tls-common-name"),
			SANList:    viper.GetString("tls-san-list"),
		},
		SAML: config.SAMLConfig{
			CommonConfig: commConfig.SigningCertConfig{
				CertFile:   viper.GetString("saml-cert-file"),
				KeyFile:    viper.GetString("saml-key-file"),
				CommonName: viper.GetString("saml-common-name"),
			},
			Issuer:       viper.GetString("saml-issuer-name"),
			ValidityDays: viper.GetInt("saml-validity-days"),
		},
		FlavorSigning: commConfig.SigningCertConfig{
			CertFile:   viper.GetString("flavor-signing-cert-file"),
			KeyFile:    viper.GetString("flavor-signing-key-file"),
			CommonName: viper.GetString("flavor-signing-common-name"),
		},
		PrivacyCA: commConfig.SelfSignedCertConfig{
			CertFile:     viper.GetString("privacy-ca-cert-file"),
			KeyFile:      viper.GetString("privacy-ca-key-file"),
			CommonName:   viper.GetString("privacy-ca-common-name"),
			Issuer:       viper.GetString("privacy-ca-issuer"),
			ValidityDays: viper.GetInt("privacy-ca-validity-days"),
		},
		EndorsementCA: commConfig.SelfSignedCertConfig{
			CertFile:     viper.GetString("endorsement-ca-cert-file"),
			KeyFile:      viper.GetString("endorsement-ca-key-file"),
			CommonName:   viper.GetString("endorsement-ca-common-name"),
			Issuer:       viper.GetString("endorsement-ca-issuer"),
			ValidityDays: viper.GetInt("endorsement-ca-validity-days"),
		},
		TagCA: commConfig.SelfSignedCertConfig{
			CertFile:     viper.GetString("tag-ca-cert-file"),
			KeyFile:      viper.GetString("tag-ca-key-file"),
			CommonName:   viper.GetString("tag-ca-common-name"),
			Issuer:       viper.GetString("tag-ca-issuer"),
			ValidityDays: viper.GetInt("tag-ca-validity-days"),
		},
		Log: commConfig.LogConfig{
			MaxLength:    viper.GetInt("log-max-length"),
			EnableStdout: viper.GetBool("log-enable-stdout"),
			Level:        viper.GetString("log-level"),
		},
		Server: commConfig.ServerConfig{
			Port:              viper.GetInt("server-port"),
			ReadTimeout:       viper.GetDuration("server-read-timeout"),
			ReadHeaderTimeout: viper.GetDuration("server-read-header-timeout"),
			WriteTimeout:      viper.GetDuration("server-write-timeout"),
			IdleTimeout:       viper.GetDuration("server-idle-timeout"),
			MaxHeaderBytes:    viper.GetInt("server-max-header-bytes"),
		},
		DB: commConfig.DBConfig{
			Vendor:                  viper.GetString("database-vendor"),
			Host:                    viper.GetString("database-host"),
			Port:                    viper.GetString("database-port"),
			DBName:                  viper.GetString("database-db-name"),
			Username:                viper.GetString("database-username"),
			Password:                viper.GetString("database-password"),
			SSLMode:                 viper.GetString("database-ssl-mode"),
			ConnectionRetryAttempts: viper.GetInt("database-conn-retry-attempts"),
			ConnectionRetryTime:     viper.GetInt("database-conn-retry-time"),
		},
		HRRS: hrrs.HRRSConfig{
			RefreshPeriod:    viper.GetDuration(hrrsRefreshPeriod),
			RefreshLookAhead: viper.GetDuration(hrrsRefreshLookAhead),
		},
		FVS: config.FVSConfig{
			NumberOfVerifiers:    viper.GetInt(fvsNumberOfVerifiers),
			NumberOfDataFetchers: viper.GetInt(fvsNumberOfDataFetchers),
		},
	}
}
