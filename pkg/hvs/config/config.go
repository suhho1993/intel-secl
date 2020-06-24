/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package config

import (
	"os"

	"github.com/intel-secl/intel-secl/v3/pkg/hvs/constants"
	commConfig "github.com/intel-secl/intel-secl/v3/pkg/lib/common/config"
	"github.com/pkg/errors"
	"github.com/spf13/viper"
	"gopkg.in/yaml.v2"
)

type HVSConfig struct {
	Username string `yaml:"username" mapstructure:"username"`
	Password string `yaml:"password" mapstructure:"password"`
}

type Configuration struct {
	AASApiUrl        string `yaml:"aas-base-url" mapstructure:"aas-base-url"`
	CMSBaseURL       string `yaml:"cms-base-url" mapstructure:"cms-base-url"`
	CmsTlsCertDigest string `yaml:"cms-tls-cert-sha384" mapstructure:"cms-tls-cert-sha384"`

	HVS HVSConfig `yaml:"hvs" mapstructure:"hvs"`

	TLS           commConfig.CertConfig `yaml:"tls" mapstructure:"tls"`
	SAML          commConfig.CertConfig `yaml:"saml" mapstructure:"saml"`
	FlavorSigning commConfig.CertConfig `yaml:"flavor-signing" mapstructure:"flavor-signing"`

	PrivacyCA     commConfig.CertConfig `yaml:"privacy-ca" mapstructure:"privacy-ca"`
	EndorsementCA commConfig.CertConfig `yaml:"endorsement-ca" mapstructure:"endorsement-ca"`
	TagCA         commConfig.CertConfig `yaml:"tag-ca" mapstructure:"tag-ca"`

	Server commConfig.ServerConfig `yaml:"server" mapstructure:"server"`
	Log    commConfig.LogConfig    `yaml:"log" mapstructure:"log"`
	DB     commConfig.DBConfig     `yaml:"database" mapstructure:"database"`
}

// this function sets the configure file name and type
func init() {
	viper.SetConfigName(constants.ConfigFile)
	viper.SetConfigType("yaml")
	viper.AddConfigPath(".")
}

// config is application specific
func LoadConfiguration() (*Configuration, error) {
	ret := Configuration{}
	// Find and read the config file
	if err := viper.ReadInConfig(); err != nil {
		if _, ok := err.(viper.ConfigFileNotFoundError); ok {
			// Config file not found
			return &ret, errors.Wrap(err, "Config file not found")
		}
		return &ret, errors.Wrap(err, "Failed to load config")
	}
	if err := viper.Unmarshal(&ret); err != nil {
		return &ret, errors.Wrap(err, "Failed to unmarshal config")
	}
	return &ret, nil
}

func (c *Configuration) Save(filename string) error {
	configFile, err := os.Create(filename)
	if err != nil {
		return errors.Wrap(err, "Failed to create config file")
	}
	defer configFile.Close()
	err = yaml.NewEncoder(configFile).Encode(c)
	if err != nil {
		return errors.Wrap(err, "Failed to encode config structure")
	}
	return nil
}
