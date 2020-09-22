/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package config

import (
	"os"

	"github.com/intel-secl/intel-secl/v3/pkg/kbs/constants"
	commConfig "github.com/intel-secl/intel-secl/v3/pkg/lib/common/config"
	"github.com/pkg/errors"
	"github.com/spf13/viper"
	"gopkg.in/yaml.v2"
)

type Configuration struct {
	AASApiUrl        string `yaml:"aas-base-url" mapstructure:"aas-base-url"`
	CMSBaseURL       string `yaml:"cms-base-url" mapstructure:"cms-base-url"`
	CmsTlsCertDigest string `yaml:"cms-tls-cert-sha384" mapstructure:"cms-tls-cert-sha384"`

	EndpointURL string `yaml:"endpoint-url" mapstructure:"endpoint-url"`
	KeyManager  string `yaml:"key-manager" mapstructure:"key-manager"`

	TLS    commConfig.TLSCertConfig `yaml:"tls" mapstructure:"tls"`
	Log    commConfig.LogConfig     `yaml:"log" mapstructure:"log"`
	Server commConfig.ServerConfig  `yaml:"server" mapstructure:"server"`

	Kmip KmipConfig `yaml:"kmip" mapstructure:"kmip"`
}

type KmipConfig struct {
	ServerIP   string `yaml:"server-ip" mapstructure:"server-ip"`
	ServerPort string `yaml:"server-port" mapstructure:"server-port"`
	ClientCert string `yaml:"client-cert-path" mapstructure:"client-cert-path"`
	ClientKey  string `yaml:"client-key-path" mapstructure:"client-key-path"`
	RootCert   string `yaml:"root-cert-path" mapstructure:"root-cert-path"`
}

// init sets the configuration file name and type
func init() {
	viper.SetConfigName(constants.ConfigFile)
	viper.SetConfigType("yaml")
	viper.AddConfigPath(".")
}

// LoadConfiguration loads application specific configuration from config.yml
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

// Save saves application specific configuration to config.yml
func (config *Configuration) Save(filename string) error {
	configFile, err := os.Create(filename)
	if err != nil {
		return errors.Wrap(err, "Failed to create config file")
	}
	defer configFile.Close()
	err = yaml.NewEncoder(configFile).Encode(config)
	if err != nil {
		return errors.Wrap(err, "Failed to encode config structure")
	}
	return nil
}
