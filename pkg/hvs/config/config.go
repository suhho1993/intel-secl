/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package config

import (
	"errors"
	"github.com/intel-secl/intel-secl/v3/pkg/hvs/constants"
	commLog "github.com/intel-secl/intel-secl/v3/pkg/lib/common/log"
	"github.com/intel-secl/intel-secl/v3/pkg/lib/common/setup"
	"os"
	"path"
	"strconv"
	"strings"
	"sync"
	"time"

	errorLog "github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	"gopkg.in/yaml.v2"
)

// should move this into lib common, as its duplicated across HVS and HVS

// Configuration is the global configuration struct that is marshalled/unmarshaled to a persisted yaml file
// Probably should embed a config generic struct
type Configuration struct {
	configFile       string
	Port             int
	CmsTlsCertDigest string
	Postgres         struct {
		DBName            string
		Username          string
		Password          string
		Hostname          string
		Port              int
		SSLMode           string
		SSLCert           string
		ConnRetryAttempts int
		ConnRetryTime     int
	}
	LogMaxLength    int
	LogEnableStdout bool
	LogLevel        logrus.Level

	CMSBaseUrl string
	AASApiUrl  string
	Subject    struct {
		TLSCertCommonName string
	}
	HVS struct {
		User     string
		Password string
	}
	TLSKeyFile        string
	TLSCertFile       string
	CertSANList       string
	ReadTimeout       time.Duration
	ReadHeaderTimeout time.Duration
	WriteTimeout      time.Duration
	IdleTimeout       time.Duration
	MaxHeaderBytes    int
}

var mu sync.Mutex

var global *Configuration

var log = commLog.GetDefaultLogger()

func Global() *Configuration {
	if global == nil {
		global = Load(path.Join(constants.ConfigDir, constants.ConfigFile))
	}
	return global
}

var ErrNoConfigFile = errors.New("no config file")

func (conf *Configuration) SaveConfiguration(c setup.Context) error {
	log.Trace("config/config:SaveConfiguration() Entering")
	defer log.Trace("config/config:SaveConfiguration() Leaving")
	var err error = nil

	vsPort, err := c.GetenvInt("HVS_PORT", "HVS Listener Port")
	if err == nil && vsPort > 0 {
		conf.Port = vsPort
	} else if conf.Port <= 0 {
		conf.Port = constants.DefaultHVSListenerPort
		log.Info("config/config:SaveConfiguration() HVS_PORT not defined, using default value: ", constants.DefaultHVSListenerPort)
	}

	tlsCertDigest, err := c.GetenvString(constants.CmsTlsCertDigestEnv, "TLS certificate digest")
	if err == nil && tlsCertDigest != "" {
		conf.CmsTlsCertDigest = tlsCertDigest
	} else if conf.CmsTlsCertDigest == "" {
		log.Error("CMS_TLS_CERT_SHA384 is not defined in environment")
		return errorLog.Wrap(errors.New("CMS_TLS_CERT_SHA384 is not defined in environment"), "config/config:SaveConfiguration() ENV variable not found")
	}

	cmsBaseUrl, err := c.GetenvString(constants.CmsBaseUrlEnv, "CMS Base URL")
	if err == nil && cmsBaseUrl != "" {
		conf.CMSBaseUrl = cmsBaseUrl
	} else if conf.CMSBaseUrl == "" {
		log.Error("CMS_BASE_URL is not defined in environment")
		return errorLog.Wrap(errors.New("CMS_BASE_URL is not defined in environment"), "config/config:SaveConfiguration() ENV variable not found")
	}

	aasAPIUrl, err := c.GetenvString(constants.AasApiUrlEnv, "AAS API URL")
	if err == nil && aasAPIUrl != "" {
		conf.AASApiUrl = aasAPIUrl
	} else if conf.AASApiUrl == "" {
		log.Error("AAS_API_URL is not defined in environment")
		return errorLog.Wrap(errors.New("AAS_API_URL is not defined in environment"), "config/config:SaveConfiguration() ENV variable not found")
	}

	vsAASUser, err := c.GetenvString(constants.HvsServiceUsernameEnv, "HVS Service Username")
	if err == nil && vsAASUser != "" {
		conf.HVS.User = vsAASUser
	} else if conf.HVS.User == "" {
		log.Error("HVS_SERVICE_USERNAME is not defined in environment")
		return errorLog.Wrap(errors.New("HVS_SERVICE_USERNAME is not defined in environment"),  "config/config:SaveConfiguration() ENV variable not found")
	}

	vsAASPassword, err := c.GetenvSecret(constants.HvsServicePasswordEnv, "HVS Service Password")
	if err == nil && vsAASPassword != "" {
		conf.HVS.Password = vsAASPassword
	} else if strings.TrimSpace(conf.HVS.Password) == "" {
		log.Error("HVS_SERVICE_PASSWORD is not defined in environment")
		return errorLog.Wrap(errors.New("HVS_SERVICE_PASSWORD is not defined in environment"), "config/config:SaveConfiguration() ENV variable not found")
	}

	if conf.TLSKeyFile == "" {
		conf.TLSKeyFile = constants.DefaultTLSKeyPath
	}

	if conf.TLSCertFile == "" {
		conf.TLSCertFile = constants.DefaultTLSCertPath
	}

	tlsCertCN, err := c.GetenvString("HVS_TLS_CERT_CN", "HVS TLS Certificate Common Name")
	if err == nil && tlsCertCN != "" {
		conf.Subject.TLSCertCommonName = tlsCertCN
	} else if conf.Subject.TLSCertCommonName == "" {
		conf.Subject.TLSCertCommonName = constants.DefaultHvsTlsCn
	}

	sanList, err := c.GetenvString("SAN_LIST", "SAN list for TLS")
	if err == nil && sanList != "" {
		conf.CertSANList = sanList
	} else if conf.CertSANList == "" {
		conf.CertSANList = constants.DefaultHvsTlsSan
	}

	ll, err := c.GetenvString("HVS_LOGLEVEL", "Logging Level")
	if err != nil {
		if conf.LogLevel.String() == "" {
			log.Infof("config/config:SaveConfiguration() %s not defined, using default log level: Info", "HVS_LOGLEVEL")
			conf.LogLevel = logrus.InfoLevel
		}
	} else {
		llp, err := logrus.ParseLevel(ll)
		if err != nil {
			log.Info("config/config:SaveConfiguration() Invalid log level specified in env, using default log level: Info")
			conf.LogLevel = logrus.InfoLevel
		} else {
			conf.LogLevel = llp
			log.Infof("config/config:SaveConfiguration() Log level set %s\n", ll)
		}
	}

	logMaxLen, err := c.GetenvInt("HVS_LOG_MAX_LENGTH", "Maximum length of each entry in a log")
	if err == nil && logMaxLen >= 300 {
		conf.LogMaxLength = logMaxLen
	} else {
		log.Info("config/config:SaveConfiguration() Invalid Log Entry Max Length defined (should be >= ", constants.DefaultLogEntryMaxlength, "), using default value:", constants.DefaultLogEntryMaxlength)
		conf.LogMaxLength = constants.DefaultLogEntryMaxlength
	}

	readTimeout, err := c.GetenvInt("HVS_SERVER_READ_TIMEOUT", "HVS Read Timeout")
	if err != nil {
		conf.ReadTimeout = constants.DefaultReadTimeout
	} else {
		conf.ReadTimeout = time.Duration(readTimeout) * time.Second
	}

	readHeaderTimeout, err := c.GetenvInt("HVS_SERVER_READ_HEADER_TIMEOUT", "HVS Read Header Timeout")
	if err != nil {
		conf.ReadHeaderTimeout = constants.DefaultReadHeaderTimeout
	} else {
		conf.ReadHeaderTimeout = time.Duration(readHeaderTimeout) * time.Second
	}

	writeTimeout, err := c.GetenvInt("HVS_SERVER_WRITE_TIMEOUT", "HVS Write Timeout")
	if err != nil {
		conf.WriteTimeout = constants.DefaultWriteTimeout
	} else {
		conf.WriteTimeout = time.Duration(writeTimeout) * time.Second
	}

	idleTimeout, err := c.GetenvInt("HVS_SERVER_IDLE_TIMEOUT", "HVS Idle Timeout")
	if err != nil {
		conf.IdleTimeout = constants.DefaultIdleTimeout
	} else {
		conf.IdleTimeout = time.Duration(idleTimeout) * time.Second
	}

	maxHeaderBytes, err := c.GetenvInt("HVS_SERVER_MAX_HEADER_BYTES", "HVS Max Header Bytes Timeout")
	if err != nil {
		conf.MaxHeaderBytes = constants.DefaultMaxHeaderBytes
	} else {
		conf.MaxHeaderBytes = maxHeaderBytes
	}

	conf.LogEnableStdout = false
	logEnableStdout, err := c.GetenvString("HVS_ENABLE_CONSOLE_LOG", "HVS enable standard output")
	if err == nil && logEnableStdout != "" {
		conf.LogEnableStdout, err = strconv.ParseBool(logEnableStdout)
		if err != nil {
			log.Info("Error while parsing the variable ", "HVS_ENABLE_CONSOLE_LOG", " setting to default value false")
		}
	}

	return conf.Save()

}

func (conf *Configuration) Save() error {
	if conf.configFile == "" {
		return ErrNoConfigFile
	}
	file, err := os.OpenFile(conf.configFile, os.O_RDWR, 0)
	if err != nil {
		// we have an error
		if os.IsNotExist(err) {
			// error is that the config doesnt yet exist, create it
			file, err = os.Create(conf.configFile)
			os.Chmod(conf.configFile, 0640)
			if err != nil {
				return err
			}
		} else {
			// someother I/O related error
			return err
		}
	}
	defer file.Close()
	return yaml.NewEncoder(file).Encode(conf)
}

func Load(path string) *Configuration {
	var c Configuration
	file, err := os.Open(path)
	if err == nil {
		defer file.Close()
		yaml.NewDecoder(file).Decode(&c)
	} else {
		// file doesnt exist, create a new blank one
		c.LogLevel = logrus.InfoLevel
	}

	c.configFile = path
	return &c
}
