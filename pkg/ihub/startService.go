/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package ihub

import (
	"encoding/pem"
	"github.com/intel-secl/intel-secl/v3/pkg/clients/k8s"
	"github.com/intel-secl/intel-secl/v3/pkg/clients/openstack"
	"github.com/intel-secl/intel-secl/v3/pkg/lib/common/crypt"
	"io/ioutil"
	"net/url"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/intel-secl/intel-secl/v3/pkg/ihub/constants"
	"github.com/intel-secl/intel-secl/v3/pkg/ihub/k8splugin"
	"github.com/intel-secl/intel-secl/v3/pkg/ihub/openstackplugin"
	"github.com/pkg/errors"

	commLog "github.com/intel-secl/intel-secl/v3/pkg/lib/common/log"
	commLogMsg "github.com/intel-secl/intel-secl/v3/pkg/lib/common/log/message"
)

var log = commLog.GetDefaultLogger()
var secLog = commLog.GetSecurityLogger()

func (app *App) startDaemon() error {

	log.Trace("startService:startDaemon() Entering")
	defer log.Trace("startService:startDaemon() Leaving")

	configuration := app.configuration()
	if configuration == nil {
		return errors.New("Failed to load configuration")
	}
	app.configureLogs(configuration.Log.EnableStdout, true)

	if configuration.IHUB.PollIntervalMinutes < constants.PollingIntervalMinutes {
		secLog.Infof("startService:startDaemon() POLL_INTERVAL_MINUTES value is less than %v mins. Setting it to " +
			"%v mins", constants.PollingIntervalMinutes, constants.PollingIntervalMinutes)
		configuration.IHUB.PollIntervalMinutes = constants.PollingIntervalMinutes
	}

	var k k8splugin.KubernetesDetails
	var o openstackplugin.OpenstackDetails

	if configuration.Endpoint.Type == constants.OpenStackTenant {

		o.Config = configuration
		authURL := o.Config.Endpoint.AuthURL
		apiURL := o.Config.Endpoint.URL
		userName := o.Config.Endpoint.UserName
		password := o.Config.Endpoint.Password

		authUrl, err := url.Parse(authURL)
		if err != nil {
			return errors.Wrap(err, "startService:startDaemon() unable to parse OpenStack auth url")
		}

		apiUrl, err := url.Parse(apiURL)
		if err != nil {
			return errors.Wrap(err, "startService:startDaemon() unable to parse OpenStack api url")
		}

		openstackClient, err := openstack.NewOpenstackClient(authUrl, apiUrl, userName, password)
		if err != nil {
			return errors.Wrap(err, "startService:startDaemon() Error in initializing the OpenStack client")
		}
		o.OpenstackClient = openstackClient
	} else {

		privateKey, err := crypt.GetPrivateKeyFromPKCS8File(constants.PrivatekeyLocation)
		if err != nil {
			return errors.Wrap(err, "startService:startDaemon() Error in reading the ihub private key from file")
		}
		k.PrivateKey = privateKey

		publicKeyBytes, err := ioutil.ReadFile(constants.PublickeyLocation)
		if err != nil {
			return errors.Wrap(err, "startService:startDaemon() : Error in reading the ihub public key from file")
		}

		block, _ := pem.Decode(publicKeyBytes)
		if block == nil || block.Type != "PUBLIC KEY" {
			return errors.New("startService:startDaemon() : Error while decoding ihub certificate in pem format")
		}
		k.PublicKeyBytes = block.Bytes

		k.Config = configuration
		apiURL := k.Config.Endpoint.URL
		token := k.Config.Endpoint.Token
		certFile := k.Config.Endpoint.CertFile

		apiUrl, err := url.Parse(apiURL)
		if err != nil {
			return errors.Wrap(err, "startService:startDaemon() Unable to parse Kubernetes api url")
		}

		k8sClient, err := k8s.NewK8sClient(apiUrl, token, certFile)
		if err != nil {
			return errors.Wrap(err, "startService:startDaemon() Error in initializing the Kubernetes client")
		}
		k.K8sClient = k8sClient
	}

	// Setup signal handlers to gracefully handle termination
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)

	tick := time.NewTicker(time.Minute * time.Duration(configuration.IHUB.PollIntervalMinutes))
	go func() {
		secLog.Infof("startService:startDaemon() Scheduler will start at : %v", time.Now().Local().Add(
			time.Minute*time.Duration(configuration.IHUB.PollIntervalMinutes)))
		for t := range tick.C {
			log.Debugf("startService:startDaemon() The Endpoint is : %s", configuration.Endpoint.Type)
			secLog.Debugf("startService:startDaemon() Scheduler started at : %v", t)

			if configuration.Endpoint.Type == constants.OpenStackTenant {
				err := openstackplugin.SendDataToEndPoint(o)
				if err != nil {
					log.WithError(err).Error("startService:startDaemon() Error in pushing OpenStack traits")
				}
			} else {
				err := k8splugin.SendDataToEndPoint(k)
				if err != nil {
					log.WithError(err).Error("startService:startDaemon() : Error in pushing Kubernetes CRDs")
				}
			}
		}
	}()
	secLog.Info(commLogMsg.ServiceStart)

	<-stop
	tick.Stop()

	secLog.Info(commLogMsg.ServiceStop)
	return nil
}
