/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package tasks

import (
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"flag"
	"fmt"
	"github.com/intel-secl/intel-secl/v3/pkg/hvs/config"
	"github.com/intel-secl/intel-secl/v3/pkg/hvs/constants"
	"github.com/intel-secl/intel-secl/v3/pkg/lib/common/crypt"
	commLog "github.com/intel-secl/intel-secl/v3/pkg/lib/common/log"
	"github.com/intel-secl/intel-secl/v3/pkg/lib/common/setup"
	"github.com/pkg/errors"
	"io"
	"math/big"
	"os"
	"time"
)

var defaultLog = commLog.GetDefaultLogger()

type CreatePrivacyCA struct {
	Flags         []string
	Config        *config.Configuration
	ConsoleWriter io.Writer
}

func (pCa CreatePrivacyCA) Run(c setup.Context) error {
	defaultLog.Trace("tasks/privacyca:Run() Entering")
	defer defaultLog.Trace("tasks/privacyca:Run()Leaving")

	fmt.Fprintln(pCa.ConsoleWriter, "Running PrivacyCA setup...")
	fs := flag.NewFlagSet("privacyca", flag.ContinueOnError)
	force := fs.Bool("force", false, "force recreation, will overwrite any existing PrivacyCA keys")

	err := fs.Parse(pCa.Flags)
	if err != nil {
		return err
	}
	if *force || pCa.Validate(c) != nil {
		_ = updateConfig(pCa.Config, c)
		privKey, cert, err := createPrivacyCACert(pCa.Config)
		if err != nil {
			return errors.Wrap(err, "tasks/privacyca:Run() Could not create privacyca certificate")
		}
		key, err := x509.MarshalPKCS8PrivateKey(privKey)
		if err != nil {
			return errors.Wrap(err, "tasks/privacyca:Run() Could not marshal private key to pkcs8 format error")
		}

		//Store key and certificate
		err = crypt.SavePrivateKeyAsPKCS8(key, constants.PrivacyCAKeyPath)
		if err != nil {
			return errors.Wrap(err, "tasks/privacyca:Run() Could not save privacyca private key")
		}
		err = crypt.SavePemCert(cert, constants.PrivacyCACertFile)
		if err != nil {
			return errors.Wrap(err, "tasks/privacyca:Run() Could not save privacyca certificate")
		}
	} else {
		fmt.Println("Privacy CA already configured, skipping")
	}
	return nil
}

func createPrivacyCACert(cfg *config.Configuration) (privKey crypto.PrivateKey, cert []byte, err error) {
	defaultLog.Trace("tasks/privacyca:createPrivacyCACert() Entering")
	defer defaultLog.Trace("tasks/privacyca:createPrivacyCACert() Leaving")

	privKey, pubKey, err := crypt.GenerateKeyPair(constants.DefaultKeyAlgorithm, constants.DefaultKeyAlgorithmLength)
	if err != nil {
		return nil, nil, errors.Wrap(err, "tasks/privacyca:createPrivacyCACert() Could not create privacyca key pair")
	}
	caCertTemplate, err := getCACertDefaultTemplate(cfg,
		cfg.PrivacyCA.PrivacyCaIdentityIssuer)
	if err != nil {
		return nil, nil, errors.Wrap(err, "tasks/privacyca:createPrivacyCACert() Could not create PrivacyCA certificate template")
	}
	cert, err = x509.CreateCertificate(rand.Reader, &caCertTemplate, &caCertTemplate, pubKey, privKey)
	if err != nil {
		return nil, nil, errors.Wrap(err, "tasks/privacyca:createPrivacyCACert() Could not create PrivacyCA certificate")
	}
	return
}

func getCACertDefaultTemplate(cfg *config.Configuration, cn string) (x509.Certificate, error) {
	defaultLog.Trace("tasks/privacyca:getCACertDefaultTemplate() Entering")
	defer defaultLog.Trace("tasks/privacyca:getCACertDefaultTemplate() Leaving")

	tmplt := x509.Certificate{
		Subject: pkix.Name{
			CommonName:   cn,
		},
		Issuer: pkix.Name{
			CommonName: cn,
		},
		NotBefore: time.Now(),
		NotAfter: time.Now().AddDate(cfg.PrivacyCA.PrivacyCACertValidity, 0, 0),

		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return tmplt, errors.Wrap(err, "Failed to generate serial number")
	}

	tmplt.SerialNumber = serialNumber
	tmplt.SignatureAlgorithm = x509.SHA256WithRSA

	return tmplt, err
}

func (pCa CreatePrivacyCA) Validate(c setup.Context) error {
	defaultLog.Trace("tasks/privacyca:Validate() Entering")
	defer defaultLog.Trace("tasks/privacyca:Validate() Leaving")

	_, err := os.Stat(constants.PrivacyCACertFile)
	if os.IsNotExist(err) {
		return errors.Wrapf(err, "tasks/privacyca:Validate() %s does not exist", constants.PrivacyCACertFile)
	}
	_, err = os.Stat(constants.PrivacyCAKeyPath)
	if os.IsNotExist(err) {
		return errors.Wrap(err, "tasks/privacyca:Validate() PrivacyCAKeyFile is not configured")
	}
	return nil
}


func updateConfig(cfg *config.Configuration, c setup.Context) (err error){
	defaultLog.Trace("tasks/privacyca:updateConfig() Entering")
	defer defaultLog.Trace("tasks/privacyca:updateConfig() Leaving")

	cfg.PrivacyCA.PrivacyCACertValidity, err = c.GetenvInt("PRIVACYCA_CERT_VALIDITY", "HVS PrivacyCA Certificate Validity")
	if err != nil {
		cfg.PrivacyCA.PrivacyCACertValidity = constants.DefaultPrivacyCACertValidity
	}
	defaultLog.Infof("tasks/privacyca:updateConfig() PrivacyCA certificate validity - %v", cfg.PrivacyCA.PrivacyCACertValidity)

	cfg.PrivacyCA.PrivacyCaIdentityIssuer, err = c.GetenvString("PRIVACYCA_AIK_ISSUER", "HVS PrivacyCa Certificate Identity Issuer")
	if err != nil {
		cfg.PrivacyCA.PrivacyCaIdentityIssuer = constants.DefaultPrivacyCaIdentityIssuer
	}
	defaultLog.Infof("tasks/privacyca:updateConfig() PrivacyCaIdentityIssuer - %v", cfg.PrivacyCA.PrivacyCaIdentityIssuer)

	cfg.Save()
	return nil
}