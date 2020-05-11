/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package util

import (
	"github.com/intel-secl/intel-secl/v3/pkg/lib/flavor"

	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha512"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io/ioutil"

	log "github.com/sirupsen/logrus"
)

//GetSignedFlavor is used to sign flavor
func GetSignedFlavor(flavorString string, rsaPrivateKeyLocation string) (string, error) {
	var privateKey *rsa.PrivateKey
	var flavorInterface flavor.ImageFlavor
	if rsaPrivateKeyLocation == "" {
		log.Error("No RSA Key file path provided")
		return "", errors.New("No RSA Key file path provided")
	}

	priv, err := ioutil.ReadFile(rsaPrivateKeyLocation)
	if err != nil {
		log.Error("No RSA private key found")
		return "", err
	}

	privPem, _ := pem.Decode(priv)
	parsedKey, err := x509.ParsePKCS8PrivateKey(privPem.Bytes)
	if err != nil {
		log.Error("Cannot parse RSA private key from file")
		return "", err
	}

	privateKey, ok := parsedKey.(*rsa.PrivateKey)
	if !ok {
		log.Error("Unable to parse RSA private key")
		return "", err
	}
	hashEntity := sha512.New384()
	hashEntity.Write([]byte(flavorString))
	signature, err := rsa.SignPKCS1v15(rand.Reader, privateKey, crypto.SHA384, hashEntity.Sum(nil))
	signatureString := base64.StdEncoding.EncodeToString(signature)

	err = json.Unmarshal([]byte(flavorString), &flavorInterface)
	if err != nil {
		log.Error("Flavor JSON Unmarshal failure")
		return "", err
	}

	signedFlavor := &flavor.SignedImageFlavor{
		ImageFlavor: flavorInterface.Image,
		Signature:   signatureString,
	}

	signedFlavorJSON, err := json.Marshal(signedFlavor)
	if err != nil {
		return "", errors.New("Error while marshalling signed image flavor: " + err.Error())
	}

	return string(signedFlavorJSON), nil
}
