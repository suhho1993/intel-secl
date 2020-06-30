/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package model

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"github.com/pkg/errors"
)

/**
 *
 * @author mullas
 */

// SignedFlavor combines the Flavor along with the cryptographically signed hash that authenticates its source
type SignedFlavor struct {
	Flavor    Flavor `json:"flavor"`
	Signature string `json:"signature"`
}

// NewSignedFlavorFromJSON returns an instance of SignedFlavor from an JSON string
func NewSignedFlavorFromJSON(sfstring string) (*SignedFlavor, error) {
	var sf SignedFlavor
	err := json.Unmarshal([]byte(sfstring), &sf)
	if err != nil {
		err = errors.Wrapf(err, "Error unmarshaling SignedFlavor JSON: %s", err.Error())
		return nil, err
	}
	return &sf, nil
}

// NewSignedFlavor Provided an existing flavor and a privatekey, create a SignedFlavor
func NewSignedFlavor(flavor *Flavor, privateKey *rsa.PrivateKey) (*SignedFlavor, error) {

	if flavor == nil {
		return nil, errors.New("The Flavor must be provided and cannot be nil")
	}

	if privateKey == nil {
		return nil, errors.New("The private key must be provided and cannot be nil")
	}

	flavorDigest, err := flavor.getFlavorDigest()
	if err != nil {
		return nil, errors.Wrap(err, "An error occurred while creating the signed flavor")
	}

	signature, err := rsa.SignPKCS1v15(rand.Reader, privateKey, crypto.SHA384, flavorDigest)
	if err != nil {
		return nil, errors.Wrap(err, "An error occurrred while signing the flavor")
	}

	return &SignedFlavor{
		Flavor:    *flavor,
		Signature: base64.StdEncoding.EncodeToString(signature),
	}, nil
}

// Verify Provided the public key from the Flavor Signing Certifiate,
// verify that the signed flavor's signature is valid.
func (signedFlavor *SignedFlavor) Verify(publicKey *rsa.PublicKey) error {

	if len(signedFlavor.Signature) == 0 {
		return errors.New("Could not verify the signed flavor: The signed flavor that does not have a signature")
	}

	signatureBytes, err := base64.StdEncoding.DecodeString(signedFlavor.Signature)
	if err != nil {
		return errors.Wrap(err, "Could not verify the signed flavor: An error occurred attempting to decode the signed flavor's signature")
	}

	flavorDigest, err := signedFlavor.Flavor.getFlavorDigest()
	if err != nil {
		return errors.Wrap(err, "Could not verify the signed flavor: An error occurred collecting the flavor digest")
	}

	err = rsa.VerifyPKCS1v15(publicKey, crypto.SHA384, flavorDigest, signatureBytes)
	if err != nil {
		return errors.Wrap(err, "Could not verify the signed flavor: PKCS1 verification failed")
	}

	return nil
}
