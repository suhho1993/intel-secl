/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package keymanager

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"time"

	"github.com/google/uuid"
	"github.com/intel-secl/intel-secl/v3/pkg/kbs/constants"
	"github.com/intel-secl/intel-secl/v3/pkg/kbs/domain/models"
	"github.com/intel-secl/intel-secl/v3/pkg/lib/common/crypt"
	"github.com/intel-secl/intel-secl/v3/pkg/model/kbs"
	"github.com/pkg/errors"
)

type DirectoryManager struct {
}

func (dm *DirectoryManager) CreateKey(request *kbs.KeyRequest) (*models.KeyAttributes, error) {
	defaultLog.Trace("keymanager/directory_key_manager:CreateKey() Entering")
	defer defaultLog.Trace("keymanager/directory_key_manager:CreateKey() Leaving")

	var err error
	var key, publicKey, privateKey string

	if request.KeyInformation.Algorithm == constants.CRYPTOALG_AES {
		keyBytes, err := generateAESKey(request.KeyInformation.KeyLength)
		if err != nil {
			return nil, err
		}

		key = base64.StdEncoding.EncodeToString(keyBytes)
	} else {

		var publicKeyBytes, privateKeyBytes []byte
		if request.KeyInformation.Algorithm == constants.CRYPTOALG_RSA {
			privateKeyBytes, publicKeyBytes, err = generateRSAKeyPair(request.KeyInformation.KeyLength)
			if err != nil {
				return nil, err
			}
		} else {
			privateKeyBytes, publicKeyBytes, err = generateECKeyPair(request.KeyInformation.CurveType)
			if err != nil {
				return nil, err
			}
		}

		publicKey = base64.StdEncoding.EncodeToString(publicKeyBytes)
		privateKey = base64.StdEncoding.EncodeToString(privateKeyBytes)
	}

	keyAttributes := &models.KeyAttributes{
		ID:               uuid.New(),
		Algorithm:        request.KeyInformation.Algorithm,
		KeyLength:        request.KeyInformation.KeyLength,
		KeyData:          key,
		CurveType:        request.KeyInformation.CurveType,
		PublicKey:        publicKey,
		PrivateKey:       privateKey,
		TransferPolicyId: request.TransferPolicyID,
		CreatedAt:        time.Now().UTC(),
		Label:            request.Label,
		Usage:            request.Usage,
	}

	return keyAttributes, nil
}

func (dm *DirectoryManager) DeleteKey(attributes *models.KeyAttributes) error {
	defaultLog.Trace("keymanager/directory_key_manager:DeleteKey() Entering")
	defer defaultLog.Trace("keymanager/directory_key_manager:DeleteKey() Leaving")

	return nil
}

func (dm *DirectoryManager) RegisterKey(request *kbs.KeyRequest) (*models.KeyAttributes, error) {
	defaultLog.Trace("keymanager/directory_key_manager:RegisterKey() Entering")
	defer defaultLog.Trace("keymanager/directory_key_manager:RegisterKey() Leaving")

	var key, publicKey, privateKey string

	if request.KeyInformation.Algorithm == constants.CRYPTOALG_AES {
		key = request.KeyInformation.KeyString
	} else {

		var public crypto.PublicKey
		privateKey = request.KeyInformation.KeyString
		privateKeyBytes, _ := base64.StdEncoding.DecodeString(privateKey)

		if request.KeyInformation.Algorithm == constants.CRYPTOALG_RSA {
			private, err := x509.ParsePKCS1PrivateKey(privateKeyBytes)
			if err != nil {
				return nil, errors.Wrap(err, "Could not parse RSA private key")
			}
			public = private.PublicKey
		} else {
			private, err := x509.ParseECPrivateKey(privateKeyBytes)
			if err != nil {
				return nil, errors.Wrap(err, "Could not parse EC private key")
			}
			public = private.PublicKey
		}

		publicKeyBytes, err := x509.MarshalPKIXPublicKey(public)
		if err != nil {
			return nil, errors.Wrap(err, "")
		}
		publicKey = base64.StdEncoding.EncodeToString(publicKeyBytes)
	}

	keyAttributes := &models.KeyAttributes{
		ID:               uuid.New(),
		Algorithm:        request.KeyInformation.Algorithm,
		KeyLength:        request.KeyInformation.KeyLength,
		KeyData:          key,
		CurveType:        request.KeyInformation.CurveType,
		PublicKey:        publicKey,
		PrivateKey:       privateKey,
		TransferPolicyId: request.TransferPolicyID,
		CreatedAt:        time.Now().UTC(),
		Label:            request.Label,
		Usage:            request.Usage,
	}

	return keyAttributes, nil
}

func (dm *DirectoryManager) TransferKey(attributes *models.KeyAttributes) ([]byte, error) {
	defaultLog.Trace("keymanager/directory_key_manager:TransferKey() Entering")
	defer defaultLog.Trace("keymanager/directory_key_manager:TransferKey() Leaving")

	var key string
	if attributes.Algorithm == constants.CRYPTOALG_AES {
		key = attributes.KeyData
	} else {
		key = attributes.PrivateKey
	}

	return base64.StdEncoding.DecodeString(key)
}

func generateAESKey(length int) ([]byte, error) {
	defaultLog.Trace("keymanager/directory_key_manager:generateAESKey() Entering")
	defer defaultLog.Trace("keymanager/directory_key_manager:generateAESKey() Leaving")

	return crypt.GetRandomBytes(length/8)
}

func generateRSAKeyPair(length int) ([]byte, []byte, error) {
	defaultLog.Trace("keymanager/directory_key_manager:generateRSAKeyPair() Entering")
	defer defaultLog.Trace("keymanager/directory_key_manager:generateRSAKeyPair() Leaving")

	private, err := rsa.GenerateKey(rand.Reader, length)
	if err != nil {
		return nil, nil, errors.Wrap(err, "Could not create RSA keypair")
	}

	public := private.PublicKey

	if bits := private.N.BitLen(); bits != length {
		return nil, nil, errors.Errorf("key too short (%d vs %d)", bits, length)
	}

	privateBytes, err := x509.MarshalPKCS8PrivateKey(private)
	if err != nil {
		return nil, nil, errors.Wrap(err, "failed to marshal private key")
	}

	publicBytes, err := x509.MarshalPKIXPublicKey(public)
	if err != nil {
		return nil, nil, errors.Wrap(err, "failed to marshal public key")
	}

	return privateBytes, publicBytes, nil
}

func generateECKeyPair(curveType string) ([]byte, []byte, error) {
	defaultLog.Trace("keymanager/directory_key_manager:generateECKeyPair() Entering")
	defer defaultLog.Trace("keymanager/directory_key_manager:generateECKeyPair() Leaving")

	var curve elliptic.Curve

	switch curveType {
	case "secp384r1":
		curve = elliptic.P384()
	case "secp521r1":
		curve = elliptic.P521()
	default:
		return nil, nil, errors.New("unsupported curve type")
	}

	private, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		return nil, nil, errors.Wrap(err, "Could not generate EC keypair")
	}

	public := private.PublicKey

	if !curve.IsOnCurve(public.X, public.Y) {
		return nil, nil, errors.New("public key invalid")
	}

	privateBytes, err := x509.MarshalECPrivateKey(private)
	if err != nil {
		return nil, nil, errors.Wrap(err, "failed to marshal private key")
	}

	publicBytes, err := x509.MarshalPKIXPublicKey(public)
	if err != nil {
		return nil, nil, errors.Wrap(err, "failed to marshal public key")
	}

	return privateBytes, publicBytes, nil
}
