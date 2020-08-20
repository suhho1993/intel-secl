/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package tasks

import (
	"errors"
	"io/ioutil"
	"strings"
	"testing"
)

func TestCreateSigningKeyRun(t *testing.T) {

	privateKey, err := ioutil.TempFile("", "privateKey.pem")
	if err != nil {
		t.Errorf("tasks/create_signing_keypair_test:TestCreateSigningKeyValidate() unable to create privatekey.pem temp file %v", err)
	}
	publicKey, err := ioutil.TempFile("", "publicKey.pem")
	if err != nil {
		t.Errorf("tasks/create_signing_keypair_test:TestCreateSigningKeyValidate() unable to create publickey.pem temp file %v", err)
	}
	tests := []struct {
		name        string
		ek          CreateSigningKey
		wantErr     bool
		expectedErr error
	}{
		{
			name: "create-signing-key-run valid test 1",
			ek: CreateSigningKey{
				KeyAlgorithmLength: 3072,
				PrivateKeyLocation: privateKey.Name(),
				PublicKeyLocation:  publicKey.Name(),
			},
			wantErr:     false,
			expectedErr: nil,
		},
		{
			name: "create-signing-key-run valid test 2",
			ek: CreateSigningKey{
				KeyAlgorithmLength: 3073,
				PrivateKeyLocation: privateKey.Name(),
				PublicKeyLocation:  publicKey.Name(),
			},
			wantErr:     false,
			expectedErr: nil,
		},
		{
			name: "create-signing-key-run valid test 3",
			ek: CreateSigningKey{
				KeyAlgorithmLength: 3073,
				PrivateKeyLocation: privateKey.Name(),
				PublicKeyLocation:  publicKey.Name(),
			},
			wantErr:     false,
			expectedErr: nil,
		},

		{
			name: "create-signing-key-run negative test 1",
			ek: CreateSigningKey{
				KeyAlgorithmLength: 3072,
				PrivateKeyLocation: "",
				PublicKeyLocation:  "",
			},
			wantErr:     true,
			expectedErr: errors.New("could not open private key file for writing"),
		},

		{
			name: "create-signing-key-run negative test 2",
			ek: CreateSigningKey{
				KeyAlgorithmLength: 3072,
				PrivateKeyLocation: privateKey.Name(),
				PublicKeyLocation:  "",
			},
			wantErr:     true,
			expectedErr: errors.New("Error while creating a new public key"),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err = tt.ek.Run()

			if (err != nil) != tt.wantErr {
				t.Errorf("tasks/create_signing_keypair_test:TestCreateSigningKeyRun() error = %v, wantErr %v", err, tt.wantErr)
			}

			if err != nil {

				errorMessage := err.Error()
				expectedErrorMessage := tt.expectedErr.Error()

				if !strings.Contains(errorMessage, expectedErrorMessage) {
					t.Errorf("tasks/create_signing_keypair_test:TestCreateSigningKeyRun() errorMessage = %v, expectedErrorMessage %v", err, expectedErrorMessage)
				}
			}

		})
	}
}

func TestCreateSigningKeyValidate(t *testing.T) {
	privateKey, err := ioutil.TempFile("", "privateKey.pem")
	if err != nil {
		t.Errorf("tasks/create_signing_keypair_test:TestCreateSigningKeyValidate() unable to create privatekey.pem temp file %v", err)
	}
	publicKey, err := ioutil.TempFile("", "publicKey.pem")
	if err != nil {
		t.Errorf("tasks/create_signing_keypair_test:TestCreateSigningKeyValidate() unable to create publickey.pem temp file %v", err)
	}

	tests := []struct {
		name    string
		ek      CreateSigningKey
		wantErr bool
	}{

		{
			name: "create-signingkey-validate valid test 1",

			ek: CreateSigningKey{
				KeyAlgorithmLength: 3072,
				PrivateKeyLocation: privateKey.Name(),
				PublicKeyLocation:  publicKey.Name(),
			},
			wantErr: false,
		},
		{
			name: "create-signingkey-validate valid test 2",

			ek: CreateSigningKey{
				KeyAlgorithmLength: 3072,
				PrivateKeyLocation: "",
				PublicKeyLocation:  "publicKey.pem",
			},
			wantErr: true,
		},
		{
			name: "create-signingkey-validate negative test",

			ek: CreateSigningKey{
				KeyAlgorithmLength: 3072,
				PrivateKeyLocation: "privateKey.pem",
				PublicKeyLocation:  "",
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {

			err := tt.ek.Validate()

			if (err != nil) != tt.wantErr {
				t.Errorf("tasks/create_signing_keypair_test:TestCreateSigningKey_Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}

}
