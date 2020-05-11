/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package flavor

import (
	"fmt"

	uuid "github.com/satori/go.uuid"
)

/**
 *
 * @author purvades
 */

// ImageFlavor is a flavor for an image with the encryption requirement information
// and key details of an encrypted image.
type ImageFlavor struct {
	Image Image `json:"flavor"`
}

// GetImageFlavor is used to create a new image flavor with the specified label, encryption policy,
// key url, and digest of the encrypted image
func GetImageFlavor(label string, encryptionRequired bool, keyURL string, digest string) (*ImageFlavor, error) {

	var encryption *Encryption
	flavorID, err := uuid.NewV4()
	if err != nil {
		fmt.Println("Unable to create uuid. ", err)
		return nil, nil
	}

	description := Description{
		Label:      label,
		FlavorPart: "IMAGE",
	}

	meta := Meta{
		ID:          flavorID.String(),
		Description: &description,
	}

	if encryptionRequired {
		encryption = &Encryption{
			KeyURL: keyURL,
			Digest: digest,
		}
	}

	imageflavor := Image{
		Meta:               meta,
		EncryptionRequired: encryptionRequired,
		Encryption:         encryption,
	}

	flavor := ImageFlavor{
		Image: imageflavor,
	}
	return &flavor, nil
}

// GetContainerImageFlavor is used to create a new container image flavor with the specified label, encryption policy,
// Key url of the encrypted image also integrity policy and notary url for docker image signature verification
func GetContainerImageFlavor(label string, encryptionRequired bool, keyURL string, integrityEnforced bool, notaryURL string) (*ImageFlavor, error) {
	var encryption *Encryption
	var integrity *Integrity
	flavorID, err := uuid.NewV4()
	if err != nil {
		fmt.Println("Unable to create uuid. ", err)
		return nil, nil
	}

	if label == "" {
		return nil, fmt.Errorf("label cannot be empty")
	}

	description := Description{
		Label:      label,
		FlavorPart: "CONTAINER_IMAGE",
	}

	meta := Meta{
		ID:          flavorID.String(),
		Description: &description,
	}

	encryption = &Encryption{
		KeyURL: keyURL,
	}

	integrity = &Integrity{
		NotaryURL: notaryURL,
	}

	containerImageFlavor := Image{
		Meta:               meta,
		EncryptionRequired: encryptionRequired,
		Encryption:         encryption,
		IntegrityEnforced:  integrityEnforced,
		Integrity:          integrity,
	}

	flavor := ImageFlavor{
		Image: containerImageFlavor,
	}
	return &flavor, nil
}
