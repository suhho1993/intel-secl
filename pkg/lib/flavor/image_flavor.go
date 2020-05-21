/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package flavor

import (
	"fmt"
	"github.com/intel-secl/intel-secl/v3/pkg/lib/flavor/model"

	uuid "github.com/satori/go.uuid"
)

/**
 *
 * @author purvades
 */

// ImageFlavor is a flavor for an image with the encryption requirement information
// and key details of an encrypted image.
type ImageFlavor struct {
	Image model.Image `json:"flavor"`
}

// GetImageFlavor is used to create a new image flavor with the specified label, encryption policy,
// key url, and digest of the encrypted image
func GetImageFlavor(label string, encryptionRequired bool, keyURL string, digest string) (*ImageFlavor, error) {

	var encryption *model.Encryption
	flavorID, err := uuid.NewV4()
	if err != nil {
		fmt.Println("Unable to create uuid. ", err)
		return nil, nil
	}

	description := model.Description{
		Label:      label,
		FlavorPart: "IMAGE",
	}

	meta := model.Meta{
		ID:          flavorID.String(),
		Description: &description,
	}

	if encryptionRequired {
		encryption = &model.Encryption{
			KeyURL: keyURL,
			Digest: digest,
		}
	}

	imageflavor := model.Image{
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
	var encryption *model.Encryption
	var integrity *model.Integrity
	flavorID, err := uuid.NewV4()
	if err != nil {
		fmt.Println("Unable to create uuid. ", err)
		return nil, nil
	}

	if label == "" {
		return nil, fmt.Errorf("label cannot be empty")
	}

	description := model.Description{
		Label:      label,
		FlavorPart: "CONTAINER_IMAGE",
	}

	meta := model.Meta{
		ID:          flavorID.String(),
		Description: &description,
	}

	encryption = &model.Encryption{
		KeyURL: keyURL,
	}

	integrity = &model.Integrity{
		NotaryURL: notaryURL,
	}

	containerImageFlavor := model.Image{
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
