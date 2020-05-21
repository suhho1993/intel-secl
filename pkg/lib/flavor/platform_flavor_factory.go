/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package flavor

import (
	"crypto/x509"
	"fmt"
	"github.com/intel-secl/intel-secl/v3/pkg/lib/flavor/common"
	"github.com/intel-secl/intel-secl/v3/pkg/lib/flavor/constants"
	"github.com/intel-secl/intel-secl/v3/pkg/lib/flavor/model"
	"github.com/intel-secl/intel-secl/v3/pkg/lib/flavor/types"
	hcTypes "github.com/intel-secl/intel-secl/v3/pkg/lib/host-connector/types"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"strings"
)

/**
 *
 * @author mullas
 */

// FlavorProvider is an interface for PlatformFlavorProvider for a PlatformFlavorProvider
type FlavorProvider interface {
	GetPlatformFlavor() (*types.PlatformFlavor, error)
	GetGenericPlatformFlavor(string) (*types.PlatformFlavor, error)
}

// PlatformFlavorProvider is a factory for the PlatformFlavor which is responsible for instantiating
// an appropriate platform flavor implementation, based on the target host.
type PlatformFlavorProvider struct {
	hostManifest         *hcTypes.HostManifest
	attributeCertificate *model.X509AttributeCertificate
}

// NewPlatformFlavorProvider returns an instance of PlaformFlavorProvider
func NewPlatformFlavorProvider(hostManifest *hcTypes.HostManifest, tagCertificate *x509.Certificate) (FlavorProvider, error) {
	var pfp FlavorProvider
	var tc *model.X509AttributeCertificate
	var err error

	// we can skip the check for hostManifest nil, since it will not be required for GenericPlatformFlavor
	// check if attributeCertificate is populated and get the corresponding X509AttributeCertificate
	if tagCertificate != nil {
		tc, err = model.NewX509AttributeCertificate(tagCertificate)
		if err != nil {
			err = errors.Wrap(err, "Error while generating X509AttributeCertificate from TagCertificate")
			return nil, err
		}
	}

	pfp = PlatformFlavorProvider{
		hostManifest:         hostManifest,
		attributeCertificate: tc,
	}
	return pfp, nil
}

// GetPlatformFlavor parses the connection string of the target host and determines the type of the host
// and instantiates the appropriate PlatformFlavor implementation.
func (pff PlatformFlavorProvider) GetPlatformFlavor() (*types.PlatformFlavor, error) {
	var err error
	var rp types.PlatformFlavor

	if pff.hostManifest != nil {
		switch strings.ToUpper(strings.TrimSpace(pff.hostManifest.HostInfo.OSName)) {
		case constants.OsVMware:
			rp = types.NewESXPlatformFlavor(pff.hostManifest, pff.attributeCertificate)
		// Fallback to Linux
		default:
			rp = types.NewRHELPlatformFlavor(pff.hostManifest, pff.attributeCertificate)
		}
	} else {
		err = fmt.Errorf("Error while retrieving PlaformFlavor - missing HostManifest")
		err = errors.Wrapf(err, common.INVALID_INPUT().Message)
		return nil, err
	}
	return &rp, err
}

// GetGenericPlatformFlavor creates an instance of a GenericPlatform flavor using tagCert and vendor
func (pff PlatformFlavorProvider) GetGenericPlatformFlavor(vendor string) (*types.PlatformFlavor, error) {
	var err error
	var gpf types.PlatformFlavor

	if pff.attributeCertificate == nil {
		err = fmt.Errorf("Error while retrieving GenericPlatformFlavor - Tag certificate missing")
		err = errors.Wrapf(err, common.INVALID_INPUT().Message)
		return nil, err
	}

	log.Info("GetGenericPlatformFlavor: creating generic platform flavor for tag certificate with host hardware UUID {}", pff.attributeCertificate.Subject)

	gpf = types.GenericPlatformFlavor{
		Vendor:         vendor,
		TagCertificate: pff.attributeCertificate,
	}

	return &gpf, nil

}
