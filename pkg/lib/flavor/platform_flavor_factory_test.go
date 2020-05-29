/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package flavor

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"github.com/intel-secl/intel-secl/v3/pkg/lib/common/crypt"
	cf "github.com/intel-secl/intel-secl/v3/pkg/lib/flavor/common"
	"github.com/intel-secl/intel-secl/v3/pkg/lib/flavor/model"
	"github.com/intel-secl/intel-secl/v3/pkg/lib/flavor/types"
	"github.com/intel-secl/intel-secl/v3/pkg/lib/flavor/util"
	hcTypes "github.com/intel-secl/intel-secl/v3/pkg/lib/host-connector/types"
	"github.com/stretchr/testify/assert"
	"io/ioutil"
	"math/big"
	"os"
	"testing"
)

const (
	RHELManifestPath   string = "./test/resources/RHELHostManifest.json"
	TagCertPath        string = "./test/resources/AssetTagpem.Cert"
	GoodSoftwareFlavor string = "./test/resources/SoftwareFlavor.xml"
	BadSoftwareFlavor  string = "./test/resources/BadSoftwareFlavor.xml"

	ESXHostManifestPath        string = "./test/resources/VMWareManifest.json"
	RHELManifestPathWSwFlavors string = "./test/resources/SWManifest.json"
)

var pfutil util.PlatformFlavorUtil

// loadManifestAndTagCert is a helper function that loads a HostManifest and TagCertificate from files
func loadManifestAndTagCert(hmFilePath string, tcFilePath string) (*hcTypes.HostManifest, *x509.Certificate) {
	// load manifest
	var hm hcTypes.HostManifest
	var tagCert *x509.Certificate

	// load hostmanifest
	if hmFilePath != "" {
		manifestFile, _ := os.Open(hmFilePath)
		manifestBytes, _ := ioutil.ReadAll(manifestFile)
		_ = json.Unmarshal(manifestBytes, &hm)
	}

	// load tag cert
	if tcFilePath != "" {
		// load tagCert
		// read the test tag cert
		tagCertFile, _ := os.Open(tcFilePath)
		tagCertPathBytes, _ := ioutil.ReadAll(tagCertFile)

		// convert pem to cert
		pemBlock, _ := pem.Decode(tagCertPathBytes)
		tagCert, _ = x509.ParseCertificate(pemBlock.Bytes)
	}

	return &hm, tagCert
}

// checkIfRequiredFlavorsArePresent is a helper function that ensures expected flavorparts are present in Flavor
func checkIfRequiredFlavorsArePresent(t *testing.T, expFlavorParts []cf.FlavorPart, actualFlavorParts []cf.FlavorPart) {
	// check if expected flavorparts are present
	for _, expFp := range expFlavorParts {
		fpPresent := false
		for _, actFp := range actualFlavorParts {
			if expFp == actFp {
				fpPresent = true
				break
			}
		}
		assert.True(t, fpPresent, "All expected flavors not present")
	}
	// all good
}

func getSignedFlavor(t *testing.T, pflavor *types.PlatformFlavor, part cf.FlavorPart) {
	// Generate Signing Keypair
	sPriKey, _, _ := crypt.CreateSelfSignedCertAndRSAPrivKeys()

	// Sign the flavor
	signedFlavor, err := (*pflavor).GetFlavorPart(part, sPriKey)
	assert.NoError(t, err, "failed at preparing signature for ", part, " SignedFlavor")
	t.Log(signedFlavor)

	// Convert SignedFlavor to json
	jsonSf, err := json.Marshal(signedFlavor)
	assert.NoError(t, err, "failed to marshal SignedFlavor")
	assert.NotNil(t, jsonSf, "failed to marshal SignedFlavor")
	t.Log(string(jsonSf))
}

// TestLinuxPlatformFlavorGetFlavorParts validates the GetFlavorPartNames() method implementation of LinuxPlatformFlavor
func TestLinuxPlatformFlavorGetFlavorParts(t *testing.T) {
	var pffactory FlavorProvider
	var err error

	// expected FlavorParts
	expFlavorParts := cf.GetFlavorTypes()

	// load hostManifest and tagCertificate
	hm, tagCert := loadManifestAndTagCert(RHELManifestPath, TagCertPath)

	pffactory, err = NewPlatformFlavorProvider(hm, tagCert)

	// get the flavor
	pflavor, err := pffactory.GetPlatformFlavor()
	assert.NoError(t, err, "Error initializing PlatformFlavor")
	pFlavorParts, err := (*pflavor).GetFlavorPartNames()
	assert.NoError(t, err, "Error fetching flavor parts")
	t.Logf("%v", pFlavorParts)

	checkIfRequiredFlavorsArePresent(t, expFlavorParts, pFlavorParts)
}

// TestLinuxPlatformFlavorGetSignedPlatformFlavorWithoutAssetTag fetches prepares the SignedFlavor without an asset tag certificate
func TestLinuxPlatformFlavorGetSignedPlatformFlavorWithoutAssetTag(t *testing.T) {
	var pffactory FlavorProvider
	var err error

	// expected FlavorParts
	expFlavorParts := cf.GetFlavorTypes()

	// load hostManifest and tagCertificate
	hm, tagCert := loadManifestAndTagCert(RHELManifestPath, "")

	pffactory, err = NewPlatformFlavorProvider(hm, tagCert)

	// get the flavor
	pflavor, err := pffactory.GetPlatformFlavor()
	assert.NoError(t, err, "Error initializing PlatformFlavor")
	pFlavorParts, err := (*pflavor).GetFlavorPartNames()
	assert.NoError(t, err, "Error fetching flavor parts")
	t.Logf("%v", pFlavorParts)

	// remove Asset Tag from the list of expected flavors
	for i, flavorPart := range expFlavorParts {
		if flavorPart == cf.AssetTag {
			expFlavorParts = append(expFlavorParts[:i], expFlavorParts[i+1:]...)
		}
	}

	checkIfRequiredFlavorsArePresent(t, expFlavorParts, pFlavorParts)

	getSignedFlavor(t, pflavor, cf.Platform)
}

// TestLinuxPlatformFlavorGetSignedPlatformFlavor fetches the Platform flavor using
// GetFlavorPartNames() method implementation of LinuxPlatformFlavor
// And fetches the corresponding SignedFlavor
func TestLinuxPlatformFlavorGetSignedPlatformFlavor(t *testing.T) {
	var pffactory FlavorProvider
	var err error

	// expected FlavorParts
	expFlavorParts := cf.GetFlavorTypes()

	// load hostManifest and tagCertificate
	hm, tagCert := loadManifestAndTagCert(RHELManifestPath, TagCertPath)

	pffactory, err = NewPlatformFlavorProvider(hm, tagCert)

	// get the flavor
	pflavor, err := pffactory.GetPlatformFlavor()
	assert.NoError(t, err, "Error initializing PlatformFlavor")
	pFlavorParts, err := (*pflavor).GetFlavorPartNames()
	assert.NoError(t, err, "Error fetching flavor parts")
	t.Logf("%v", pFlavorParts)

	checkIfRequiredFlavorsArePresent(t, expFlavorParts, pFlavorParts)

	getSignedFlavor(t, pflavor, cf.Platform)
}

// TestLinuxPlatformFlavorGetSignedOSFlavor fetches the OS flavor using
// GetFlavorPartNames() method implementation of LinuxPlatformFlavor
// And fetches the corresponding SignedFlavor
func TestLinuxPlatformFlavorGetSignedOSFlavor(t *testing.T) {
	var pffactory FlavorProvider
	var err error

	// expected FlavorParts
	expFlavorParts := []cf.FlavorPart{cf.Os}

	// load hostManifest and tagCertificate
	hm, tagCert := loadManifestAndTagCert(RHELManifestPath, TagCertPath)

	pffactory, err = NewPlatformFlavorProvider(hm, tagCert)

	// get the flavor
	pflavor, err := pffactory.GetPlatformFlavor()
	assert.NoError(t, err, "Error initializing PlatformFlavor")
	pFlavorParts, err := (*pflavor).GetFlavorPartNames()
	assert.NoError(t, err, "Error fetching flavor parts")
	t.Logf("%v", pFlavorParts)

	checkIfRequiredFlavorsArePresent(t, expFlavorParts, pFlavorParts)

	getSignedFlavor(t, pflavor, cf.Os)
}

// TestLinuxPlatformFlavorGetSignedHostUniqueFlavor fetches the Host Unique flavor using
// GetFlavorPartNames() method implementation of LinuxPlatformFlavor
// And fetches the corresponding SignedFlavor
func TestLinuxPlatformFlavorGetSignedHostUniqueFlavor(t *testing.T) {
	var pffactory FlavorProvider
	var err error

	// expected FlavorParts
	expFlavorParts := []cf.FlavorPart{cf.HostUnique}

	// load hostManifest and tagCertificate
	hm, tagCert := loadManifestAndTagCert(RHELManifestPath, TagCertPath)

	pffactory, err = NewPlatformFlavorProvider(hm, tagCert)

	// get the flavor
	pflavor, err := pffactory.GetPlatformFlavor()
	assert.NoError(t, err, "Error initializing PlatformFlavor")
	pFlavorParts, err := (*pflavor).GetFlavorPartNames()
	assert.NoError(t, err, "Error fetching flavor parts")
	t.Logf("%v", pFlavorParts)

	checkIfRequiredFlavorsArePresent(t, expFlavorParts, pFlavorParts)

	getSignedFlavor(t, pflavor, cf.HostUnique)
}

// TestLinuxPlatformFlavorGetSignedSoftwareFlavor fetches the Software flavor using
// GetFlavorPartNames() method implementation of LinuxPlatformFlavor
// And fetches the corresponding SignedFlavor
func TestLinuxPlatformFlavorGetSignedSoftwareFlavor(t *testing.T) {
	var pffactory FlavorProvider
	var err error

	// expected FlavorParts
	expFlavorParts := []cf.FlavorPart{cf.Software}

	// load hostManifest and tagCertificate
	hm, tagCert := loadManifestAndTagCert(RHELManifestPathWSwFlavors, TagCertPath)

	pffactory, err = NewPlatformFlavorProvider(hm, tagCert)

	// get the flavor
	pflavor, err := pffactory.GetPlatformFlavor()
	assert.NoError(t, err, "Error initializing PlatformFlavor")
	pFlavorParts, err := (*pflavor).GetFlavorPartNames()
	assert.NoError(t, err, "Error fetching flavor parts")
	t.Logf("%v", pFlavorParts)

	checkIfRequiredFlavorsArePresent(t, expFlavorParts, pFlavorParts)

	getSignedFlavor(t, pflavor, cf.Software)
}

// TestCreateAssetTagFlavorOnly fetches the ASSET_TAG flavor using
// GetFlavorPartNames() method implementation of LinuxPlatformFlavor
// And fetches the corresponding SignedFlavor
func TestRHELCreateAssetTagFlavorOnly(t *testing.T) {
	var pffactory FlavorProvider
	var err error

	// expected FlavorParts
	expFlavorParts := []cf.FlavorPart{cf.AssetTag}

	// load hostManifest and tagCertificate
	hm, tagCert := loadManifestAndTagCert(RHELManifestPath, TagCertPath)

	pffactory, err = NewPlatformFlavorProvider(hm, tagCert)

	// get the flavor
	pflavor, err := pffactory.GetPlatformFlavor()
	assert.NoError(t, err, "Error initializing PlatformFlavor")
	pFlavorParts, err := (*pflavor).GetFlavorPartNames()
	assert.NoError(t, err, "Error fetching flavor parts")
	t.Logf("%v", pFlavorParts)

	checkIfRequiredFlavorsArePresent(t, expFlavorParts, pFlavorParts)

	getSignedFlavor(t, pflavor, cf.AssetTag)
}

// TestSoftwareFlavor validates GetSoftwareFlavor()
func TestSoftwareFlavor(t *testing.T) {
	var sf types.SoftwareFlavor
	// load flavor
	softwareFile, _ := os.Open(GoodSoftwareFlavor)
	sfBytes, _ := ioutil.ReadAll(softwareFile)

	sf = types.SoftwareFlavor{
		Measurement: string(sfBytes),
	}
	sfg, err := sf.GetSoftwareFlavor()
	assert.NoError(t, err, "Failed generating software flavor")
	t.Log(sfg)
}

// ---------------------------------------
// ESXPlatformFlavor Tests
// ---------------------------------------

// TestSignedESXPlatformFlavor validates the flavorparts from an ESXPlatformFlavor
// and generates a Signed Platform Flavor
func TestSignedESXPlatformFlavor(t *testing.T) {
	var pffactory FlavorProvider
	var err error

	// expected FlavorParts
	expFlavorParts := []cf.FlavorPart{cf.Platform, cf.Os, cf.HostUnique}

	// load hostManifest and tagCertificate
	hm, tagCert := loadManifestAndTagCert(ESXHostManifestPath, "")

	pffactory, err = NewPlatformFlavorProvider(hm, tagCert)

	// get the flavor
	pflavor, err := pffactory.GetPlatformFlavor()
	assert.NoError(t, err, "Error initializing PlatformFlavor")
	pFlavorParts, err := (*pflavor).GetFlavorPartNames()
	assert.NoError(t, err, "Error fetching flavor parts")
	t.Logf("%v", pFlavorParts)

	checkIfRequiredFlavorsArePresent(t, expFlavorParts, pFlavorParts)

	getSignedFlavor(t, pflavor, cf.Platform)
}

// TestSignedESXOsFlavor validates the flavorparts from an ESXPlatformFlavor
// and generates a Signed OS Flavor
func TestSignedESXOsFlavor(t *testing.T) {
	var pffactory FlavorProvider
	var err error

	// expected FlavorParts
	expFlavorParts := []cf.FlavorPart{cf.Os}

	// load hostManifest and tagCertificate
	hm, tagCert := loadManifestAndTagCert(ESXHostManifestPath, "")

	pffactory, err = NewPlatformFlavorProvider(hm, tagCert)

	// get the flavor
	pflavor, err := pffactory.GetPlatformFlavor()
	assert.NoError(t, err, "Error initializing PlatformFlavor")
	pFlavorParts, err := (*pflavor).GetFlavorPartNames()
	assert.NoError(t, err, "Error fetching flavor parts")
	t.Logf("%v", pFlavorParts)

	checkIfRequiredFlavorsArePresent(t, expFlavorParts, pFlavorParts)

	getSignedFlavor(t, pflavor, cf.Os)
}

// TestSignedESXHostUniqueFlavor validates the flavorparts from an ESXPlatformFlavor
// and generates a Signed HostUnique Flavor
func TestSignedESXHostUniqueFlavor(t *testing.T) {
	var pffactory FlavorProvider
	var err error

	// expected FlavorParts
	expFlavorParts := []cf.FlavorPart{cf.HostUnique}

	// load hostManifest and tagCertificate
	hm, tagCert := loadManifestAndTagCert(ESXHostManifestPath, "")

	pffactory, err = NewPlatformFlavorProvider(hm, tagCert)

	// get the flavor
	pflavor, err := pffactory.GetPlatformFlavor()
	assert.NoError(t, err, "Error initializing PlatformFlavor")
	pFlavorParts, err := (*pflavor).GetFlavorPartNames()
	assert.NoError(t, err, "Error fetching flavor parts")
	t.Logf("%v", pFlavorParts)

	checkIfRequiredFlavorsArePresent(t, expFlavorParts, pFlavorParts)

	getSignedFlavor(t, pflavor, cf.HostUnique)
}

// TestSignedESXAssetTagFlavorFlavor validates the flavorparts from an ESXPlatformFlavor
// and generates a Signed Asset Tag Flavor
func TestSignedESXAssetTagFlavorFlavor(t *testing.T) {
	var pffactory FlavorProvider
	var err error

	// expected FlavorParts
	expFlavorParts := []cf.FlavorPart{cf.AssetTag}

	// load hostManifest and tagCertificate
	hm, tagCert := loadManifestAndTagCert(ESXHostManifestPath, TagCertPath)

	pffactory, err = NewPlatformFlavorProvider(hm, tagCert)

	// get the flavor
	pflavor, err := pffactory.GetPlatformFlavor()
	assert.NoError(t, err, "Error initializing PlatformFlavor")
	pFlavorParts, err := (*pflavor).GetFlavorPartNames()
	assert.NoError(t, err, "Error fetching flavor parts")
	t.Logf("%v", pFlavorParts)

	checkIfRequiredFlavorsArePresent(t, expFlavorParts, pFlavorParts)

	getSignedFlavor(t, pflavor, cf.AssetTag)
}

// TestPlatformFlavorFactory_GetGenericPlatformFlavor attempts to generate a GenericPlatformFlavor from the
// HostManifest and attributeCertificate
func TestPlatformFlavorFactory_GetGenericPlatformFlavor(t *testing.T) {
	var pffactory FlavorProvider
	var err error

	// expected FlavorParts
	expFlavorParts := []cf.FlavorPart{cf.AssetTag}

	// load hostManifest and tagCertificate
	hm, tagCert := loadManifestAndTagCert(ESXHostManifestPath, TagCertPath)

	pffactory, err = NewPlatformFlavorProvider(hm, tagCert)

	vendor := pfutil.GetVendorName(&hm.HostInfo)
	// get the flavor
	pflavor, err := pffactory.GetGenericPlatformFlavor(vendor)
	assert.NoError(t, err, "Error initializing GenericPlatformFlavor")
	pFlavorParts, err := (*pflavor).GetFlavorPartNames()
	assert.NoError(t, err, "Error fetching flavor parts")
	t.Logf("%v", pFlavorParts)

	checkIfRequiredFlavorsArePresent(t, expFlavorParts, pFlavorParts)

	getSignedFlavor(t, pflavor, cf.AssetTag)
}

// NEGATIVE Cases
// Let's enumerate possible scenarios where the flavor genration might fail
// 1. SignedFlavor creation fails due to null PrivateKey
// 2. SignedFlavor creation fails due to invalid PrivateKey
// 3. SignedFlavor creation fails due to null Flavor JSON
func TestFailures4SignFlavor(t *testing.T) {
	var hm hcTypes.HostManifest
	var tagCert model.X509AttributeCertificate
	var sKey *rsa.PrivateKey

	sKey, _, _ = crypt.CreateSelfSignedCertAndRSAPrivKeys()

	// load manifest
	manifestFile, _ := os.Open(RHELManifestPath)
	manifestBytes, _ := ioutil.ReadAll(manifestFile)
	_ = json.Unmarshal(manifestBytes, &hm)

	// load tag cert
	tagCertFile, _ := os.Open(TagCertPath)
	tagCertBytes, _ := ioutil.ReadAll(tagCertFile)
	_ = json.Unmarshal(tagCertBytes, &tagCert)

	tests := []struct {
		name         string
		signingKey   *rsa.PrivateKey
		hostManifest *hcTypes.HostManifest
	}{
		{
			name: "Nil Signing Key",
		},
		{
			name: "Invalid Signing Key",
		},
		{
			name: "Nil Host Manifest",
		},
	}

	// loop through the tests
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {

			switch tt.name {
			case "Nil Host Manifest":
				tt.hostManifest = nil
				tt.signingKey = sKey
			case "Nil Signing Key":
				tt.signingKey = nil
				tt.hostManifest = &hm
			case "Invalid Signing Key":
				tt.hostManifest = &hm
				tt.signingKey = &rsa.PrivateKey{
					PublicKey: rsa.PublicKey{
						N: nil,
						E: 0,
					},
					D:      nil,
					Primes: []*big.Int{big.NewInt(int64(55)), big.NewInt(int64(44))},
				}
			}

			pffactory, err := NewPlatformFlavorProvider(tt.hostManifest, nil)

			pflavor, err := pffactory.GetPlatformFlavor()
			// if Nil Host Manifest - we expect this step to fail
			if tt.name == "Nil Host Manifest" {
				assert.Error(t, err, "Nil Host Manifest Did not fail as expected")
			} else {
				assert.NotNil(t, pflavor, "Error initializing PlatformFlavor")

				// Sign the flavor - if Nil Signed Flavor or Invalid Signing Key we expect this step to fail
				_, err = (*pflavor).(types.LinuxPlatformFlavor).GetFlavorPart(cf.Platform, tt.signingKey)
				if tt.name == "Nil Signing Key" || tt.name == "Invalid Signing Key" {
					assert.Error(t, err, "Invalid Singing Key Did not fail as expected")
				}
			}
		})
	}
}

// TestSoftwareFlavor_Failure validates GetSoftwareFlavor()
func TestSoftwareFlavor_Failure(t *testing.T) {
	var sf types.SoftwareFlavor
	// load flavor
	softwareFile, _ := os.Open(BadSoftwareFlavor)
	sfBytes, _ := ioutil.ReadAll(softwareFile)

	sf = types.SoftwareFlavor{
		Measurement: string(sfBytes),
	}
	sfg, err := sf.GetSoftwareFlavor()
	assert.Error(t, err, "Error expected for invalid software flavor")
	t.Log(sfg)
}
