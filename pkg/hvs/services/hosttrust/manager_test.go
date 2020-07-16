/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */

package hosttrust_test

import (
	"encoding/json"
	"fmt"
	"github.com/google/uuid"
	"github.com/intel-secl/intel-secl/v3/pkg/hvs/domain"
	"github.com/intel-secl/intel-secl/v3/pkg/hvs/domain/mocks"
	"github.com/intel-secl/intel-secl/v3/pkg/hvs/domain/models"
	hostfetcher "github.com/intel-secl/intel-secl/v3/pkg/hvs/services/host-fetcher"
	"github.com/intel-secl/intel-secl/v3/pkg/hvs/services/hosttrust"
	hc "github.com/intel-secl/intel-secl/v3/pkg/lib/host-connector"
	hcTypes "github.com/intel-secl/intel-secl/v3/pkg/lib/host-connector/types"
	libVerifier "github.com/intel-secl/intel-secl/v3/pkg/lib/verifier"
	"github.com/intel-secl/intel-secl/v3/pkg/model/hvs"
	"github.com/stretchr/testify/assert"
	"io/ioutil"
	"time"

	"testing"
)

func TestHostTrustManagerNewService(t *testing.T) {

	qs := mocks.NewQueueStore()
	hs := mocks.NewMockHostStore()
	hss := mocks.NewFakeHostStatusStore()

	newHost, err := hs.Create(&hvs.Host{
		HostName:         "test.domain.com",
		Description:      "Host at test.domain.com",
		ConnectionString: "intel://test.domain.com/ta",
		HardwareUuid:     uuid.New(),
	})
	assert.NoError(t, err)
	hrec, err := hs.Retrieve(newHost.Id)
	fmt.Println(hrec)
	assert.NoError(t, err)

	//qs.Create(&models.Queue{})

	cfg := domain.HostDataFetcherConfig{
		HostConnectorFactory: hc.HostConnectorFactory{},
		RetryTimeMinutes:     7,
		HostStatusStore:      hss,
	}
	_, f, _ := hostfetcher.NewService(cfg, 5)

	fv := hosttrust.NewVerifier(domain.HostTrustVerifierConfig{})
	_, ht, _ := hosttrust.NewService(domain.HostTrustMgrConfig{
		PersistStore:      qs,
		HostStore:         hs,
		HostFetcher:       f,
		Verifiers:         5,
		HostTrustVerifier: fv,
	})

	err = ht.VerifyHostsAsync([]uuid.UUID{newHost.Id}, true, false)
	assert.NoError(t, err)
	time.Sleep(time.Duration(5 * time.Second))

	qrecs, err := qs.Search(&models.QueueFilterCriteria{})
	assert.NoError(t, err)
	for _, qrec := range qrecs {
		fmt.Println(*qrec)
	}

}

func TestVerifier_Verify(t *testing.T) {

	hostStore := mocks.NewMockHostStore()
	hwUuid := uuid.MustParse("0005AE6E-36D6-E711-906E-001560A04062")
	hostId := uuid.MustParse("204466f6-8611-4e03-934d-832172a41917")
	_, err := hostStore.Create(&hvs.Host{
		HostName:         "hostname",
		Description:      "Host at test.domain.com",
		ConnectionString: "intel://test.domain.com/ta",
		HardwareUuid:     hwUuid,
		Id:               hostId,
	})
	assert.NoError(t, err)

	var fgIds []uuid.UUID
	//Add flavorgroup hvs_flavorgroup_test1 having flavor types platform, os and software to host
	fgIds = append(fgIds, uuid.MustParse("ee37c360-7eae-4250-a677-6ee12adce8e2"))
	//Add flavorgroup hvs_flavorgroup_test2 having flavor types host_unique to host
	fgIds = append(fgIds, uuid.MustParse("e57e5ea0-d465-461e-882d-1600090caa0d"))
	hostStore.AddFlavorgroups(hostId, fgIds)

	flavorStore := mocks.NewFakeFlavorStoreWithAllFlavors("../../../lib/verifier/test_data/intel20/signed_flavors.json")
	flavorgroupStore := mocks.NewFakeFlavorgroupStore()
	flavorgroupStore.HostFlavorgroupStore = hostStore.HostFlavorgroupStore

	var fIds []uuid.UUID
	//platform flavor
	fIds = append(fIds, uuid.MustParse("890bc756-40da-4bde-a707-3b27b23e0149"))
	// os flavor
	fIds = append(fIds, uuid.MustParse("71e4c52e-595a-429d-9917-1965b437c353"))
	// software flavor
	fIds = append(fIds, uuid.MustParse("339a7ac6-b8be-4356-ab34-be6e3bdfa1ed"))
	// flavor group with software and platform
	flavorgroupStore.AddFlavors(uuid.MustParse("ee37c360-7eae-4250-a677-6ee12adce8e2"), fIds)

	fIds = make([]uuid.UUID, 1)
	// host_unique flavor
	fIds = append(fIds, uuid.MustParse("6762b4e2-fa3a-4e57-b3ff-733600c6dadc"))
	//Add host_unique flavor to host_unique flavorgroup
	flavorgroupStore.AddFlavors(uuid.MustParse("e57e5ea0-d465-461e-882d-1600090caa0d"), fIds)
	flavorStore.FlavorgroupStore = flavorgroupStore.FlavorgroupStore
	flavorStore.FlavorFlavorGroupStore = flavorgroupStore.FlavorgroupFlavorStore

	verifierCertificates := createVerifierCertificates(
		"../../../lib/verifier/test_data/intel20/PrivacyCA.pem",
		"../../../lib/verifier/test_data/intel20/flavor-signer.crt.pem",
		"../../../lib/verifier/test_data/intel20/cms-ca-cert.pem",
		"../../../lib/verifier/test_data/intel20/tag-cacerts.pem")

	flvrVerifier, _ := libVerifier.NewVerifier(*verifierCertificates)

	htv := domain.HostTrustVerifierConfig{
		FlavorStore:         flavorStore,
		FlavorGroupStore:    flavorgroupStore,
		HostStore:           hostStore,
		ReportStore:         mocks.NewEmptyMockReportStore(),
		FlavorVerifier:      flvrVerifier,
		SamlIssuerConfig:    *getIssuer(),
		SkipFlavorSignature: true,
	}
	v := hosttrust.NewVerifier(htv)

	var hostManifest hcTypes.HostManifest
	manifestJSON, _ := ioutil.ReadFile("../../../lib/verifier/test_data/intel20/host_manifest.json")
	json.Unmarshal(manifestJSON, &hostManifest)

	report, err := v.Verify(hostId, &hostManifest, false)
	fmt.Println(report.TrustReport.Trusted)
	assert.Equal(t, report.TrustReport.Trusted, true)
	fmt.Println(report.Saml)
	assert.NoError(t, err)
}
