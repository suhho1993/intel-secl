/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */

package hosttrust

import (
	"fmt"
	"github.com/google/uuid"
	"github.com/intel-secl/intel-secl/v3/pkg/hvs/domain"
	"github.com/intel-secl/intel-secl/v3/pkg/hvs/domain/mocks"
	"github.com/intel-secl/intel-secl/v3/pkg/hvs/domain/models"
	hostfetcher "github.com/intel-secl/intel-secl/v3/pkg/hvs/services/host-fetcher"
	"github.com/intel-secl/intel-secl/v3/pkg/model/hvs"
	"github.com/stretchr/testify/assert"
	"time"

	"testing"
)

func TestHostTrustManagetNewService(t *testing.T) {

	qs := mocks.NewQueueStore()
	hs := mocks.NewHostStore()
	newHost, err := hs.Create(&hvs.Host{
		HostName:         "10.105.245.85",
		Description:      "Host at 10.105.245.85",
		ConnectionString: "intel://10.105.245.85/ta",
		HardwareUuid:     uuid.New(),
	})
	assert.NoError(t, err)
	hrec, err := hs.Retrieve(newHost.Id)
	fmt.Println(hrec)
	assert.NoError(t, err)

	//qs.Create(&models.Queue{})

	cfg := models.HostDataFetcherConfig{}
	_, f, _ := hostfetcher.NewService(cfg, 5)

	_, ht, _ := NewService(domain.HostTrustMgrConfig{
		PersistStore: qs,
		HostStore:    hs,
		HostFetcher:  f,
		Verifiers:    5,
	})

	err = ht.VerifyHostsAsync([]uuid.UUID{newHost.Id}, true, false)
	assert.NoError(t, err)
	time.Sleep(time.Duration(20 * time.Second))

	qrecs, err := qs.Search(&models.QueueFilterCriteria{})
	assert.NoError(t, err)
	for _, qrec := range qrecs {
		fmt.Println(*qrec)
	}

}
