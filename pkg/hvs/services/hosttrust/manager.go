/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */

package hosttrust

import (
	"context"
	"fmt"
	"github.com/google/uuid"
	"github.com/intel-secl/intel-secl/v3/pkg/hvs/domain"
	"github.com/intel-secl/intel-secl/v3/pkg/hvs/domain/models"
	"github.com/intel-secl/intel-secl/v3/pkg/hvs/domain/models/taskstage"
	"github.com/intel-secl/intel-secl/v3/pkg/lib/common/chnlworkq"
	commLog "github.com/intel-secl/intel-secl/v3/pkg/lib/common/log"
	"github.com/intel-secl/intel-secl/v3/pkg/lib/host-connector/types"
	"github.com/intel-secl/intel-secl/v3/pkg/model/hvs"
	"github.com/pkg/errors"
	"sync"
)

var defaultLog = commLog.GetDefaultLogger()
var secLog = commLog.GetSecurityLogger()

type verifyTrustJob struct {
	ctx             context.Context
	cancelFn        context.CancelFunc
	host            *hvs.Host
	storPersistId   uuid.UUID
	getNewHostData  bool
	preferHashMatch bool
}

type newHostFetch struct {
	ctx    context.Context
	hostId uuid.UUID
	data   *types.HostManifest
}

type Service struct {
	// channel that hold requests that came back from host data fetch
	hfRqstChan chan interface{}
	// channel that hold queued flavor verify that came back from host data fetch.
	// The workers processing this do not need to get the data from the store.
	// It is already in the channel
	hfWorkChan chan interface{}
	// request channel is used to route requests into internal queue
	rqstChan chan interface{}
	// work items (their id) is pulled out of a queue and fed to the workers
	workChan chan interface{}
	// map that holds all the hosts that needs trust verification.
	hosts map[uuid.UUID]*verifyTrustJob
	// mutex for map
	mapmtx sync.RWMutex
	//
	prstStor        domain.QueueStore
	hdFetcher       domain.HostDataFetcher
	hostStore       domain.HostStore
	verifier        domain.HostTrustVerifier
	hostStatusStore domain.HostStatusStore
	// waitgroup used to wait for workers to finish up when signal for shutdown comes in
	wg          sync.WaitGroup
	quit        chan struct{}
	serviceDone bool
}

func NewService(cfg domain.HostTrustMgrConfig) (*Service, domain.HostTrustManager, error) {
	svc := &Service{prstStor: cfg.PersistStore,
		hdFetcher:       cfg.HostFetcher,
		hostStore:       cfg.HostStore,
		verifier:        cfg.HostTrustVerifier,
		hostStatusStore: cfg.HostStatusStore,
		quit:            make(chan struct{}),
		hosts:           make(map[uuid.UUID]*verifyTrustJob),
	}
	var err error
	nw := cfg.Verifiers
	if svc.rqstChan, svc.workChan, err = chnlworkq.New(nw, nw, nil, nil, svc.quit, &svc.wg); err != nil {
		return nil, nil, errors.New("hosttrust:NewService:Error starting work queue")
	}
	if svc.hfRqstChan, svc.hfWorkChan, err = chnlworkq.New(nw, nw, nil, nil, svc.quit, &svc.wg); err != nil {
		return nil, nil, errors.New("hosttrust:NewService:Error starting work queue")
	}

	// start go routines
	svc.startWorkers(cfg.Verifiers)
	return svc, svc, nil
}

// Function to Shutdown service. Will wait for pending host data fetch jobs to complete
// Will not process any further requests. Calling interface Async methods will result in error
func (svc *Service) Shutdown() error {
	svc.serviceDone = true
	close(svc.quit)
	svc.wg.Wait()

	return nil
}

func (svc *Service) startWorkers(workers int) {
	// start worker go routines

	for i := 0; i < workers; i++ {
		svc.wg.Add(1)
		go svc.doWork()
	}
}

func (svc *Service) VerifyHost(hostId uuid.UUID, fetchHostData, preferHashMatch bool) (interface{}, error) {
	return nil, errors.New("hosttrust/Manager: VerifyHost Not implemented")
}

func (svc *Service) VerifyHostsAsync(hostIds []uuid.UUID, fetchHostData, preferHashMatch bool) error {

	adds := make([]uuid.UUID, 0, len(hostIds))
	updates := []uuid.UUID{}

	// iterate through the hosts and check if there is an existing entry
	for _, hid := range hostIds {
		svc.mapmtx.RLock()
		vtj, found := svc.hosts[hid]
		svc.mapmtx.RUnlock()
		if found {
			prevJobStage, _ := taskstage.FromContext(vtj.ctx)
			if shouldCancelPrevJob(fetchHostData, vtj.getNewHostData, prevJobStage) {
				// cancel the curr Job and make a new entry
				vtj.cancelFn()
				updates = append(updates, hid)
			}
			continue
		} else {
			adds = append(adds, hid)
		}
	}
	if err := svc.persistToStore(adds, updates, fetchHostData, preferHashMatch); err != nil {
		return errors.Wrap(err, "hosttrust:Service:persistRequest - error in Persisting to Store")
	}
	// at this point, it is safe to return the async call as the records have been persisted.
	// TODO : add to channel for host data fetch and flavor verification
	if fetchHostData {
		svc.wg.Add(1)
		go svc.submitHostDataFetch(adds)
	} else {
		go svc.queueFlavorVerify(adds, updates)
	}
	return nil
}

func (svc *Service) submitHostDataFetch(hostLists ...[]uuid.UUID) {
	defer svc.wg.Done()
	for _, hosts := range hostLists {
		// since current store method only support searching one record at a time, use that.
		// TODO: update to builk retrieve host records when store method supports it. In this case, iterate by
		// result from the host store.
		for _, hId := range hosts {
			if host, err := svc.hostStore.Retrieve(hId); err != nil {
				defaultLog.Info("hosttrust:Service:submitHostDataFetch - error retrieving host data for id", hId)
				continue
			} else {
				svc.mapmtx.Lock() //  need to update the record - so take a write lock
				vtj, ok := svc.hosts[hId]
				if !ok {
					svc.mapmtx.Unlock()
					defaultLog.Error("hosttrust:Service:submitHostDataFetch - Unexpected error retrieving map entry for id:", hId)
					continue
				}
				vtj.host = host
				svc.mapmtx.Unlock()
				if err := svc.hdFetcher.RetriveAsync(vtj.ctx, *vtj.host, svc); err != nil {
					defaultLog.Error("hosttrust:Service:submitHostDataFetch - error calling RetrieveAsync", hId)
				}
			}
		}
	}
}

func (svc *Service) queueFlavorVerify(hostsLists ...[]uuid.UUID) {
	for _, hosts := range hostsLists {
		// unlike the submitHostDataFetch, this one needs to be processed one at a time.
		for _, hId := range hosts {
			// here the map already has the information that we need to start the job. The host data
			// is not available - but the worker thread should just retrieve it individually from the
			// go routine. So, all we have to do is submit requests
			svc.rqstChan <- hId
			// the go routine that manages the work queue will process the request. It only blocks till the
			// request is copied to the interal queue
		}
	}
}

func (svc *Service) persistToStore(additions, updates []uuid.UUID, fetchHostData, preferHashMatch bool) error {
	strRec := &models.Queue{Action: "flavor-verify",
		Params: map[string]interface{}{"host_id": uuid.UUID{}, "fetch_host_data": fetchHostData, "prefer_hash_match": preferHashMatch},
		State:  models.QueueStatePending,
	}

	persistRecords := func(lst []uuid.UUID, create bool) error {
		for _, hid := range lst {
			var err error
			if create {
				strRec.Id = uuid.UUID{}
				strRec.Params["host_id"] = hid
				if strRec, err = svc.prstStor.Create(strRec); err != nil {
					return errors.Wrap(err, "hosttrust:Service:persistToStore - Could not create record")
				}

			} else {
				svc.mapmtx.RLock()
				strRec.Id = svc.hosts[hid].storPersistId
				svc.mapmtx.RUnlock()
				if err = svc.prstStor.Update(strRec); err != nil {
					return errors.Wrap(err, "hosttrust:Service:persistRequest - Could not update record")
				}
			}
			ctx, cancel := context.WithCancel(context.Background())
			svc.mapmtx.Lock()
			// the host field is not filled at this stage since it requires a trip to the host store
			svc.hosts[hid] = &verifyTrustJob{ctx, cancel, nil, strRec.Id,
				fetchHostData, preferHashMatch}
			svc.mapmtx.Unlock()
		}
		return nil
	}
	if err := persistRecords(additions, true); err != nil {
		return errors.Wrap(err, "hosttrust:Service:persistRequest - persistRecords additions error")
	}
	if err := persistRecords(updates, false); err != nil {
		return errors.Wrap(err, "hosttrust:Service:persistRequest - persistRecords updates error")
	}

	return nil
}

// function that does the actual work. There are two seperate channels that contains work.
// First one is the flavor verification work submitted that does not require new host data
// Second one is work that first requires new data from host.
// In the first case, the host data has to be retrieved from the store.
// second case, the host data is already available in the work channel - so there is no
// need to fetch from the store.
func (svc *Service) doWork() {

	defer svc.wg.Done()

	// receive id of queued work over the channel.
	// Fetch work context from the map.
	for {
		var hostId uuid.UUID
		var hostData *types.HostManifest
		newData := false

		select {

		case <-svc.quit:
			// we have received a quit. Don't process anymore items - just return
			return

		case id := <-svc.workChan:
			if hId, ok := id.(uuid.UUID); ok {
				defaultLog.Error("hosttrust:doWork:expecting uuid from channel - but got different type")
				return
			} else if status, err := svc.hostStatusStore.Retrieve(hId); err != nil {
				defaultLog.Error("hosttrust:doWork: - could not retrieve host data from store - error :", err)
				return
			} else {
				hostId = hId
				hostData = &status.HostManifest
			}

		case data := <-svc.hfWorkChan:
			if hData, ok := data.(newHostFetch); !ok {
				defaultLog.Error("hosttrust:doWork:expecting newHostFetch type from channel - but got different one")
				return
			} else {
				hostId = hData.hostId
				hostData = hData.data
				newData = true
			}

		}
		svc.verifyHostData(hostId, hostData, newData)
	}
}

// This function kicks of the verification process given a manifest
func (svc *Service) verifyHostData(hostId uuid.UUID, data *types.HostManifest, newData bool) {
	//check if the job has not already been cancelled
	svc.mapmtx.Lock()
	vtj := svc.hosts[hostId]
	select {
	// remove the requests that have already been cancelled.
	case <-vtj.ctx.Done():
		fmt.Println("Host Flavor verification is cancelled for host id", hostId, "...continuing to next one")
		svc.mapmtx.Unlock()
		return
	default:
		taskstage.StoreInContext(vtj.ctx, taskstage.FlavorVerifyStarted)
	}
	svc.mapmtx.Unlock()

	svc.verifier.Verify(hostId, data, newData)

}

// This function is the implementation of the HostDataReceiver interface method. Just create a new request
// to process the newly obtained data and it will be submitted to the verification queue
func (svc *Service) ProcessHostData(ctx context.Context, host hvs.Host, data *types.HostManifest, err error) error {
	select {
	case <-ctx.Done():
		return nil
	default:
	}
	// queue the new data to be processed by one of the worker threads by adding this to the queue
	taskstage.StoreInContext(ctx, taskstage.FlavorVerifyQueued)
	svc.hfRqstChan <- newHostFetch{
		ctx:    ctx,
		hostId: host.Id,
		data:   data,
	}
	return nil
}

func shouldCancelPrevJob(newJobNeedFreshHostData, prevJobNeededFreshData bool, prevJobStage taskstage.Stage) bool {
	//TODO: implement
	return true
}
