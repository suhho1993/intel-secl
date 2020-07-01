/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */

package hostfetcher

import (
	"context"
	"errors"
	"fmt"
	"github.com/google/uuid"
	"github.com/intel-secl/intel-secl/v3/pkg/hvs/domain"
	"github.com/intel-secl/intel-secl/v3/pkg/lib/common/chnlworkq"
	commLog "github.com/intel-secl/intel-secl/v3/pkg/lib/common/log"
	hc "github.com/intel-secl/intel-secl/v3/pkg/lib/host-connector"
	"github.com/intel-secl/intel-secl/v3/pkg/lib/host-connector/types"
	"github.com/intel-secl/intel-secl/v3/pkg/model/hvs"
	tamodel "github.com/intel-secl/intel-secl/v3/pkg/model/ta"
	"sync"
	"time"
)

var defaultLog = commLog.GetDefaultLogger()
var secLog = commLog.GetSecurityLogger()

type fetchRequest struct {
	ctx   context.Context
	host  hvs.Host
	rcvrs []domain.HostDataReceiver
}

type Service struct {
	Fetcher domain.HostDataFetcher
	// request channel is used to route requests into internal queue
	rqstChan chan interface{}
	// work items (their id) is pulled out of a queue and fed to the workers
	workChan chan interface{}
	// map that holds all hosts that need to be fetched.
	// The reason this is a map is that redundant requests can come in
	// that could theoretically be consolidated
	workMap map[uuid.UUID][]*fetchRequest
	// map is not protected access concurrent goroutine access. need a lock
	wmLock sync.Mutex
	// waitgroup used to wait for workers to finish up when signal for shutdown comes in
	wg sync.WaitGroup

	quit        chan struct{}
	serviceDone bool

	// pointer to object that implement host connector interface
	hc hc.HostConnector
}

func NewService(cfg domain.HostDataFetcherConfig, workers int) (*Service, domain.HostDataFetcher, error) {
	defaultLog.Trace("hostfetcher/Service:New() Entering")
	defer defaultLog.Trace("hostfetcher/Service:New() Leaving")

	defer defaultLog.Info("Started Host Data Fetcher with number of workers: ", workers)

	// setting size of channel to the same as number of workers.
	// this way, go routine can start work as soon as a current work is done
	svc := &Service{workMap: make(map[uuid.UUID][]*fetchRequest),
		quit: make(chan struct{}),
		hc:   cfg.HostConnector,
	}

	svc.Fetcher = svc
	var err error
	if svc.rqstChan, svc.workChan, err = chnlworkq.New(workers, workers, svc.addWorkToMap, nil, svc.quit, &svc.wg); err != nil {
		return nil, nil, errors.New("hostfetcher:NewService:Error starting work queue")
	}

	// start workers.. individual workers are spawned as go routines
	svc.startWorkers(workers)

	return svc, svc.Fetcher, nil
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

// function used to add work to the map. If there is a current entry
// append the new request to the already queued up requests
func (svc *Service) addWorkToMap(wrk interface{}) interface{} {
	fr := wrk.(*fetchRequest)
	svc.wmLock.Lock()
	if _, ok := svc.workMap[fr.host.Id]; !ok {
		svc.workMap[fr.host.Id] = append(svc.workMap[fr.host.Id], fr)
	} else {
		svc.workMap[fr.host.Id] = []*fetchRequest{fr}
	}
	svc.wmLock.Unlock()
	return fr.host.Id
}

// function that does the actual work. Receives id of host through work channel
// then pull records from the map, proceed to work unless requests are not already
// cancelled
func (svc *Service) doWork() {

	defer svc.wg.Done()

	// receive id of queued work over the channel.
	// Fetch work context from the map.
	for {
		select {
		case <-svc.quit:
			// we have received a quit. Don't process anymore items - just return
			return
		case id := <-svc.workChan:
			hId, ok := id.(uuid.UUID)
			if !ok {
				defaultLog.Error("hostfetcher:doWork:expecting uuid from channel - but got different type")
			}
			// iterate through work requests for this host. Usually, there will only be a single element in the
			// work list.
			svc.wmLock.Lock()
			ws := svc.workMap[hId]
			frs := append([]*fetchRequest{}, ws...)
			delete(svc.workMap, hId)
			svc.wmLock.Unlock()

			// TODO : move this out of here to the FetchDataAndRespond function
			getData := false
			for i, req := range frs {
				select {
				// remove the requests that have already been cancelled.
				case <-req.ctx.Done():
					frs = append(frs[:i], frs[i+1:]...)
					continue
				default:
					getData = true
				}
			}
			if getData {
				svc.FetchDataAndRespond(frs)
			} else {
				defaultLog.Info("Fetch data for ", hId, "cancelled")
			}
		}
	}
}

func (svc *Service) Retrieve(ctx context.Context, host hvs.Host) (*types.HostManifest, error) {
	return nil, errors.New("Not implemented")
}

func (svc *Service) RetriveAsync(ctx context.Context, host hvs.Host, rcvrs ...domain.HostDataReceiver) error {
	if svc.serviceDone {
		return errors.New("Host Fetcher has been shut down - cannot accept any more requests")
	}
	fr := &fetchRequest{ctx, host, rcvrs}
	// queue up the request
	svc.rqstChan <- fr
	return nil
}

func (svc *Service) FetchDataAndRespond(frs []*fetchRequest) {
	if len(frs) == 0 {
		return
	}
	hId := frs[0].host.Id
	//TODO: check if cancelled
	//TODO: update the state in the context to reflect that we are about to start processing
	fmt.Println("Getting data for ", hId, "using connection string", frs[0].host.ConnectionString)
	time.Sleep(time.Duration(5 * time.Second))
	for _, fr := range frs {
		select {
		case <-fr.ctx.Done():
			continue
		default:
		}
		for _, rcv := range fr.rcvrs {
			rcv.ProcessHostData(fr.ctx, fr.host, &types.HostManifest{
				// Todo - remove test data.
				HostInfo: tamodel.HostInfo{
					OSName:   "Redhat Linux",
					HostName: "test-host",
					BiosName: "test bios",
				},
			}, nil)
		}
	}
	// TODO: after work is completed, need to send result back to receivers if job not cancelled yet

}
