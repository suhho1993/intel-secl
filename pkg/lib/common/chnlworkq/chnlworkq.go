/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */

// chnlworkq package makes work queues based on channels using a double linked list as internal storage
package chnlworkq

import (
	"container/list"
	"sync"
)
import (
	"errors"
)

type procReq = func(interface{}) interface{}
type procWork = func(interface{})

// New make a work queue. It creates a channel that can be used to submit requests and another channel from which
// queued items can be pulled out. Here internal storage (using double linked list) is used instead of allocating a
// fixed sized for channel buffer. The size of the queue can grow and shrink based on the contents currently in the queue.
// reqBufSize and workBufSize represents the  buffer size of the channel. Consider the size of these to avoid goroutines
// going to sleep in between since items have not been pulled out from the channel.
// procReq is a callback function that can be used to process a request and return an object that is to be stored within
// the queue data structure.
func New(reqBufSize, workBufSize int, procReq procReq, procWork procWork, quit chan struct{}, wg *sync.WaitGroup) (chan interface{}, chan interface{}, error) {

	req, work := make(chan interface{}, reqBufSize), make(chan interface{}, workBufSize)
	if wg == nil {
		return nil, nil, errors.New("Waitgroup cannot be nil")
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		l := list.New()
		var w interface{}
		for {
			if l.Len() == 0 {
				select {
				case <-quit:
					return
				case r := <-req:
					if procReq != nil {
						w = procReq(r)
					} else {
						w = r
					}
				}
			}
			select {
			case <-quit:
				return
			case r := <-req:
				if procReq != nil {
					l.PushBack(procReq(r))
				} else {
					l.PushBack(r)
				}
			case work <- w:
				if procWork != nil {
					procWork(w)
				}
				if l.Len() != 0 {
					w = l.Remove(l.Front())
				}

			}

		}

	}()
	return req, work, nil

}
