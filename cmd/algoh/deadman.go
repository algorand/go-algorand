// Copyright (C) 2019 Algorand, Inc.
// This file is part of go-algorand
//
// go-algorand is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as
// published by the Free Software Foundation, either version 3 of the
// License, or (at your option) any later version.
//
// go-algorand is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with go-algorand.  If not, see <https://www.gnu.org/licenses/>.

package main

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/algorand/go-algorand/daemon/algod/api/spec/v1"
	"github.com/algorand/go-algorand/logging/telemetryspec"
)

type deadManWatcher struct {
	timeout       time.Duration
	newBlockChan  chan uint64
	uploadOnError bool
	client        Client
	done          <-chan struct{}
	wg            *sync.WaitGroup
}

func makeDeadManWatcher(timeout int64, client Client, uploadOnError bool, done <-chan struct{}, wg *sync.WaitGroup) deadManWatcher {
	var deadManTime time.Duration
	if timeout == 0 {
		deadManTime = time.Hour * (10 * 365 * 24) // Don't fire for 10 years
	} else {
		deadManTime = time.Duration(timeout) * time.Second
	}

	return deadManWatcher{
		timeout:       deadManTime,
		newBlockChan:  make(chan uint64),
		client:        client,
		uploadOnError: uploadOnError,
		done:          done,
		wg:            wg,
	}
}

func (w deadManWatcher) init(initBlock uint64) {
	go w.run(initBlock)
}

func (w deadManWatcher) run(initBlock uint64) {
	defer w.wg.Done()
	latestBlock := initBlock

	var deadManTimeout <-chan time.Time

	for {
		select {
		case block := <-w.newBlockChan:
			latestBlock = block
			deadManTimeout = time.After(w.timeout)
		case <-w.done:
			return
		case <-deadManTimeout:
			deadManTimeout = nil // Don't detect deadlock again until after we see another block

			err := w.reportDeadManTimeout(latestBlock)
			// If err is not nil, algod failed to respond to goroutine request
			// This is a critical failure - hopefully telemetry and logging will capture
			// the details, but the best thing we can do is try to shut it down.
			if err != nil {
				nc := getNodeController()
				nc.FullStop()
			}
		}
	}
}

func (w deadManWatcher) onBlock(block v1.Block) {
	w.newBlockChan <- block.Round
}

func (w deadManWatcher) reportDeadManTimeout(curBlock uint64) (err error) {
	goRoutines, err := getGoRoutines(w.client)
	if err != nil {
		goRoutines = fmt.Sprintf("Error dumping goroutines: %v", err)
	}

	details := telemetryspec.DeadManTriggeredEventDetails{
		Timeout:      int64(w.timeout.Seconds()),
		CurrentBlock: curBlock,
		GoRoutines:   goRoutines,
	}
	log.EventWithDetails(telemetryspec.HostApplicationState, telemetryspec.DeadManTriggeredEvent, details)

	if w.uploadOnError {
		sendLogs()
	}
	return
}

func getGoRoutines(client Client) (goRoutines string, err error) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	goRoutines, err = client.GetGoRoutines(ctx)
	if ctx.Err() == context.DeadlineExceeded {
		err = fmt.Errorf("timed out requesting goroutines")
	}
	return
}
