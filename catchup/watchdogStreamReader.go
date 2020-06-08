// Copyright (C) 2019-2020 Algorand, Inc.
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

package catchup

import (
	"fmt"
	"io"
	"sync"
	"time"

	"github.com/algorand/go-deadlock"
)

// ErrWatchdogStreamReaderTimerElapsed is returned when the watchdogStreamReader was not reset in the past readaheadDuration and read was attempted
var ErrWatchdogStreamReaderTimerElapsed = fmt.Errorf("watchdog stream reader timer elapsed")

// ErrWatchdogStreamReaderReaderReachedDataLimit is returned when watchdogStreamReader was asked to read beyond the designated data limits
var ErrWatchdogStreamReaderReaderReachedDataLimit = fmt.Errorf("watchdog stream reader reached data limit")

type watchdogStreamReader struct {
	// watchdog configuration
	underlayingReader io.Reader     // the underlaying data source
	readSize          uint64        // the amount of data we would attempt to read from the source on each iteration
	readaheadSize     uint64        // the total maximum data allowed to be read from the source at any given time between Resets call
	readaheadDuration time.Duration // the timeout at which the watchdog would signal the read to be aborted.

	stageBuffer []byte // the staging buffer
	readError   error  // the outgoing reported error ( either coming from the underlaying data source or self-generated )
	totalRead   uint64 // the total amount of bytes read from the data source so far.

	maxDataSize   uint64 // the current high threshold for data reader
	readerClose   chan struct{}
	tickerClose   chan struct{}
	readerRequest chan struct{}
	readerMu      deadlock.Mutex
	readerCond    *sync.Cond
}

func makeWatchdogStreamReader(underlayingReader io.Reader, readSize uint64, readaheadSize uint64, readaheadDuration time.Duration) *watchdogStreamReader {
	reader := &watchdogStreamReader{
		underlayingReader: underlayingReader,
		readerClose:       make(chan struct{}, 1),
		tickerClose:       make(chan struct{}), // create a non-buffered channel
		readerRequest:     make(chan struct{}, 1),
		totalRead:         0,
		readSize:          readSize,
		readaheadDuration: readaheadDuration,
		readaheadSize:     readaheadSize,
		maxDataSize:       readaheadSize + readSize,
	}
	reader.readerCond = sync.NewCond(&reader.readerMu)
	go reader.puller()
	go reader.ticker()
	return reader
}

func (r *watchdogStreamReader) Reset() error {
	r.readerMu.Lock()
	if r.readError != nil && len(r.stageBuffer) == 0 {
		defer r.readerMu.Unlock()
		return r.readError
	}
	r.maxDataSize = r.totalRead + r.readaheadSize
	r.readerMu.Unlock()
	r.tickerClose <- struct{}{}
	go r.ticker()
	return nil
}

func (r *watchdogStreamReader) Read(p []byte) (n int, err error) {
	r.readerMu.Lock()
	defer r.readerMu.Unlock()
	for {
		// did we get either timeout, error or some data ?
		if len(r.stageBuffer) > 0 || r.readError != nil {
			break
		}
		r.readerRequest <- struct{}{}
		r.readerCond.Wait()
	}
	if len(r.stageBuffer) > 0 {
		// copy the data to the buffer p
		n = len(p)
		if n > len(r.stageBuffer) {
			n = len(r.stageBuffer)
		}
		copy(p, r.stageBuffer)
		r.stageBuffer = r.stageBuffer[n:]
	}
	if n < len(p) || (len(p) == 0 && len(r.stageBuffer) == 0) {
		err = r.readError
	}
	return
}

func (r *watchdogStreamReader) ticker() {
	timerCh := time.After(r.readaheadDuration)
	select {
	case <-timerCh:
		// timer has expired.
		r.readerMu.Lock()
		r.readError = ErrWatchdogStreamReaderTimerElapsed
		r.readerMu.Unlock()
		r.readerCond.Broadcast()

		// wait for the channel to get closed.
		<-r.tickerClose
	case <-r.tickerClose:
	}
}

func (r *watchdogStreamReader) puller() {
	var n int
	for err := error(nil); err == nil; {
		// if the close channel is closed, exit the function.
		select {
		case <-r.readerClose:
			return
		case <-r.readerRequest:
		}
		// otherwise, keep reading from the input channel.
		localBuf := make([]byte, r.readSize)
		n, err = r.underlayingReader.Read(localBuf)
		r.readerMu.Lock()
		if n > 0 {
			r.stageBuffer = append(r.stageBuffer, localBuf[:n]...)
			r.totalRead += uint64(n)
			if r.totalRead > r.maxDataSize {
				err = fmt.Errorf("watchdogStreamReader exceeded data size limit")
			}
		}
		r.readError = err
		r.readerMu.Unlock()
		r.readerCond.Broadcast()
	}
}

func (r *watchdogStreamReader) Close() {
	// signal the puller goroutine to shut down
	close(r.readerClose)
	// signal the ticker goroutine to shut down
	r.tickerClose <- struct{}{}
}
