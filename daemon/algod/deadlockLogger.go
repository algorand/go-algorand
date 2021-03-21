// Copyright (C) 2019-2021 Algorand, Inc.
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

package algod

import (
	"bytes"
	"fmt"
	"os"
	"runtime"
	"sync"

	"github.com/algorand/go-deadlock"

	"github.com/algorand/go-algorand/logging"
)

type deadlockLogger struct {
	logging.Logger
	*bytes.Buffer
	bufferSync     chan struct{}
	panic          func()
	reportDeadlock sync.Once
}

// Panic is defined here just so we can emulate the usage of the deadlockLogger
func (logger *deadlockLogger) Panic() {
	logger.Logger.Panic("potential deadlock detected")
}

// Write implements the io.Writer interface, ensuring that the write is syncronized.
func (logger *deadlockLogger) Write(p []byte) (n int, err error) {
	logger.bufferSync <- struct{}{}
	n, err = logger.Buffer.Write(p)
	<-logger.bufferSync
	return
}

// captureCallstack captures the callstack and return a byte array of the output.
func captureCallstack() []byte {
	// Capture all goroutine stacks
	var buf []byte
	bufferSize := 256 * 1024
	for {
		buf = make([]byte, bufferSize)
		if runtime.Stack(buf, true) < bufferSize {
			break
		}
		bufferSize *= 2
	}
	return buf
}

// onPotentialDeadlock is the handler to be used by the deadlock library.
func (logger *deadlockLogger) onPotentialDeadlock() {
	// The deadlock reporting is done only once; this would prevent recursive deadlock issues.
	// in practive, once we report the deadlock, we panic and abort anyway, so it won't be an issue.
	logger.reportDeadlock.Do(func() {
		// Capture all goroutine stacks
		buf := captureCallstack()

		logger.bufferSync <- struct{}{}
		loggedString := logger.String()
		<-logger.bufferSync

		fmt.Fprintln(os.Stderr, string(buf))

		// logging the logged string to the logger has to happen in a separate go-routine, since the
		// logger itself ( for instance, the CyclicLogWriter ) is using a mutex of it's own.
		go func() {
			logger.Error(loggedString)
			logger.panic()
		}()
	})
}

func setupDeadlockLogger() *deadlockLogger {
	logger := &deadlockLogger{
		Logger:     logging.Base(),
		Buffer:     bytes.NewBuffer(make([]byte, 0)),
		bufferSync: make(chan struct{}, 1),
	}

	logger.panic = logger.Panic
	deadlock.Opts.LogBuf = logger
	deadlock.Opts.OnPotentialDeadlock = logger.onPotentialDeadlock
	return logger
}
