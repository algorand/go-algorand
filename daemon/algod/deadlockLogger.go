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

	"github.com/algorand/go-deadlock"

	"github.com/algorand/go-algorand/logging"
)

type dumpLogger struct {
	logging.Logger
	*bytes.Buffer
	bufferSync chan struct{}
}

func (logger *dumpLogger) dump() {
	logger.bufferSync <- struct{}{}
	outBuffer := logger.String()
	<-logger.bufferSync
	logger.Error(outBuffer)
}

// we need to implement the io.Writer interface so that we can syncronize access to underlying buffer/
func (logger *dumpLogger) Write(p []byte) (n int, err error) {
	logger.bufferSync <- struct{}{}
	n, err = logger.Buffer.Write(p)
	<-logger.bufferSync
	return
}

var logger = &dumpLogger{
	Logger:     logging.Base(),
	Buffer:     bytes.NewBuffer(make([]byte, 0)),
	bufferSync: make(chan struct{}, 1),
}

var deadlockPanic func()

func setupDeadlockLogger() {
	deadlockPanic = func() {
		logger.Panic("potential deadlock detected")
	}

	deadlock.Opts.LogBuf = logger
	deadlock.Opts.OnPotentialDeadlock = func() {
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

		// Run this code in a separate goroutine because it might grab locks.
		go func() {
			logger.dump()
			fmt.Fprintln(os.Stderr, string(buf))
			deadlockPanic()
		}()
	}
}
