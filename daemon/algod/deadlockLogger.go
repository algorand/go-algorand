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
}

func (logger *dumpLogger) dump() {
	logger.Error(logger.String())
}

var logger = dumpLogger{Logger: logging.Base(), Buffer: bytes.NewBuffer(make([]byte, 0))}

func setupDeadlockLogger() {
	deadlock.Opts.LogBuf = logger
	deadlock.Opts.OnPotentialDeadlock = func() {
		logger.dump()

		// Capture all goroutine stacks and log to stderr
		var buf []byte
		bufferSize := 256 * 1024
		for {
			buf = make([]byte, bufferSize)
			if runtime.Stack(buf, true) < bufferSize {
				break
			}
			bufferSize *= 2
		}
		fmt.Fprintln(os.Stderr, string(buf))
		logger.Panic("potential deadlock detected")
	}
}
