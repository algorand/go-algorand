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
	"fmt"
	"testing"
	"time"

	"github.com/algorand/go-deadlock"

	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/logging"
)

func TestDeadlockLogging(t *testing.T) {
	logFn := fmt.Sprintf("/tmp/test.%s.%d.log", t.Name(), crypto.RandUint64())
	archiveFn := fmt.Sprintf("%s.archive", logFn)

	l := logging.Base()
	logWriter := logging.MakeCyclicFileWriter(logFn, archiveFn, 65536, time.Hour)
	l.SetOutput(logWriter)

	logger := setupDeadlockLogger()

	deadlockCh := make(chan struct{})
	logger.panic = func() {
		close(deadlockCh)
	}

	var mu deadlock.RWMutex
	defer func() {
		r := recover()
		if r != nil {
			fmt.Printf("Recovered: %v\n", r)
		}
	}()

	mu.RLock()
	mu.RLock()

	_ = <-deadlockCh
}

func TestDeadlockOnPotentialDeadlock(t *testing.T) {
	logFn := fmt.Sprintf("/tmp/test.%s.%d.log", t.Name(), crypto.RandUint64())
	archiveFn := fmt.Sprintf("%s.archive", logFn)

	l := logging.Base()
	logWriter := logging.MakeCyclicFileWriter(logFn, archiveFn, 65536, time.Hour)
	l.SetOutput(logWriter)

	logger := setupDeadlockLogger()

	deadlockCh := make(chan struct{})
	logger.panic = func() {
		close(deadlockCh)
	}

	defer func() {
		r := recover()
		if r != nil {
			fmt.Printf("Recovered: %v\n", r)
		}
	}()

	for linenum := 0; linenum < 10; linenum++ {
		fmt.Fprintf(logger, "line %d", linenum)
	}
	logger.onPotentialDeadlock()
	for linenum := 10; linenum < 20; linenum++ {
		fmt.Fprintf(logger, "line %d", linenum)
	}

	_ = <-deadlockCh
}
