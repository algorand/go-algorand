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

package main

import (
	"context"
	"math/rand"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/mux"
	"github.com/stretchr/testify/require"
)

type mockFactory struct{}

type testServerDebugFrontend struct {
	debugger      Control
	notifications chan Notification
}

func (t testServerDebugFrontend) SessionStarted(sid string, debugger Control, ch chan Notification) {
	t.notifications = ch
	t.debugger = debugger
	go t.eventLoop()
}

func (t testServerDebugFrontend) SessionEnded(sid string) {
}

func (t testServerDebugFrontend) WaitForCompletion() {
}

func (t testServerDebugFrontend) URL() string {
	return ""
}

func (t testServerDebugFrontend) eventLoop() {
	for {
		select {
		case n := <-t.notifications:
			if n.Event == "completed" {
				return
			}
			if n.Event == "registered" {
			}
			// simulate user delay to workaround race cond
			time.Sleep(10 * time.Millisecond)
			t.debugger.Resume()
		}
	}
}

func (f *mockFactory) Make(router *mux.Router, appAddress string) (da DebugAdapter) {
	return testServerDebugFrontend{}
}

func tryStartingServerRemote(t *testing.T, ds *DebugServer) (ok bool) {
	res := make(chan bool)
	go func() {
		defer func() {
			if r := recover(); r != nil {
				res <- false
			}
		}()
		err := ds.startRemote()
		require.NoError(t, err)
		res <- true
	}()

	time.Sleep(500 * time.Millisecond)
	err := ds.server.Shutdown(context.Background())
	require.NoError(t, err)

	ok = <-res
	return
}

func tryStartingServerDebug(t *testing.T, ds *DebugServer) (ok bool) {
	defer func() {
		if r := recover(); r != nil {
			ok = false
		}
	}()
	err := ds.startDebug()
	require.NoError(t, err)
	ok = true
	return
}

func serverTestImpl(t *testing.T, run func(t *testing.T, ds *DebugServer) bool, dp *DebugParams) {
	maxPortNum := 65000
	minPortNum := 40000
	attempt := 0
	started := false
	var ds DebugServer
	for attempt < 5 && !started {
		port = rand.Intn(maxPortNum-minPortNum) + minPortNum
		ds = makeDebugServer(port, &mockFactory{}, dp)
		started = run(t, &ds)
		attempt++
	}

	require.True(t, started)
	require.NotEmpty(t, ds)
	require.NotNil(t, ds.debugger)
	require.NotNil(t, ds.router)
	require.NotNil(t, ds.server)
}

func TestServerRemote(t *testing.T) {
	serverTestImpl(t, tryStartingServerRemote, &DebugParams{})
}

func TestServerLocal(t *testing.T) {
	txnBlob := []byte("[" + strings.Join([]string{string(txnSample), txnSample}, ",") + "]")
	dp := DebugParams{
		ProgramNames: []string{"test"},
		ProgramBlobs: [][]byte{{2, 0x20, 1, 1, 0x22}}, // version, intcb, int 1
		TxnBlob:      txnBlob,
		GroupIndex:   0,
		RunMode:      "signature",
	}

	serverTestImpl(t, tryStartingServerDebug, &dp)
}
