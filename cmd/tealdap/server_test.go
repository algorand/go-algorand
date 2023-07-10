// Copyright (C) 2019-2023 Algorand, Inc.
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
	"bufio"
	"bytes"
	"github.com/algorand/go-algorand/test/partitiontest"
	"github.com/google/go-dap"
	"github.com/stretchr/testify/require"
	"log"
	"net"
	"sync"
	"testing"
	"time"
	// "github.com/stretchr/testify/require"
)

var initializeRequest = []byte(`{"seq":1,"type":"request","command":"initialize","arguments":{"clientID":"vscode","clientName":"Visual Studio Code","adapterID":"go","pathFormat":"path","linesStartAt1":true,"columnsStartAt1":true,"supportsVariableType":true,"supportsVariablePaging":true,"supportsRunInTerminalRequest":true,"locale":"en-us"}}`)
var initializedEvent = []byte(`{"seq":0,"type":"event","event":"initialized"}`)
var initializeResponse = []byte(`{"seq":0,"type":"response","request_seq":1,"success":true,"command":"initialize","body":{"supportsConfigurationDoneRequest":true}}`)

var launchRequest = []byte(`{"seq":2,"type":"request","command":"launch","arguments":{"noDebug": true,"name":"Launch","type":"go","request":"launch","mode":"debug","program":"/Users/foo/go/src/hello","__sessionId":"4c88179f-1202-4f75-9e67-5bf535cde30a","args":["somearg"],"env":{"GOPATH":"/Users/foo/go","HOME":"/Users/foo","SHELL":"/bin/bash"}}}`)
var launchResponse = []byte(`{"seq":0,"type":"response","request_seq":2,"success":true,"command":"launch"}`)

var setBreakpointsRequest = []byte(`{"seq":3,"type":"request","command":"setBreakpoints","arguments":{"source":{"name":"hello.go","path":"/Users/foo/go/src/hello/hello.go"},"lines":[7],"breakpoints":[{"line":7}],"sourceModified":false}}`)
var setBreakpointsResponse = []byte(`{"seq":0,"type":"response","request_seq":3,"success":true,"command":"setBreakpoints","body":{"breakpoints":[{"verified":true,"line":7}]}}`)

var setExceptionBreakpointsRequest = []byte(`{"seq":4,"type":"request","command":"setExceptionBreakpoints","arguments":{"filters":[]}}`)
var setExceptionBreakpointsResponse = []byte(`{"seq":0,"type":"response","request_seq":4,"success":true,"command":"setExceptionBreakpoints","body":{}}`)

var configurationDoneRequest = []byte(`{"seq":5,"type":"request","command":"configurationDone"}`)
var threadEvent = []byte(`{"seq":0,"type":"event","event":"thread","body":{"reason":"started","threadId":1}}`)
var configurationDoneResponse = []byte(`{"seq":0,"type":"response","request_seq":5,"success":true,"command":"configurationDone"}`)

var stoppedEvent = []byte(`{"seq":0,"type":"event","event":"stopped","body":{"reason":"breakpoint","threadId":1,"allThreadsStopped":true}}`)

var stackTraceRequest = []byte(`{"seq":7,"type":"request","command":"stackTrace","arguments":{"threadId":1,"startFrame":0,"levels":20}}`)
var stackTraceResponse = []byte(`{"seq":0,"type":"response","request_seq":7,"success":true,"command":"stackTrace","body":{"stackFrames":[{"id":1000,"name":"main.main","source":{"name":"hello.go","path":"/Users/foo/go/src/hello/hello.go"},"line":5,"column":0}],"totalFrames":1}}`)

var variablesRequest = []byte(`{"seq":9,"type":"request","command":"variables","arguments":{"variablesReference":1000}}`)
var variablesResponse = []byte(`{"seq":0,"type":"response","request_seq":9,"success":true,"command":"variables","body":{"variables":[{"name":"i","value":"18434528","evaluateName":"i","variablesReference":0}]}}`)

var continueRequest = []byte(`{"seq":10,"type":"request","command":"continue","arguments":{"threadId":1}}`)
var continueResponse = []byte(`{"seq":0,"type":"response","request_seq":10,"success":true,"command":"continue","body":{"allThreadsContinued":false}}`)

var terminatedEvent = []byte(`{"seq":0,"type":"event","event":"terminated","body":{}}`)
var disconnectRequest = []byte(`{"seq":11,"type":"request","command":"disconnect","arguments":{"restart":false}}`)
var disconnectResponse = []byte(`{"seq":0,"type":"response","request_seq":11,"success":true,"command":"disconnect"}`)

func expectMessage(t *testing.T, r *bufio.Reader, want []byte) {
	got, err := dap.ReadBaseMessage(r)
	if err != nil {
		t.Error(err)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("\ngot  %q\nwant %q", got, want)
	}
}

func client(t *testing.T, port string, wg *sync.WaitGroup) {
	defer wg.Done()
	conn, err := net.Dial("tcp", ":"+port)
	if err != nil {
		log.Fatal("Could not connect to server:", err)
	}
	defer func() {
		t.Log("Closing connection to server at", conn.RemoteAddr())
		conn.Close()
	}()
	t.Log("Connected to server at", conn.RemoteAddr())

	r := bufio.NewReader(conn)

	// Start up

	dap.WriteBaseMessage(conn, initializeRequest)
	expectMessage(t, r, initializedEvent)
	expectMessage(t, r, initializeResponse)

	dap.WriteBaseMessage(conn, launchRequest)
	expectMessage(t, r, launchResponse)

	dap.WriteBaseMessage(conn, setBreakpointsRequest)
	expectMessage(t, r, setBreakpointsResponse)
	dap.WriteBaseMessage(conn, setExceptionBreakpointsRequest)
	expectMessage(t, r, setExceptionBreakpointsResponse)

	dap.WriteBaseMessage(conn, configurationDoneRequest)
	expectMessage(t, r, threadEvent)
	expectMessage(t, r, configurationDoneResponse)

	// Stop on preconfigured breakpoint & Continue

	expectMessage(t, r, stoppedEvent)

	dap.WriteBaseMessage(conn, stackTraceRequest)
	expectMessage(t, r, stackTraceResponse)

	// Processing of this request will be slow due to a fake delay.
	// Send the next request right away and confirm that processing
	// happens concurrently and the two responses are received
	// out of order.
	dap.WriteBaseMessage(conn, variablesRequest)
	dap.WriteBaseMessage(conn, continueRequest)
	expectMessage(t, r, continueResponse)
	expectMessage(t, r, variablesResponse)

	// Shut down

	expectMessage(t, r, terminatedEvent)
	_ = dap.WriteBaseMessage(conn, disconnectRequest)
	expectMessage(t, r, disconnectResponse)
}

func TestServer(t *testing.T) {
	partitiontest.PartitionTest(t)

	port := "54321"
	go func() {
		err := server(port)
		require.NoError(t, err, "The server returned with error %v", err)
	}()
	// Give server time to start listening before clients connect
	time.Sleep(100 * time.Millisecond)

	var wg sync.WaitGroup
	wg.Add(1)
	go client(t, port, &wg)
	wg.Wait()
}
