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

package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/algorand/websocket"
	"github.com/gorilla/mux"
)

var upgrader = websocket.Upgrader{
	ReadBufferSize:  20480,
	WriteBufferSize: 20480,
	CheckOrigin: func(r *http.Request) bool {
		if len(r.Header.Get("Origin")) == 0 {
			return true
		}
		if strings.HasPrefix(r.Header.Get("Origin"), "devtools://") {
			return true
		}
		if strings.HasPrefix(r.Header.Get("Origin"), "http://localhost") {
			return true
		}
		if strings.HasPrefix(r.Header.Get("Origin"), "http://127.0.0.1") {
			return true
		}
		return false
	},
}

// DebugServer is Debugger + HTTP/WS handlers for frontends
type DebugServer struct {
	debugger *Debugger
	frontend DebugAdapter
	router   *mux.Router
	server   *http.Server
	remote   *RemoteHookAdapter
	params   *DebugParams
}

// DebugParams is a container for debug parameters
type DebugParams struct {
	ProgramNames     []string
	ProgramBlobs     [][]byte
	Proto            string
	TxnBlob          []byte
	GroupIndex       int
	BalanceBlob      []byte
	DdrBlob          []byte
	IndexerURL       string
	IndexerToken     string
	Round            uint64
	LatestTimestamp  int64
	RunMode          string
	DisableSourceMap bool
	AppID            uint64
	Painless         bool
}

// FrontendFactory interface for attaching debug frontends
type FrontendFactory interface {
	Make(router *mux.Router, appAddress string) (da DebugAdapter)
}

func makeDebugServer(port int, ff FrontendFactory, dp *DebugParams) DebugServer {
	debugger := MakeDebugger()

	router := mux.NewRouter()
	appAddress := fmt.Sprintf("127.0.0.1:%d", port)

	da := ff.Make(router, appAddress)
	debugger.AddAdapter(da)

	server := &http.Server{
		Handler:      router,
		Addr:         appAddress,
		WriteTimeout: time.Duration(0),
		ReadTimeout:  time.Duration(0),
	}

	return DebugServer{
		debugger: debugger,
		frontend: da,
		router:   router,
		server:   server,
		params:   dp,
	}
}

func (ds *DebugServer) startRemote() {
	remote := MakeRemoteHook(ds.debugger)
	remote.Setup(ds.router)
	ds.remote = remote

	log.Printf("starting server on %s", ds.server.Addr)
	err := ds.server.ListenAndServe()
	if err != nil {
		log.Panicf("failed to listen: %v", err)
	}
}

func (ds *DebugServer) startDebug() (err error) {
	local := MakeLocalRunner(ds.debugger)
	if err = local.Setup(ds.params); err != nil {
		return
	}

	go func() {
		err = ds.server.ListenAndServe()
		if err != nil {
			log.Panicf("failed to listen: %v", err)
		}
	}()
	defer ds.server.Shutdown(context.Background())

	err = local.RunAll()
	if err != nil {
		return
	}

	ds.frontend.WaitForCompletion()
	return
}
