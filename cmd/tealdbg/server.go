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
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/algorand/websocket"
	"github.com/gorilla/mux"
)

var upgrader = websocket.Upgrader{
	ReadBufferSize:  10240,
	WriteBufferSize: 10240,
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
		return false
	},
}

// DebugServer is Debugger + HTTP/WS handlers for frontends
type DebugServer struct {
	debugger *Debugger
	router   *mux.Router
	server   *http.Server
	remote   *RemoteHookAdapter
	params   *DebugParams
}

// DebugParams is a container for debug parameters
type DebugParams struct {
	ProgramBlobs [][]byte
	Proto        string
	TxnBlob      []byte
	GroupIndex   int
	BalanceBlob  []byte
	Round        int
	RunMode      string
	Remote       bool
}

// AdapterMaker interface for attaching debug adapters
type AdapterMaker interface {
	MakeAdapter(router *mux.Router, appAddress string) (da DebugAdapter)
}

func makeDebugServer(maker AdapterMaker, dp *DebugParams) DebugServer {
	debugger := MakeDebugger()

	router := mux.NewRouter()
	appAddress := "localhost:9392"

	da := maker.MakeAdapter(router, appAddress)
	debugger.AddAdapter(da)

	server := &http.Server{
		Handler:      router,
		Addr:         appAddress,
		WriteTimeout: time.Duration(0),
		ReadTimeout:  time.Duration(0),
	}

	return DebugServer{
		debugger: debugger,
		router:   router,
		server:   server,
		params:   dp,
	}
}

func (ds *DebugServer) startRemote() {
	remote := RemoteHookAdapter{ds.debugger}
	remote.Setup(ds.router)
	ds.remote = &remote

	log.Printf("starting server on %s", ds.server.Addr)
	ds.server.ListenAndServe()
}

func (ds *DebugServer) startDebug() (err error) {
	go ds.server.ListenAndServe()

	err = RunLocal(ds.debugger, ds.params)

	// TODO: better sync to give frontend a change to process all notifications
	ds.server.Shutdown(context.Background())
	return
}
