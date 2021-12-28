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
	"fmt"
	"io"
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
	debugger  *Debugger
	frontend  DebugAdapter
	router    *mux.Router
	server    *http.Server
	remote    *RemoteHookAdapter
	params    *DebugParams
	spinoffCh chan spinoffMsg
}

type spinoffMsg struct {
	err  error
	data []byte
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
	ListenForDrReq   bool
}

// FrontendFactory interface for attaching debug frontends
type FrontendFactory interface {
	Make(router *mux.Router, appAddress string) (da DebugAdapter)
}

func makeDebugServer(iface string, port int, ff FrontendFactory, dp *DebugParams) DebugServer {
	debugger := MakeDebugger()

	router := mux.NewRouter()
	appAddress := fmt.Sprintf("%s:%d", iface, port)

	da := ff.Make(router, appAddress)
	debugger.AddAdapter(da)

	server := &http.Server{
		Handler:      router,
		Addr:         appAddress,
		WriteTimeout: time.Duration(0),
		ReadTimeout:  time.Duration(0),
	}

	return DebugServer{
		debugger:  debugger,
		frontend:  da,
		router:    router,
		server:    server,
		params:    dp,
		spinoffCh: make(chan spinoffMsg),
	}
}

func (ds *DebugServer) startRemote() error {
	remote := MakeRemoteHook(ds.debugger)
	remote.Setup(ds.router)
	ds.remote = remote

	log.Printf("starting server on %s", ds.server.Addr)
	err := ds.server.ListenAndServe()
	if err != nil && err != http.ErrServerClosed {
		return err
	}
	return nil
}

// DebugServer in local evaluator mode either accepts Dryrun Request obj if ListenForDrReq is set
// or works with existing args set via command line.
// So that for ListenForDrReq case a new endpoint is created and incoming data is await first.
// Then execution is set up and program(s) run with stage-by-stage sync with ListenForDrReq's handler.
func (ds *DebugServer) startDebug() (err error) {
	local := MakeLocalRunner(ds.debugger)

	if ds.params.ListenForDrReq {
		path := "/spinoff"
		ds.router.HandleFunc(path, ds.dryrunReqHander).Methods("POST")
		log.Printf("listening for upcoming dryrun requests at http://%s%s", ds.server.Addr, path)
	}

	go func() {
		err := ds.server.ListenAndServe()
		if err != nil && err != http.ErrServerClosed {
			log.Panicf("failed to listen: %v", err)
		}
	}()
	defer ds.server.Shutdown(context.Background())

	urlFetcherCh := make(chan struct{})
	if ds.params.ListenForDrReq {
		msg := <-ds.spinoffCh
		ds.params.DdrBlob = msg.data
		go func() {
			for {
				url := ds.frontend.URL()
				if len(url) > 0 {
					ds.spinoffCh <- spinoffMsg{nil, []byte(url)}
					break
				}
				time.Sleep(100 * time.Millisecond)
			}
			urlFetcherCh <- struct{}{}
		}()
	}

	if err = local.Setup(ds.params); err != nil {
		if ds.params.ListenForDrReq {
			ds.spinoffCh <- spinoffMsg{err, []byte(err.Error())}
			<-ds.spinoffCh // wait handler to complete
		}
		return
	}

	if err = local.RunAll(); err != nil {
		if ds.params.ListenForDrReq {
			ds.spinoffCh <- spinoffMsg{err, []byte(err.Error())}
			<-ds.spinoffCh // wait handler to complete
		}
		return
	}

	ds.frontend.WaitForCompletion()

	if ds.params.ListenForDrReq {
		// It is possible URL fetcher routine does not return anything and stuck in the loop.
		// By this point all executions are done and a message urlFetcherCh must be available.
		// If not then URL fetcher stuck and special handling is needed: send an error message
		// to the network handler in order to unblock it.
		select {
		case <-urlFetcherCh:
		default:
			err = fmt.Errorf("no URL from frontend")
			ds.spinoffCh <- spinoffMsg{err, []byte(err.Error())}
		}
		<-ds.spinoffCh // wait handler to complete
	}
	return
}

func (ds *DebugServer) dryrunReqHander(w http.ResponseWriter, r *http.Request) {
	blob := make([]byte, 0, 4096)
	buf := make([]byte, 1024)
	n, err := r.Body.Read(buf)
	for n > 0 {
		blob = append(blob, buf...)
		n, err = r.Body.Read(buf)
	}
	if err != nil && err != io.EOF {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	// send data
	ds.spinoffCh <- spinoffMsg{nil, blob}
	// wait for confirmation message
	msg := <-ds.spinoffCh

	w.Header().Set("Content-Type", "text/plain")
	if msg.err == nil {
		w.WriteHeader(http.StatusOK)
	} else {
		w.WriteHeader(http.StatusBadRequest)
	}
	w.Write(msg.data)

	// let the main thread to exit
	close(ds.spinoffCh)
	return
}
