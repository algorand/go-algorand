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
	"io"
	"net/http"

	"github.com/gorilla/mux"

	"github.com/algorand/go-algorand/data/transactions/logic"
	"github.com/algorand/go-algorand/protocol"
)

// RemoteHookAdapter provides HTTP transport for WebDebuggerHook
type RemoteHookAdapter struct {
	debugger *Debugger
}

// MakeRemoteHook creates new RemoteHookAdapter
func MakeRemoteHook(debugger *Debugger) *RemoteHookAdapter {
	r := new(RemoteHookAdapter)
	r.debugger = debugger
	return r
}

// Setup adds HTTP handlers for remote WebDebuggerHook
func (rha *RemoteHookAdapter) Setup(router *mux.Router) {
	router.HandleFunc("/exec/register", rha.registerHandler).Methods("POST")
	router.HandleFunc("/exec/update", rha.updateHandler).Methods("POST")
	router.HandleFunc("/exec/complete", rha.completeHandler).Methods("POST")
}

func (rha *RemoteHookAdapter) decodeState(body io.Reader) (state logic.DebugState, err error) {
	dec := protocol.NewJSONDecoder(body)
	err = dec.Decode(&state)
	return
}

func (rha *RemoteHookAdapter) registerHandler(w http.ResponseWriter, r *http.Request) {
	state, err := rha.decodeState(r.Body)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	// Register, and wait for user to acknowledge registration
	err = rha.debugger.Register(&state)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	// Proceed!
	w.WriteHeader(http.StatusOK)
	return
}

func (rha *RemoteHookAdapter) updateHandler(w http.ResponseWriter, r *http.Request) {
	state, err := rha.decodeState(r.Body)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	// Ask debugger to process and wait to continue
	err = rha.debugger.Update(&state)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	w.WriteHeader(http.StatusOK)
	return
}

func (rha *RemoteHookAdapter) completeHandler(w http.ResponseWriter, r *http.Request) {
	state, err := rha.decodeState(r.Body)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	// Ask debugger to process and wait to continue
	err = rha.debugger.Complete(&state)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	// Proceed!
	w.WriteHeader(http.StatusOK)
	return
}
