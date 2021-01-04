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
	"database/sql"
	"encoding/json"
	"net/http"

	"github.com/gorilla/schema"
)

// This file defines helpers for running HTTP handlers in an SQL
// transaction, and sending back JSON-encoded results.

type status struct {
	Success bool   `json:"success"`
	Err     string `json:"err,omitempty"`
}

func sendJSON(w http.ResponseWriter, obj interface{}) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(obj)
}

func httpError(w http.ResponseWriter, err error) {
	sendJSON(w, status{
		Success: false,
		Err:     err.Error(),
	})
}

func readForm(obj interface{}, r *http.Request) error {
	err := r.ParseForm()
	if err != nil {
		return err
	}

	dec := schema.NewDecoder()
	return dec.Decode(obj, r.Form)
}

// txHandle runs handler function [f] inside of an SQL transaction.
// On success, it returns a JSON encoding of [f]'s return value to
// the HTTP client.  On failure, it rolls back the transaction and
// sends the error to the HTTP client.
func txHandle(w http.ResponseWriter, f func(*sql.Tx) (interface{}, error)) {
	tx, err := db.Begin()
	if err != nil {
		httpError(w, err)
		return
	}

	reply, err := f(tx)
	if err != nil {
		tx.Rollback()
		httpError(w, err)
		return
	}

	err = tx.Commit()
	if err != nil {
		httpError(w, err)
		return
	}

	sendJSON(w, reply)
}

// txHandleSuccess runs handler [f] and, on success, send a JSON
// encoding of {"success": true}.  On error, it sends the error
// to the client.
func txHandleSuccess(w http.ResponseWriter, f func(*sql.Tx) error) {
	txHandle(w, func(tx *sql.Tx) (interface{}, error) {
		err := f(tx)
		if err != nil {
			return nil, err
		}

		return status{Success: true}, nil
	})
}
