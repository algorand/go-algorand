// Copyright (C) 2019-2026 Algorand Foundation Ltd.
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

// The ignore tag keeps go-algorand/config out of this module's go.mod. xrt.go
// runs this file alongside main.go and typeAnalyzer.go only when comparing
// config.ConsensusParams, after go-getting config's dependencies.

//go:build ignore

package main

import (
	"reflect"

	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/protocol"
)

// A ConsensusParams field that only vFuture sets is unreleased, so the SDK
// need not carry it yet. It becomes required when a numbered version sets it,
// normally when vFuture is promoted. Only top-level fields are considered: a
// new field inside an existing struct such as Payouts is still required.
func init() {
	xUnreleased = make(map[string]bool)
	t := reflect.TypeOf(config.ConsensusParams{})
	for i := range t.NumField() {
		released := false
		for v, params := range config.Consensus {
			if v != protocol.ConsensusFuture && !reflect.ValueOf(params).Field(i).IsZero() {
				released = true
				break
			}
		}
		if !released {
			xUnreleased[t.Field(i).Name] = true
		}
	}
}
