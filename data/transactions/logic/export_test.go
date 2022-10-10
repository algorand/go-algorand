// Copyright (C) 2019-2022 Algorand, Inc.
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

package logic

import "github.com/algorand/go-algorand/data/basics"

// Export for testing only.  See
// https://medium.com/@robiplus/golang-trick-export-for-test-aa16cbd7b8cd for a
// nice explanation. tl;dr: Since some of our testing is in logic_test package,
// we export some extra things to make testing easier there. But we do it in a
// _test.go file, so they are only exported during testing.

func NewExpect(l int, s string) Expect {
	return Expect{l, s}
}

func (ep *EvalParams) Reset() {
	ep.reset()
}

// Inefficient (hashing), just a testing convenience
func (l *Ledger) CreateBox(app basics.AppIndex, name string, size uint64) {
	l.NewBox(app, name, string(make([]byte, size)), app.Address())
}

// Inefficient (hashing), just a testing convenience
func (l *Ledger) DelBoxes(app basics.AppIndex, names ...string) {
	for _, n := range names {
		l.DelBox(app, n, app.Address())
	}
}

var MakeSampleEnv = makeSampleEnv
var MakeSampleEnvWithVersion = makeSampleEnvWithVersion
var MakeSampleTxn = makeSampleTxn
var MakeSampleTxnGroup = makeSampleTxnGroup
var MakeTestProto = makeTestProto
var MakeTestProtoV = makeTestProtoV
var NoTrack = notrack
var TestApp = testApp
var TestAppBytes = testAppBytes
var TestApps = testApps
var TestProg = testProg

const CreatedResourcesVersion = createdResourcesVersion
