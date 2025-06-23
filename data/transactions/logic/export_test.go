// Copyright (C) 2019-2025 Algorand, Inc.
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

import (
	"testing"

	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/transactions"
)

// Export for testing only.  See
// https://medium.com/@robiplus/golang-trick-export-for-test-aa16cbd7b8cd for a
// nice explanation. tl;dr: Since some of our testing is in logic_test package,
// we export some extra things to make testing easier there. But we do it in a
// _test.go file, so they are only exported during testing.

// Inefficient (hashing), just a testing convenience
func (l *Ledger) CreateBox(app basics.AppIndex, name string, size uint64) {
	l.NewBox(app, name, make([]byte, size), app.Address())
}

// Inefficient (hashing), just a testing convenience
func (l *Ledger) DelBoxes(app basics.AppIndex, names ...string) {
	for _, n := range names {
		l.DelBox(app, n, app.Address())
	}
}

var ConvertEPToAccess = convertEPToAccess
var DefaultSigParams = defaultSigParams
var DefaultAppParams = defaultAppParams
var Exp = exp
var MakeSampleEnv = makeSampleEnv
var MakeSampleEnvWithVersion = makeSampleEnvWithVersion
var MakeSampleTxn = makeSampleTxn
var MakeSampleTxnGroup = makeSampleTxnGroup
var MakeTestProto = makeTestProto
var NoTrack = notrack
var TestLogic = testLogic
var TestApp = testApp
var TestAppBytes = testAppBytes
var TestAppFull = testAppFull
var TestLogicRange = testLogicRange
var TestProg = testProg
var WithPanicOpcode = withPanicOpcode

// TryApps exports "testApps" while accepting a simple uint64. Annoying, we
// can't export call this "TestApps" because it looks like a Test function with
// the wrong signature. But we can get that effect with the alias below.
func TryApps(t *testing.T, programs []string, txgroup []transactions.SignedTxn, ver uint64, ledger *Ledger, expected ...expect) (*EvalParams, error) {
	t.Helper()
	return testApps(t, programs, txgroup, protoVer(ver), ledger, expected...)
}

var TestApps = TryApps

const CreatedResourcesVersion = createdResourcesVersion
const AssemblerNoVersion = assemblerNoVersion
const FirstTestID = firstTestID
const TestCallStackProgram = testCallStackProgram
