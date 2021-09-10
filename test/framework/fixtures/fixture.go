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

package fixtures

import (
	"testing"

	"github.com/algorand/go-deadlock"
)

// TestingTB is identical to testing.TB, beside the private method.
type TestingTB interface {
	Cleanup(func())
	Error(args ...interface{})
	Errorf(format string, args ...interface{})
	Fail()
	FailNow()
	Failed() bool
	Fatal(args ...interface{})
	Fatalf(format string, args ...interface{})
	Helper()
	Log(args ...interface{})
	Logf(format string, args ...interface{})
	Name() string
	Skip(args ...interface{})
	SkipNow()
	Skipf(format string, args ...interface{})
	Skipped() bool
}

// Fixture provides the base interface for all E2E test fixtures
// so we can work with them abstractly if needed
type Fixture interface {
	// Run executes the tests after the fixture initializes
	// and returns the exit code from testing
	Run(m *testing.M) int

	// Run executes the tests after the fixture initializes, and either
	// returns the exit code from testing, or calls os.Exit(ret) directly
	RunAndExit(m *testing.M)

	// Shutdown should be called for a single-use fixture shutdown / cleanup
	// It requires a valid t.Testing to be assigned.
	Shutdown()

	// ShutdownImpl should not generally be called except for implementations
	// where there is no single t.Testing associated with the fixture
	// (e.g. shared across all tests in a package)
	ShutdownImpl(preserveData bool)
}

var synchTestMu deadlock.Mutex
var synchTests = make(map[TestingTB]TestingTB)

// SynchronizedTest generates a testing.TB compatible test for a given testing.TB interface.
// calling SynchronizedTest with the same tb would return the exact same instance of synchTest
func SynchronizedTest(tb TestingTB) TestingTB {
	if st, ok := tb.(*synchTest); ok {
		return st
	}
	synchTestMu.Lock()
	defer synchTestMu.Unlock()
	if t, have := synchTests[tb]; have {
		return t
	}
	t := &synchTest{
		t: tb,
	}
	synchTests[tb] = t
	return t
}

type synchTest struct {
	deadlock.Mutex
	t TestingTB
}

func (st *synchTest) Cleanup(f func()) {
	st.Lock()
	defer st.Unlock()
	st.t.Cleanup(f)
}
func (st *synchTest) Error(args ...interface{}) {
	st.Lock()
	defer st.Unlock()
	st.t.Error(args...)
}
func (st *synchTest) Errorf(format string, args ...interface{}) {
	st.Lock()
	defer st.Unlock()
	st.t.Errorf(format, args...)
}
func (st *synchTest) Fail() {
	st.Lock()
	defer st.Unlock()
	st.t.Fail()
}
func (st *synchTest) FailNow() {
	st.Lock()
	defer st.Unlock()
	st.t.FailNow()
}
func (st *synchTest) Failed() bool {
	st.Lock()
	defer st.Unlock()
	return st.t.Failed()
}
func (st *synchTest) Fatal(args ...interface{}) {
	st.Lock()
	defer st.Unlock()
	st.t.Fatal(args...)
}
func (st *synchTest) Fatalf(format string, args ...interface{}) {
	st.Lock()
	defer st.Unlock()
	st.t.Fatalf(format, args...)
}
func (st *synchTest) Helper() {
	st.Lock()
	defer st.Unlock()
	st.t.Helper()
}
func (st *synchTest) Log(args ...interface{}) {
	st.Lock()
	defer st.Unlock()
	st.t.Log(args...)
}
func (st *synchTest) Logf(format string, args ...interface{}) {
	st.Lock()
	defer st.Unlock()
	st.t.Logf(format, args...)
}
func (st *synchTest) Name() string {
	st.Lock()
	defer st.Unlock()
	return st.t.Name()
}
func (st *synchTest) Skip(args ...interface{}) {
	st.Lock()
	defer st.Unlock()
	st.t.Skip(args...)
}
func (st *synchTest) SkipNow() {
	st.Lock()
	defer st.Unlock()
	st.t.SkipNow()
}
func (st *synchTest) Skipf(format string, args ...interface{}) {
	st.Lock()
	defer st.Unlock()
	st.t.Skipf(format, args...)
}
func (st *synchTest) Skipped() bool {
	st.Lock()
	defer st.Unlock()
	return st.t.Skipped()
}
