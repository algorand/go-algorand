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

import "testing"

// TestingT captures the common methods of *testing.T and *testing.B
// that we use.
type TestingT interface {
	Fatalf(format string, args ...interface{})
	Errorf(format string, args ...interface{})
	Error(args ...interface{})
	Logf(format string, args ...interface{})
	FailNow()
	Failed() bool
	Name() string
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
