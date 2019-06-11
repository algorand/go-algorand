// Copyright (C) 2019 Algorand, Inc.
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

package algod

// this should make dummy requests against the API and check the results for consistency

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestFirstListenerSetupGetsPort8080WhenPassedPortZero(t *testing.T) {
	// this test will fail if there is already a listener on the testing machine's port 8080
	// (ex if a dev has a node running on port 8080 and runs the test, it will fail)
	defaultAddr := "127.0.0.1:0"
	expectedAddr := "127.0.0.1:8080"
	listener, err := makeListener(defaultAddr)
	require.NoError(t, err)
	actualAddr := listener.Addr().String()
	require.Equal(t, expectedAddr, actualAddr, "if port 8080 is occupied when this test runs, it will fail")
}

func TestSecondListenerSetupGetsAnotherPortWhen8080IsBusy(t *testing.T) {
	defaultAddr := "127.0.0.1:0"
	unexpectedAddr := "127.0.0.1:8080"
	makeListener(defaultAddr)
	secondListener, err := makeListener(defaultAddr)
	require.NoError(t, err)
	actualAddr := secondListener.Addr().String()
	require.NotEqual(t, unexpectedAddr, actualAddr)
}

func TestFirstListenerSetupGetsPassedPortWhenPassedPortNonZero(t *testing.T) {
	expectedAddr := "127.0.0.1:8081"
	listener, err := makeListener(expectedAddr)
	require.NoError(t, err)
	actualAddr := listener.Addr().String()
	require.Equal(t, expectedAddr, actualAddr)
}
