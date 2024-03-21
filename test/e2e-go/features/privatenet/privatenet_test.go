// Copyright (C) 2019-2024 Algorand, Inc.
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

// Check that private networks are started as designed.
package privatenet

import (
	"testing"

	"github.com/algorand/go-algorand/test/framework/fixtures"
	"github.com/algorand/go-algorand/test/partitiontest"
	"github.com/stretchr/testify/require"
)

// TestPrivateNetworkImportKeys tests that part keys can be exported and
// imported when starting a private network.
func TestPrivateNetworkImportKeys(t *testing.T) {
	partitiontest.PartitionTest(t)

	// This test takes 5~10 seconds.
	if testing.Short() {
		t.Skip()
	}

	// First test that keys can be exported by using `goal network pregen ...`
	// Don't start up network, just create genesis files.
	var goalFixture fixtures.GoalFixture
	tmpGenDir := t.TempDir()
	tmpNetDir := t.TempDir()
	defaultTemplate := "" // Use the default template by omitting the filepath.

	_, err := goalFixture.NetworkPregen(defaultTemplate, tmpGenDir)
	require.NoError(t, err)

	// Check that if there is an existing directory with same name, test fails.
	errStr, err := goalFixture.NetworkPregen(defaultTemplate, tmpGenDir)
	require.Error(t, err)
	require.Contains(t, errStr, "already exists and is not empty")

	// Then try importing files from same template.
	err = goalFixture.NetworkCreate(tmpNetDir, "", defaultTemplate, tmpGenDir)
	require.NoError(t, err)

	err = goalFixture.NetworkStart(tmpNetDir)
	require.NoError(t, err)

	err = goalFixture.NetworkStop(tmpNetDir)
	require.NoError(t, err)
}
