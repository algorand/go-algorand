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

package participation

import (
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/algorand/go-algorand/test/framework/fixtures"
	"github.com/algorand/go-algorand/test/partitiontest"
)

// TestDeletePartKey tests that the deletepartkey subcommand works
func TestDeletePartKey(t *testing.T) {
	partitiontest.PartitionTest(t)

	// Start devmode network and initialize things for the test.
	var fixture fixtures.RestClientFixture
	fixture.SetupNoStart(t, filepath.Join("nettemplates", "DevModeOneWallet.json"))
	fixture.Start()
	defer fixture.Shutdown()
	sClient := fixture.GetLibGoalClientForNamedNode("Node")

	partKeyResponse, err := sClient.GetParticipationKeys()
	require.NoError(t, err)
	numberOfPartKeys := len(partKeyResponse)
	require.True(t, numberOfPartKeys > 0)
	participationID := partKeyResponse[0].Id
	err = sClient.RemoveParticipationKey(participationID)
	require.NoError(t, err)

	newPartKeyResponse, err := sClient.GetParticipationKeys()
	require.NoError(t, err)
	newNumberOfPartKeys := len(newPartKeyResponse)
	require.True(t, newNumberOfPartKeys < numberOfPartKeys)

}
