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

package testing

import (
	"testing"

	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/protocol"
	"github.com/algorand/go-algorand/test/partitiontest"
	"github.com/stretchr/testify/require"
)

// TestReleasedVersion ensures that the necessary tidying is done when a new
// protocol release happens.  The new version must be added to
// consensusByNumber, and a new LogicSigVersion must be added to vFuture.
func TestReleasedVersion(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	// This confirms that the proto before future has no ApprovedUpgrades.  Once
	// it does, that new version should be added to consensusByNumber.
	require.Len(t, config.Consensus[consensusByNumber[len(consensusByNumber)-2]].ApprovedUpgrades, 0)
	// And no funny business with vFuture
	require.Equal(t, protocol.ConsensusFuture, consensusByNumber[len(consensusByNumber)-1])

	// Ensure that vFuture gets a new LogicSigVersion when we promote the
	// existing one.  That allows TestExperimental in the logic package to
	// prevent unintended releases of experimental opcodes.
	relV := config.Consensus[consensusByNumber[len(consensusByNumber)-2]].LogicSigVersion
	futureV := config.Consensus[protocol.ConsensusFuture].LogicSigVersion
	require.Less(t, int(relV), int(futureV))

	// Require that all are present
	for _, cv := range consensusByNumber {
		if cv == "" {
			continue
		}
		params, ok := config.Consensus[cv]
		require.True(t, ok, string(cv))
		require.NotZero(t, params) // just making sure an empty one didn't get put in
	}

	require.Equal(t, versionStringFromIndex(len(consensusByNumber)-1), "vFuture")
	require.Equal(t, versionStringFromIndex(39), "v39")

}
