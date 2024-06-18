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

package agreement

import (
	"testing"
	"time"

	"github.com/algorand/go-algorand/test/partitiontest"
	"github.com/stretchr/testify/require"
)

func TestSampleIndexIsValid(t *testing.T) {
	partitiontest.PartitionTest(t)

	require.GreaterOrEqual(t, dynamicFilterCredentialArrivalHistory, 0)
	require.GreaterOrEqual(t, dynamicFilterTimeoutCredentialArrivalHistoryIdx, 0)
	if dynamicFilterCredentialArrivalHistory > 0 {
		require.Less(t, dynamicFilterTimeoutCredentialArrivalHistoryIdx, dynamicFilterCredentialArrivalHistory)
	}
}

func TestLowerBound(t *testing.T) {
	partitiontest.PartitionTest(t)

	require.Less(t, 20*time.Millisecond, dynamicFilterTimeoutLowerBound)
}
