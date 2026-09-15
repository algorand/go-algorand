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

package agreement

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/algorand/go-algorand/test/partitiontest"
)

// TestBundleFreshDiscardsStaleCertBundle checks that bundleFresh follows the
// spec bundle relay rule: a bundle is fresh only for the current round and no
// more than one period behind the current period. Cert bundles are not exempt.
// A late cert for an already-collected period (period+1 < player period) is
// discarded here, before verification, so it can never be routed into a
// garbage-collected period tracker.
func TestBundleFreshDiscardsStaleCertBundle(t *testing.T) {
	partitiontest.PartitionTest(t)

	fd := freshnessData{PlayerRound: 10, PlayerPeriod: 4}
	bundleAt := func(p period, s step) unauthenticatedBundle {
		return unauthenticatedBundle{Round: 10, Period: p, Step: s}
	}

	// Cert bundles obey the same period-age bound as every other bundle.
	require.NoError(t, bundleFresh(fd, bundleAt(4, cert)), "current period is fresh")
	require.NoError(t, bundleFresh(fd, bundleAt(3, cert)), "one period behind is fresh")
	require.NoError(t, bundleFresh(fd, bundleAt(9, cert)), "a future period is fresh")
	require.Error(t, bundleFresh(fd, bundleAt(2, cert)), "two periods behind must be discarded")
	require.Error(t, bundleFresh(fd, bundleAt(0, cert)), "far behind must be discarded")

	// Non-cert bundles are unchanged by removing the cert exception.
	require.NoError(t, bundleFresh(fd, bundleAt(3, soft)))
	require.Error(t, bundleFresh(fd, bundleAt(2, soft)))

	// A bundle for a different round is always discarded, cert included.
	require.Error(t, bundleFresh(freshnessData{PlayerRound: 11, PlayerPeriod: 4}, bundleAt(4, cert)))

	// At period 0 the period-age bound does not apply.
	require.NoError(t, bundleFresh(freshnessData{PlayerRound: 10, PlayerPeriod: 0}, bundleAt(0, cert)))
}
