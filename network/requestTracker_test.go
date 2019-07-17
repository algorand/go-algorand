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

package network

import (
	"math/rand"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestHostIncomingRequestsOrdering(t *testing.T) {
	// add 100 items to the hostIncomingRequests object, and make sure they are sorted.
	hir := hostIncomingRequests{}
	now := time.Now()
	perm := rand.Perm(100)
	for i := 0; i < 100; i++ {
		hir.add("host", "port", "remoteaddr", now.Add(time.Duration(perm[i])*time.Minute), now.Add(-time.Second))
	}
	require.Equal(t, 100, len(hir.requests))

	// make sure the array ends up being ordered.
	for i := 1; i < 100; i++ {
		require.True(t, hir.requests[i].created.After(hir.requests[i-1].created))
	}
}
