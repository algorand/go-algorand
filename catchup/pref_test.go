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

package catchup

import (
	"strconv"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/algorand/go-algorand/components/mocks"
	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/data"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/logging"
	"github.com/algorand/go-algorand/protocol"
)

func BenchmarkServiceFetchBlocks(b *testing.B) {
	b.StopTimer()
	// Make Ledger
	remote, local, release, genesisBalances := testingenv(b, 100, 500)
	defer release()

	require.NotNil(b, remote)
	require.NotNil(b, local)

	net := &mocks.MockNetwork{}

	for i := 0; i < b.N; i++ {
		local, err := data.LoadLedger(logging.Base(), b.Name()+"empty"+strconv.Itoa(i), true, protocol.ConsensusCurrentVersion, genesisBalances, "", crypto.Digest{}, nil)
		require.NoError(b, err)

		// Make Service
		syncer := MakeService(logging.Base(), defaultConfig, net, local, nil, nil)
		syncer.fetcherFactory = makeMockFactory(&MockedFetcher{ledger: remote, timeout: false, errorRound: -1, fail: 0, tries: make(map[basics.Round]int), latency: 100 * time.Millisecond, predictable: true})

		b.StartTimer()
		syncer.sync()
		b.StopTimer()
		local.Close()
		require.Equal(b, remote.LastRound(), local.LastRound())
	}
}
