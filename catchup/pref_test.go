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

package catchup

import (
	"math/rand"
	"strconv"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/algorand/go-algorand/components/mocks"
	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/data"
	"github.com/algorand/go-algorand/data/account"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/datatest"
	"github.com/algorand/go-algorand/logging"
	"github.com/algorand/go-algorand/protocol"
	"github.com/algorand/go-algorand/util/db"
)

func BenchmarkServiceFetchBlocks(b *testing.B) {
	b.StopTimer()
	// Make Ledger
	remote, local, release, genesisBalances := benchenv(b, 100, 500)
	defer release()

	require.NotNil(b, remote)
	require.NotNil(b, local)

	net := &mocks.MockNetwork{}

	cfg := config.GetDefaultLocal()
	cfg.Archival = true

	for i := 0; i < b.N; i++ {
		inMem := true
		local, err := data.LoadLedger(logging.Base(), b.Name()+"empty"+strconv.Itoa(i), inMem, protocol.ConsensusCurrentVersion, genesisBalances, "", crypto.Digest{}, nil, cfg)
		require.NoError(b, err)

		// Make Service
		syncer := MakeService(logging.Base(), defaultConfig, net, local, new(mockedAuthenticator), nil)
		syncer.blockFetcherFactory = &mockBlockFetcherFactory{mf: &MockedFetcher{ledger: remote, timeout: false, tries: make(map[basics.Round]int), latency: 100 * time.Millisecond, predictable: true}}
		b.StartTimer()
		syncer.sync()
		b.StopTimer()
		local.Close()
		require.Equal(b, remote.LastRound(), local.LastRound())
	}
}

// one service
func benchenv(t testing.TB, numAccounts, numBlocks int) (ledger, emptyLedger *data.Ledger, release func(), genesisBalances data.GenesisBalances) {
	P := numAccounts                                  // n accounts
	maxMoneyAtStart := uint64(10 * defaultRewardUnit) // max money start
	minMoneyAtStart := uint64(defaultRewardUnit)      // min money start

	accesssors := make([]db.Accessor, 0)
	release = func() {
		ledger.Close()
		emptyLedger.Close()
		for _, acc := range accesssors {
			acc.Close()
		}
	}
	// generate accounts
	genesis := make(map[basics.Address]basics.AccountData)
	gen := rand.New(rand.NewSource(2))
	parts := make([]account.Participation, P)
	for i := 0; i < P; i++ {
		access, err := db.MakeAccessor(t.Name()+"_root_benchenv"+strconv.Itoa(i), false, true)
		if err != nil {
			panic(err)
		}
		accesssors = append(accesssors, access)
		root, err := account.GenerateRoot(access)
		if err != nil {
			panic(err)
		}

		access, err = db.MakeAccessor(t.Name()+"_part_benchenv"+strconv.Itoa(i), false, true)
		if err != nil {
			panic(err)
		}
		accesssors = append(accesssors, access)
		part, err := account.FillDBWithParticipationKeys(access, root.Address(), 0, basics.Round(numBlocks),
			config.Consensus[protocol.ConsensusCurrentVersion].DefaultKeyDilution)
		if err != nil {
			panic(err)
		}

		startamt := basics.AccountData{
			Status:      basics.Online,
			MicroAlgos:  basics.MicroAlgos{Raw: uint64(minMoneyAtStart + (gen.Uint64() % (maxMoneyAtStart - minMoneyAtStart)))},
			SelectionID: part.VRFSecrets().PK,
			VoteID:      part.VotingSecrets().OneTimeSignatureVerifier,
		}
		short := root.Address()

		parts[i] = part
		genesis[short] = startamt
	}

	genesis[basics.Address(sinkAddr)] = basics.AccountData{
		Status:     basics.NotParticipating,
		MicroAlgos: basics.MicroAlgos{Raw: uint64(1e3 * minMoneyAtStart)},
	}
	genesis[basics.Address(poolAddr)] = basics.AccountData{
		Status:     basics.NotParticipating,
		MicroAlgos: basics.MicroAlgos{Raw: uint64(1e3 * minMoneyAtStart)},
	}

	var err error
	genesisBalances = data.MakeGenesisBalances(genesis, sinkAddr, poolAddr)
	const inMem = true
	cfg := config.GetDefaultLocal()
	cfg.Archival = true
	emptyLedger, err = data.LoadLedger(logging.Base(), t.Name()+"empty", inMem, protocol.ConsensusCurrentVersion, genesisBalances, "", crypto.Digest{}, nil, cfg)
	require.NoError(t, err)

	ledger, err = datatest.FabricateLedger(logging.Base(), t.Name(), parts, genesisBalances, emptyLedger.LastRound()+basics.Round(numBlocks))
	require.NoError(t, err)
	require.Equal(t, ledger.LastRound(), emptyLedger.LastRound()+basics.Round(numBlocks))
	return ledger, emptyLedger, release, genesisBalances
}
