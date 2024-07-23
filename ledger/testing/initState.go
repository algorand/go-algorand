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

	"github.com/stretchr/testify/require"

	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/data/basics"
	basics_testing "github.com/algorand/go-algorand/data/basics/testing"
	"github.com/algorand/go-algorand/data/bookkeeping"
	"github.com/algorand/go-algorand/ledger/ledgercore"
	"github.com/algorand/go-algorand/protocol"
)

var poolSecret, sinkSecret *crypto.SignatureSecrets

func init() {
	var seed crypto.Seed

	incentivePoolName := []byte("incentive pool")
	copy(seed[:], incentivePoolName)
	poolSecret = crypto.GenerateSignatureSecrets(seed)

	feeSinkName := []byte("fee sink")
	copy(seed[:], feeSinkName)
	sinkSecret = crypto.GenerateSignatureSecrets(seed)
}

// GenerateInitState generates testing init state
func GenerateInitState(tb testing.TB, proto protocol.ConsensusVersion, baseAlgoPerAccount int) (genesisInitState ledgercore.InitState, initKeys map[basics.Address]*crypto.SignatureSecrets) {
	poolAddr := testPoolAddr
	sinkAddr := testSinkAddr

	var zeroSeed crypto.Seed
	var genaddrs [10]basics.Address
	var gensecrets [10]*crypto.SignatureSecrets
	for i := range genaddrs {
		seed := zeroSeed
		seed[0] = byte(i)
		x := crypto.GenerateSignatureSecrets(seed)
		genaddrs[i] = basics.Address(x.SignatureVerifier)
		gensecrets[i] = x
	}

	initKeys = make(map[basics.Address]*crypto.SignatureSecrets, len(genaddrs)+2) // + pool and sink
	initAccounts := make(map[basics.Address]basics.AccountData, len(genaddrs)+2)
	for i := range genaddrs {
		initKeys[genaddrs[i]] = gensecrets[i]
		// Give each account quite a bit more balance than MinFee or MinBalance
		ad := basics_testing.MakeAccountData(basics.Online, basics.MicroAlgos{Raw: uint64((i + baseAlgoPerAccount) * 100000)})
		ad.VoteFirstValid = 1
		ad.VoteLastValid = 100_000
		initAccounts[genaddrs[i]] = ad
	}
	initKeys[poolAddr] = poolSecret
	initAccounts[poolAddr] = basics_testing.MakeAccountData(basics.NotParticipating, basics.MicroAlgos{Raw: 1234567})
	initKeys[sinkAddr] = sinkSecret
	initAccounts[sinkAddr] = basics_testing.MakeAccountData(basics.NotParticipating, basics.MicroAlgos{Raw: 7654321})

	genesisBalances := bookkeeping.MakeTimestampedGenesisBalances(initAccounts, sinkAddr, poolAddr, 0)
	genesisID := tb.Name()
	genesisHash := crypto.Hash([]byte(genesisID))

	initBlock, err := bookkeeping.MakeGenesisBlock(proto, genesisBalances, genesisID, genesisHash)
	require.NoError(tb, err)

	initBlock.TxnCommitments, err = initBlock.PaysetCommit()
	require.NoError(tb, err)

	genesisInitState.Block = initBlock
	genesisInitState.Accounts = initAccounts
	genesisInitState.GenesisHash = genesisHash

	return
}
