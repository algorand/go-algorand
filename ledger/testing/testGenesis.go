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

package testing

import (
	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/bookkeeping"
	"github.com/algorand/go-algorand/ledger/ledgercore"
	"github.com/algorand/go-algorand/protocol"
)

// NewTestGenesis creates a bunch of accounts, splits up 10B algos
// between them and the rewardspool and feesink, and gives out the
// addresses and secrets it creates to enable tests.  For special
// scenarios, manipulate these return values before using newTestLedger.
func NewTestGenesis() (bookkeeping.GenesisBalances, []basics.Address, []*crypto.SignatureSecrets) {
	// irrelevant, but deterministic
	sink, err := basics.UnmarshalChecksumAddress("YTPRLJ2KK2JRFSZZNAF57F3K5Y2KCG36FZ5OSYLW776JJGAUW5JXJBBD7Q")
	if err != nil {
		panic(err)
	}
	rewards, err := basics.UnmarshalChecksumAddress("242H5OXHUEBYCGGWB3CQ6AZAMQB5TMCWJGHCGQOZPEIVQJKOO7NZXUXDQA")
	if err != nil {
		panic(err)
	}

	const count = 10
	addrs := make([]basics.Address, count)
	secrets := make([]*crypto.SignatureSecrets, count)
	accts := make(map[basics.Address]basics.AccountData)

	// 10 billion microalgos, across N accounts and pool and sink
	amount := 10 * 1000000000 * 1000000 / uint64(count+2)

	for i := 0; i < count; i++ {
		// Create deterministic addresses, so that output stays the same, run to run.
		var seed crypto.Seed
		seed[0] = byte(i)
		secrets[i] = crypto.GenerateSignatureSecrets(seed)
		addrs[i] = basics.Address(secrets[i].SignatureVerifier)

		adata := basics.AccountData{
			MicroAlgos: basics.MicroAlgos{Raw: amount},
		}
		accts[addrs[i]] = adata
	}

	accts[sink] = basics.AccountData{
		MicroAlgos: basics.MicroAlgos{Raw: amount},
		Status:     basics.NotParticipating,
	}

	accts[rewards] = basics.AccountData{
		MicroAlgos: basics.MicroAlgos{Raw: amount},
	}

	genBalances := bookkeeping.MakeGenesisBalances(accts, sink, rewards)

	return genBalances, addrs, secrets
}

// Genesis creates a genesis state for naccts accounts using the ConsensusCurrentVersion
func Genesis(naccts int) (ledgercore.InitState, []basics.Address, []*crypto.SignatureSecrets) {
	return GenesisWithProto(naccts, protocol.ConsensusCurrentVersion)
}

// GenesisWithProto creates a genesis state for naccts accounts using the proto consensus protocol
func GenesisWithProto(naccts int, proto protocol.ConsensusVersion) (ledgercore.InitState, []basics.Address, []*crypto.SignatureSecrets) {
	blk := bookkeeping.Block{}
	blk.CurrentProtocol = proto
	blk.BlockHeader.GenesisID = "test"
	blk.FeeSink = testSinkAddr
	blk.RewardsPool = testPoolAddr
	crypto.RandBytes(blk.BlockHeader.GenesisHash[:])

	addrs := []basics.Address{}
	keys := []*crypto.SignatureSecrets{}
	accts := make(map[basics.Address]basics.AccountData)

	// 10 billion microalgos, across N accounts and pool and sink
	amount := 10 * 1000000000 * 1000000 / uint64(naccts+2)

	for i := 0; i < naccts; i++ {
		var seed crypto.Seed
		crypto.RandBytes(seed[:])
		key := crypto.GenerateSignatureSecrets(seed)
		addr := basics.Address(key.SignatureVerifier)

		keys = append(keys, key)
		addrs = append(addrs, addr)

		adata := basics.AccountData{}
		adata.MicroAlgos.Raw = amount //1000 * 1000 * 1000 * 1000 / uint64(naccts)
		accts[addr] = adata
	}

	pooldata := basics.AccountData{}
	pooldata.MicroAlgos.Raw = amount //1000 * 1000 * 1000 * 1000
	pooldata.Status = basics.NotParticipating
	accts[testPoolAddr] = pooldata

	sinkdata := basics.AccountData{}
	sinkdata.MicroAlgos.Raw = amount //1000 * 1000 * 1000 * 1000
	sinkdata.Status = basics.NotParticipating
	accts[testSinkAddr] = sinkdata

	genesisHash := blk.BlockHeader.GenesisHash

	incentivePoolBalanceAtGenesis := pooldata.MicroAlgos
	var initialRewardsPerRound uint64
	params := config.Consensus[proto]
	if params.InitialRewardsRateCalculation {
		initialRewardsPerRound = basics.SubSaturate(incentivePoolBalanceAtGenesis.Raw, params.MinBalance) / uint64(params.RewardsRateRefreshInterval)
	} else {
		initialRewardsPerRound = incentivePoolBalanceAtGenesis.Raw / uint64(params.RewardsRateRefreshInterval)
	}
	blk.RewardsRate = initialRewardsPerRound

	return ledgercore.InitState{Block: blk, Accounts: accts, GenesisHash: genesisHash}, addrs, keys
}
