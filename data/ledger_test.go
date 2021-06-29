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

package data

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/algorand/go-algorand/agreement"
	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/bookkeeping"
	"github.com/algorand/go-algorand/data/transactions"
	"github.com/algorand/go-algorand/ledger"
	"github.com/algorand/go-algorand/ledger/ledgercore"
	"github.com/algorand/go-algorand/logging"
	"github.com/algorand/go-algorand/protocol"
   "github.com/algorand/go-algorand/testPartitioning"
)

var testPoolAddr = basics.Address{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}
var testSinkAddr = basics.Address{0x2c, 0x2a, 0x6c, 0xe9, 0xa9, 0xa7, 0xc2, 0x8c, 0x22, 0x95, 0xfd, 0x32, 0x4f, 0x77, 0xa5, 0x4, 0x8b, 0x42, 0xc2, 0xb7, 0xa8, 0x54, 0x84, 0xb6, 0x80, 0xb1, 0xe1, 0x3d, 0x59, 0x9b, 0xeb, 0x36}

func testGenerateInitState(tb testing.TB, proto protocol.ConsensusVersion) (genesisInitState ledger.InitState, initKeys map[basics.Address]*crypto.SignatureSecrets) {

	var poolSecret, sinkSecret *crypto.SignatureSecrets
	var seed crypto.Seed

	incentivePoolName := []byte("incentive pool")
	copy(seed[:], incentivePoolName)
	poolSecret = crypto.GenerateSignatureSecrets(seed)

	feeSinkName := []byte("fee sink")
	copy(seed[:], feeSinkName)
	sinkSecret = crypto.GenerateSignatureSecrets(seed)

	params := config.Consensus[proto]
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

	initKeys = make(map[basics.Address]*crypto.SignatureSecrets)
	initAccounts := make(map[basics.Address]basics.AccountData)
	for i := range genaddrs {
		initKeys[genaddrs[i]] = gensecrets[i]
		// Give each account quite a bit more balance than MinFee or MinBalance
		accountStatus := basics.Online
		if i%2 == 0 {
			accountStatus = basics.NotParticipating
		}
		initAccounts[genaddrs[i]] = basics.MakeAccountData(accountStatus, basics.MicroAlgos{Raw: uint64((i + 100) * 100000)})
	}
	initKeys[poolAddr] = poolSecret
	initAccounts[poolAddr] = basics.MakeAccountData(basics.NotParticipating, basics.MicroAlgos{Raw: 1234567})
	initKeys[sinkAddr] = sinkSecret
	initAccounts[sinkAddr] = basics.MakeAccountData(basics.NotParticipating, basics.MicroAlgos{Raw: 7654321})

	incentivePoolBalanceAtGenesis := initAccounts[poolAddr].MicroAlgos
	initialRewardsPerRound := incentivePoolBalanceAtGenesis.Raw / uint64(params.RewardsRateRefreshInterval)

	initBlock := bookkeeping.Block{
		BlockHeader: bookkeeping.BlockHeader{
			GenesisID: tb.Name(),
			Round:     0,
			RewardsState: bookkeeping.RewardsState{
				RewardsRate: initialRewardsPerRound,
				RewardsPool: poolAddr,
				FeeSink:     sinkAddr,
			},
			UpgradeState: bookkeeping.UpgradeState{
				CurrentProtocol: proto,
			},
		},
	}
	var err error
	initBlock.TxnRoot, err = initBlock.PaysetCommit()
	require.NoError(tb, err)
	if params.SupportGenesisHash {
		initBlock.BlockHeader.GenesisHash = crypto.Hash([]byte(tb.Name()))
	}

	genesisInitState.Block = initBlock
	genesisInitState.Accounts = initAccounts
	genesisInitState.GenesisHash = crypto.Hash([]byte(tb.Name()))

	return
}

func TestLedgerCirculation(t *testing.T) {
   testPartitioning.PartitionTest(t)

	genesisInitState, keys := testGenerateInitState(t, protocol.ConsensusCurrentVersion)

	const inMem = true
	cfg := config.GetDefaultLocal()
	cfg.Archival = true
	log := logging.TestingLog(t)
	log.SetLevel(logging.Warn)
	realLedger, err := ledger.OpenLedger(log, t.Name(), inMem, genesisInitState, cfg)
	require.NoError(t, err, "could not open ledger")
	defer realLedger.Close()

	l := Ledger{Ledger: realLedger}
	require.NotNil(t, &l)

	var sourceAccount basics.Address
	var destAccount basics.Address
	for addr, acctData := range genesisInitState.Accounts {
		if addr == testPoolAddr || addr == testSinkAddr {
			continue
		}
		if acctData.Status == basics.Online {
			sourceAccount = addr
			break
		}
	}
	for addr, acctData := range genesisInitState.Accounts {
		if addr == testPoolAddr || addr == testSinkAddr {
			continue
		}
		if acctData.Status == basics.NotParticipating {
			destAccount = addr
			break
		}
	}
	require.False(t, sourceAccount.IsZero())
	require.False(t, destAccount.IsZero())

	data, err := realLedger.Lookup(basics.Round(0), destAccount)
	require.NoError(t, err)
	baseDestValue := data.MicroAlgos.Raw

	blk := genesisInitState.Block
	totals, _ := realLedger.Totals(basics.Round(0))
	baseCirculation := totals.Online.Money.Raw

	srcAccountKey := keys[sourceAccount]
	require.NotNil(t, srcAccountKey)

	for rnd := basics.Round(1); rnd < basics.Round(600); rnd++ {
		blk.BlockHeader.Round++
		blk.BlockHeader.TimeStamp += int64(crypto.RandUint64() % 100 * 1000)
		var tx transactions.Transaction
		tx.Sender = sourceAccount
		tx.Fee = basics.MicroAlgos{Raw: 10000}
		tx.FirstValid = rnd - 1
		tx.LastValid = tx.FirstValid + 999
		tx.Receiver = destAccount
		tx.Amount = basics.MicroAlgos{Raw: 1}
		tx.Type = protocol.PaymentTx
		signedTx := tx.Sign(srcAccountKey)
		blk.Payset = transactions.Payset{transactions.SignedTxnInBlock{
			SignedTxnWithAD: transactions.SignedTxnWithAD{
				SignedTxn: signedTx,
			},
		}}
		require.NoError(t, l.AddBlock(blk, agreement.Certificate{}))
		l.WaitForCommit(rnd)

		// test most recent round
		if rnd < basics.Round(500) {
			data, err = realLedger.Lookup(rnd, destAccount)
			require.NoError(t, err)
			require.Equal(t, baseDestValue+uint64(rnd), data.MicroAlgos.Raw)
			data, err = l.Lookup(rnd, destAccount)
			require.NoError(t, err)
			require.Equal(t, baseDestValue+uint64(rnd), data.MicroAlgos.Raw)

			totals, err = realLedger.Totals(rnd)
			require.NoError(t, err)
			roundCirculation := totals.Online.Money.Raw
			require.Equal(t, baseCirculation-uint64(rnd)*(10001), roundCirculation)

			totals, err = l.Totals(rnd)
			require.NoError(t, err)
			roundCirculation = totals.Online.Money.Raw
			require.Equal(t, baseCirculation-uint64(rnd)*(10001), roundCirculation)
		} else if rnd < basics.Round(510) {
			// test one round ago
			data, err = realLedger.Lookup(rnd-1, destAccount)
			require.NoError(t, err)
			require.Equal(t, baseDestValue+uint64(rnd)-1, data.MicroAlgos.Raw)
			data, err = l.Lookup(rnd-1, destAccount)
			require.NoError(t, err)
			require.Equal(t, baseDestValue+uint64(rnd)-1, data.MicroAlgos.Raw)

			totals, err = realLedger.Totals(rnd - 1)
			require.NoError(t, err)
			roundCirculation := totals.Online.Money.Raw
			require.Equal(t, baseCirculation-uint64(rnd-1)*(10001), roundCirculation)

			totals, err = l.Totals(rnd - 1)
			require.NoError(t, err)
			roundCirculation = totals.Online.Money.Raw
			require.Equal(t, baseCirculation-uint64(rnd-1)*(10001), roundCirculation)
		} else if rnd < basics.Round(520) {
			// test one round in the future ( expected error )
			data, err = realLedger.Lookup(rnd+1, destAccount)
			require.Error(t, err)
			require.Equal(t, uint64(0), data.MicroAlgos.Raw)
			data, err = l.Lookup(rnd+1, destAccount)
			require.Error(t, err)
			require.Equal(t, uint64(0), data.MicroAlgos.Raw)

			_, err = realLedger.Totals(rnd + 1)
			require.Error(t, err)

			_, err = l.Totals(rnd + 1)
			require.Error(t, err)
		} else if rnd < basics.Round(520) {
			// test expired round ( expected error )
			_, err = realLedger.Totals(rnd - 500)
			require.Error(t, err)

			_, err = l.Totals(rnd - 500)
			require.Error(t, err)
		}
	}
	return
}

func TestLedgerSeed(t *testing.T) {
   testPartitioning.PartitionTest(t)

	genesisInitState, _ := testGenerateInitState(t, protocol.ConsensusCurrentVersion)

	const inMem = true
	cfg := config.GetDefaultLocal()
	cfg.Archival = true
	log := logging.TestingLog(t)
	log.SetLevel(logging.Warn)
	realLedger, err := ledger.OpenLedger(log, t.Name(), inMem, genesisInitState, cfg)
	require.NoError(t, err, "could not open ledger")
	defer realLedger.Close()

	l := Ledger{Ledger: realLedger}
	require.NotNil(t, &l)

	blk := genesisInitState.Block
	for rnd := basics.Round(1); rnd < basics.Round(32); rnd++ {
		blk.BlockHeader.Round++
		blk.BlockHeader.Seed[0] = byte(uint64(rnd))
		blk.BlockHeader.Seed[1] = byte(uint64(rnd) / 256)
		blk.BlockHeader.Seed[2] = byte(uint64(rnd) / 65536)
		blk.BlockHeader.TimeStamp += int64(crypto.RandUint64() % 100 * 1000)
		require.NoError(t, l.AddBlock(blk, agreement.Certificate{}))
		l.WaitForCommit(rnd)
		if rnd < basics.Round(16) {
			// test the current round
			expectedHdr, err := realLedger.BlockHdr(rnd)
			require.NoError(t, err)

			// ensure the item is not in the cache
			seed, cached := l.lastRoundSeed.Load().(roundSeed)
			if cached {
				require.NotEqual(t, seed.elements[1].seed, expectedHdr.Seed)
			}

			actualSeed, err := l.Seed(rnd)
			require.NoError(t, err)

			require.Equal(t, expectedHdr.Seed, actualSeed)

			seed, cached = l.lastRoundSeed.Load().(roundSeed)
			require.True(t, cached)
			require.Equal(t, seed.elements[1].seed, expectedHdr.Seed)
		} else if rnd < basics.Round(32) {
			// test against the previous round
			expectedHdr, err := realLedger.BlockHdr(rnd - 1)
			require.NoError(t, err)

			// ensure the cache is aligned with the previous round
			seed, cached := l.lastRoundSeed.Load().(roundSeed)
			require.True(t, cached)
			require.Equal(t, seed.elements[1].round, rnd-1)
			require.Equal(t, seed.elements[1].seed, expectedHdr.Seed)

			actualSeed, err := l.Seed(rnd)
			require.NoError(t, err)

			expectedHdr, err = realLedger.BlockHdr(rnd)
			require.NoError(t, err)

			require.Equal(t, expectedHdr.Seed, actualSeed)

			// ensure the cache is aligned with the updated round
			seed, cached = l.lastRoundSeed.Load().(roundSeed)
			require.True(t, cached)
			require.Equal(t, seed.elements[1].round, rnd)
			require.Equal(t, seed.elements[1].seed, expectedHdr.Seed)
		}
	}
	return
}

func TestConsensusVersion(t *testing.T) {
   testPartitioning.PartitionTest(t)

	// find a consensus protocol that leads to ConsensusCurrentVersion
	var previousProtocol protocol.ConsensusVersion
	for ver, params := range config.Consensus {
		if _, has := params.ApprovedUpgrades[protocol.ConsensusCurrentVersion]; has {
			previousProtocol = ver
			break
		}
	}
	require.NotEqual(t, protocol.ConsensusVersion(""), previousProtocol)
	consensusParams := config.Consensus[previousProtocol]

	genesisInitState, _ := testGenerateInitState(t, previousProtocol)

	const inMem = true
	cfg := config.GetDefaultLocal()
	cfg.Archival = false
	log := logging.TestingLog(t)
	log.SetLevel(logging.Warn)
	realLedger, err := ledger.OpenLedger(log, t.Name(), inMem, genesisInitState, cfg)
	require.NoError(t, err, "could not open ledger")
	defer realLedger.Close()

	l := Ledger{Ledger: realLedger}
	require.NotNil(t, &l)

	blk := genesisInitState.Block

	// add 5 blocks.
	for rnd := basics.Round(1); rnd < basics.Round(consensusParams.MaxTxnLife+5); rnd++ {
		blk.BlockHeader.Round++
		blk.BlockHeader.Seed[0] = byte(uint64(rnd))
		blk.BlockHeader.Seed[1] = byte(uint64(rnd) / 256)
		blk.BlockHeader.Seed[2] = byte(uint64(rnd) / 65536)
		blk.BlockHeader.TimeStamp += int64(crypto.RandUint64() % 100 * 1000)
		blk.BlockHeader.CurrentProtocol = previousProtocol
		require.NoError(t, l.AddBlock(blk, agreement.Certificate{}))
		l.WaitForCommit(rnd)
	}
	// ensure that all the first 5 has the expected version.
	for rnd := basics.Round(consensusParams.MaxTxnLife); rnd < basics.Round(consensusParams.MaxTxnLife+5); rnd++ {
		ver, err := l.ConsensusVersion(rnd)
		require.NoError(t, err)
		require.Equal(t, previousProtocol, ver)
	}
	// the next UpgradeVoteRounds can also be known to have the previous version.
	for rnd := basics.Round(consensusParams.MaxTxnLife + 5); rnd < basics.Round(consensusParams.MaxTxnLife+5+consensusParams.UpgradeVoteRounds); rnd++ {
		ver, err := l.ConsensusVersion(rnd)
		require.NoError(t, err)
		require.Equal(t, previousProtocol, ver)
	}

	// but two rounds ahead is not known.
	ver, err := l.ConsensusVersion(basics.Round(consensusParams.MaxTxnLife + 6 + consensusParams.UpgradeVoteRounds))
	require.Equal(t, protocol.ConsensusVersion(""), ver)
	require.Equal(t, ledgercore.ErrNoEntry{Round: basics.Round(consensusParams.MaxTxnLife + 6 + consensusParams.UpgradeVoteRounds), Latest: basics.Round(consensusParams.MaxTxnLife + 4), Committed: basics.Round(consensusParams.MaxTxnLife + 4)}, err)

	// check round #1 which was already dropped.
	ver, err = l.ConsensusVersion(basics.Round(1))
	require.Equal(t, protocol.ConsensusVersion(""), ver)
	require.Equal(t, ledgercore.ErrNoEntry{Round: basics.Round(1), Latest: basics.Round(consensusParams.MaxTxnLife + 4), Committed: basics.Round(consensusParams.MaxTxnLife + 4)}, err)

	// add another round, with upgrade
	rnd := basics.Round(consensusParams.MaxTxnLife + 5)
	blk.BlockHeader.Round++
	blk.BlockHeader.Seed[0] = byte(uint64(rnd))
	blk.BlockHeader.Seed[1] = byte(uint64(rnd) / 256)
	blk.BlockHeader.Seed[2] = byte(uint64(rnd) / 65536)
	blk.BlockHeader.TimeStamp += int64(crypto.RandUint64() % 100 * 1000)
	blk.BlockHeader.CurrentProtocol = previousProtocol
	blk.BlockHeader.NextProtocol = protocol.ConsensusCurrentVersion
	blk.BlockHeader.NextProtocolVoteBefore = basics.Round(rnd) + basics.Round(consensusParams.UpgradeVoteRounds)
	blk.BlockHeader.NextProtocolSwitchOn = basics.Round(rnd) + basics.Round(consensusParams.UpgradeVoteRounds) + basics.Round(consensusParams.ApprovedUpgrades[protocol.ConsensusCurrentVersion])
	require.NoError(t, l.AddBlock(blk, agreement.Certificate{}))
	l.WaitForCommit(rnd)

	for ; rnd < blk.BlockHeader.NextProtocolSwitchOn; rnd++ {
		ver, err := l.ConsensusVersion(rnd)
		require.NoError(t, err)
		require.Equal(t, previousProtocol, ver)
	}

	for rnd = blk.BlockHeader.Round; rnd <= blk.BlockHeader.NextProtocolVoteBefore; rnd++ {
		blk.BlockHeader.Round++
		blk.BlockHeader.Seed[0] = byte(uint64(rnd))
		blk.BlockHeader.Seed[1] = byte(uint64(rnd) / 256)
		blk.BlockHeader.Seed[2] = byte(uint64(rnd) / 65536)
		blk.BlockHeader.NextProtocolApprovals++
		blk.BlockHeader.TimeStamp += int64(crypto.RandUint64() % 100 * 1000)
		require.NoError(t, l.AddBlock(blk, agreement.Certificate{}))
		l.WaitForCommit(rnd + 1)
	}

	ver, err = l.ConsensusVersion(blk.BlockHeader.NextProtocolSwitchOn)
	require.NoError(t, err)
	require.Equal(t, protocol.ConsensusCurrentVersion, ver)

	ver, err = l.ConsensusVersion(blk.BlockHeader.NextProtocolSwitchOn + 1)
	require.Equal(t, protocol.ConsensusVersion(""), ver)
	require.Equal(t, ledgercore.ErrNoEntry{Round: basics.Round(blk.BlockHeader.NextProtocolSwitchOn + 1), Latest: basics.Round(blk.BlockHeader.Round), Committed: basics.Round(blk.BlockHeader.Round)}, err)
}
