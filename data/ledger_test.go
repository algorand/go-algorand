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

package data

import (
	"context"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/algorand/go-algorand/agreement"
	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/data/basics"
	basics_testing "github.com/algorand/go-algorand/data/basics/testing"
	"github.com/algorand/go-algorand/data/bookkeeping"
	"github.com/algorand/go-algorand/data/transactions"
	"github.com/algorand/go-algorand/ledger"
	"github.com/algorand/go-algorand/ledger/ledgercore"
	"github.com/algorand/go-algorand/logging"
	"github.com/algorand/go-algorand/protocol"
	"github.com/algorand/go-algorand/test/partitiontest"
	"github.com/algorand/go-algorand/util/execpool"
)

var testPoolAddr = basics.Address{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}
var testSinkAddr = basics.Address{0x2c, 0x2a, 0x6c, 0xe9, 0xa9, 0xa7, 0xc2, 0x8c, 0x22, 0x95, 0xfd, 0x32, 0x4f, 0x77, 0xa5, 0x4, 0x8b, 0x42, 0xc2, 0xb7, 0xa8, 0x54, 0x84, 0xb6, 0x80, 0xb1, 0xe1, 0x3d, 0x59, 0x9b, 0xeb, 0x36}

func testGenerateInitState(tb testing.TB, proto protocol.ConsensusVersion) (genesisInitState ledgercore.InitState, initKeys map[basics.Address]*crypto.SignatureSecrets) {

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
		initAccounts[genaddrs[i]] = basics_testing.MakeAccountData(accountStatus, basics.MicroAlgos{Raw: uint64((i + 100) * 100000)})
	}
	initKeys[poolAddr] = poolSecret
	initAccounts[poolAddr] = basics_testing.MakeAccountData(basics.NotParticipating, basics.MicroAlgos{Raw: 1234567})
	initKeys[sinkAddr] = sinkSecret
	initAccounts[sinkAddr] = basics_testing.MakeAccountData(basics.NotParticipating, basics.MicroAlgos{Raw: 7654321})

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
	initBlock.TxnCommitments, err = initBlock.PaysetCommit()
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
	partitiontest.PartitionTest(t)

	proto := protocol.ConsensusCurrentVersion
	genesisInitState, keys := testGenerateInitState(t, proto)

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

	data, validThrough, _, err := realLedger.LookupAccount(basics.Round(0), destAccount)
	require.Equal(t, basics.Round(0), validThrough)
	require.NoError(t, err)
	baseDestValue := data.MicroAlgos.Raw

	blk := genesisInitState.Block
	totalsRound, totals, err := realLedger.LatestTotals()
	require.NoError(t, err)
	require.Equal(t, basics.Round(0), totalsRound)
	baseCirculation := totals.Online.Money.Raw

	srcAccountKey := keys[sourceAccount]
	require.NotNil(t, srcAccountKey)

	params := config.Consensus[proto]

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

		var voteRoundOffset = basics.Round(2 * params.SeedRefreshInterval * params.SeedLookback)

		// test most recent round
		if rnd < basics.Round(500) {
			data, validThrough, _, err = realLedger.LookupAccount(rnd, destAccount)
			require.NoError(t, err)
			require.Equal(t, rnd, validThrough)
			require.Equal(t, baseDestValue+uint64(rnd), data.MicroAlgos.Raw)
			data, validThrough, _, err = realLedger.LookupAccount(rnd, destAccount)
			require.NoError(t, err)
			require.Equal(t, rnd, validThrough)
			require.Equal(t, baseDestValue+uint64(rnd), data.MicroAlgos.Raw)

			roundCirculation, err := realLedger.OnlineCirculation(rnd, rnd+voteRoundOffset)
			require.NoError(t, err)
			require.Equal(t, baseCirculation-uint64(rnd)*(10001), roundCirculation.Raw)

			roundCirculation, err = l.OnlineCirculation(rnd, rnd+voteRoundOffset)
			require.NoError(t, err)
			require.Equal(t, baseCirculation-uint64(rnd)*(10001), roundCirculation.Raw)
		} else if rnd < basics.Round(510) {
			// test one round ago
			data, validThrough, _, err = realLedger.LookupAccount(rnd-1, destAccount)
			require.NoError(t, err)
			require.Equal(t, rnd-1, validThrough)
			require.Equal(t, baseDestValue+uint64(rnd)-1, data.MicroAlgos.Raw)
			data, validThrough, _, err = l.LookupAccount(rnd-1, destAccount)
			require.NoError(t, err)
			require.Equal(t, rnd-1, validThrough)
			require.Equal(t, baseDestValue+uint64(rnd)-1, data.MicroAlgos.Raw)

			roundCirculation, err := realLedger.OnlineCirculation(rnd-1, rnd-1+voteRoundOffset)
			require.NoError(t, err)
			require.Equal(t, baseCirculation-uint64(rnd-1)*(10001), roundCirculation.Raw)

			roundCirculation, err = l.OnlineCirculation(rnd-1, rnd-1+voteRoundOffset)
			require.NoError(t, err)
			require.Equal(t, baseCirculation-uint64(rnd-1)*(10001), roundCirculation.Raw)
		} else if rnd < basics.Round(520) {
			// test one round in the future ( expected error )
			data, _, _, err = realLedger.LookupAccount(rnd+1, destAccount)
			require.Error(t, err)
			require.Equal(t, uint64(0), data.MicroAlgos.Raw)
			data, _, _, err = l.LookupAccount(rnd+1, destAccount)
			require.Error(t, err)
			require.Equal(t, uint64(0), data.MicroAlgos.Raw)

			_, err = realLedger.OnlineCirculation(rnd+1, rnd+1+voteRoundOffset)
			require.Error(t, err)

			_, err = l.OnlineCirculation(rnd+1, rnd+1+voteRoundOffset)
			require.Error(t, err)
		} else if rnd < basics.Round(520) {
			// test expired round ( expected error )
			_, err = realLedger.OnlineCirculation(rnd-500, rnd-500+voteRoundOffset)
			require.Error(t, err)

			_, err = l.OnlineCirculation(rnd-500, rnd-500+voteRoundOffset)
			require.Error(t, err)
		}
	}
}

func TestLedgerSeed(t *testing.T) {
	partitiontest.PartitionTest(t)

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
}

func TestConsensusVersion(t *testing.T) {
	partitiontest.PartitionTest(t)
	if testing.Short() {
		t.Log("this is a long test and skipping for -short")
		return
	}

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
	flushOffset := uint64(129) // pendingDeltasFlushThreshold = 128 will flush every 128 rounds (RewardsPool acct)
	// txTailRetainSize = MaxTxnLife + DeeperBlockHeaderHistory = 1000 + 1

	// add some blocks.
	for rnd := basics.Round(1); rnd < basics.Round(consensusParams.MaxTxnLife+flushOffset); rnd++ {
		blk.BlockHeader.Round++
		blk.BlockHeader.Seed[0] = byte(uint64(rnd))
		blk.BlockHeader.Seed[1] = byte(uint64(rnd) / 256)
		blk.BlockHeader.Seed[2] = byte(uint64(rnd) / 65536)
		blk.BlockHeader.TimeStamp += int64(crypto.RandUint64() % 100 * 1000)
		blk.BlockHeader.CurrentProtocol = previousProtocol
		require.NoError(t, l.AddBlock(blk, agreement.Certificate{}))
		l.WaitForCommit(rnd)
	}
	// ensure that all the first flushOffset have the expected version.
	for rnd := basics.Round(consensusParams.MaxTxnLife); rnd < basics.Round(consensusParams.MaxTxnLife+flushOffset); rnd++ {
		ver, err := l.ConsensusVersion(rnd)
		require.NoError(t, err)
		require.Equal(t, previousProtocol, ver)
	}
	// the next UpgradeVoteRounds can also be known to have the previous version.
	for rnd := basics.Round(consensusParams.MaxTxnLife + flushOffset); rnd < basics.Round(consensusParams.MaxTxnLife+
		flushOffset+consensusParams.UpgradeVoteRounds); rnd++ {
		ver, err := l.ConsensusVersion(rnd)
		require.NoError(t, err)
		require.Equal(t, previousProtocol, ver)
	}

	// but two rounds ahead is not known.
	ver, err := l.ConsensusVersion(basics.Round(consensusParams.MaxTxnLife + flushOffset + 1 + consensusParams.UpgradeVoteRounds))
	require.Equal(t, protocol.ConsensusVersion(""), ver)
	require.Equal(t, ledgercore.ErrNoEntry{
		Round:     basics.Round(consensusParams.MaxTxnLife + flushOffset + 1 + consensusParams.UpgradeVoteRounds),
		Latest:    basics.Round(consensusParams.MaxTxnLife + flushOffset - 1),
		Committed: basics.Round(consensusParams.MaxTxnLife + flushOffset - 1)}, err)

	// check round #1 which was already dropped.
	ver, err = l.ConsensusVersion(basics.Round(1))
	require.Equal(t, protocol.ConsensusVersion(""), ver)
	require.Equal(t, ledgercore.ErrNoEntry{
		Round:     basics.Round(1),
		Latest:    basics.Round(consensusParams.MaxTxnLife + flushOffset - 1),
		Committed: basics.Round(consensusParams.MaxTxnLife + flushOffset - 1)}, err)

	// add another round, with upgrade
	rnd := basics.Round(consensusParams.MaxTxnLife + flushOffset)
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

type loggedMessages struct {
	logging.Logger
	expectedMessages   chan string
	unexpectedMessages chan string
}

func (lm loggedMessages) Debug(args ...interface{}) {
	m := fmt.Sprint(args...)
	lm.unexpectedMessages <- m
}
func (lm loggedMessages) Debugf(s string, args ...interface{}) {
	m := fmt.Sprintf(s, args...)
	lm.expectedMessages <- m
}
func (lm loggedMessages) Info(args ...interface{}) {
	m := fmt.Sprint(args...)
	lm.unexpectedMessages <- m
}
func (lm loggedMessages) Infof(s string, args ...interface{}) {
	m := fmt.Sprintf(s, args...)
	lm.unexpectedMessages <- m
}
func (lm loggedMessages) Warn(args ...interface{}) {
	m := fmt.Sprint(args...)
	lm.unexpectedMessages <- m
}
func (lm loggedMessages) Warnf(s string, args ...interface{}) {
	m := fmt.Sprintf(s, args...)
	lm.unexpectedMessages <- m
}
func (lm loggedMessages) Error(args ...interface{}) {
	m := fmt.Sprint(args...)
	lm.unexpectedMessages <- m
}
func (lm loggedMessages) Errorf(s string, args ...interface{}) {
	m := fmt.Sprintf(s, args...)
	lm.unexpectedMessages <- m
}

// TestLedgerErrorValidate creates 3 parallel routines adding blocks to the ledger through different interfaces.
// The purpose here is to simulate the scenario where the catchup and the agreement compete to add blocks to the ledger.
// The error messages reported can be excessive or unnecessary. This test evaluates what messages are generate and at what frequency.
func TestLedgerErrorValidate(t *testing.T) {
	partitiontest.PartitionTest(t)

	var testPoolAddr = basics.Address{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}
	var testSinkAddr = basics.Address{0x2c, 0x2a, 0x6c, 0xe9, 0xa9, 0xa7, 0xc2, 0x8c, 0x22, 0x95, 0xfd, 0x32, 0x4f, 0x77, 0xa5, 0x4, 0x8b, 0x42, 0xc2, 0xb7, 0xa8, 0x54, 0x84, 0xb6, 0x80, 0xb1, 0xe1, 0x3d, 0x59, 0x9b, 0xeb, 0x36}

	proto := config.Consensus[protocol.ConsensusCurrentVersion]
	origProto := proto
	defer func() {
		config.Consensus[protocol.ConsensusCurrentVersion] = origProto
	}()
	proto.MinBalance = 0
	config.Consensus[protocol.ConsensusCurrentVersion] = proto

	blk := bookkeeping.Block{}
	blk.CurrentProtocol = protocol.ConsensusCurrentVersion
	blk.RewardsPool = testPoolAddr
	blk.FeeSink = testSinkAddr
	blk.BlockHeader.GenesisHash = crypto.Hash([]byte(t.Name()))

	accts := make(map[basics.Address]basics.AccountData)
	accts[testPoolAddr] = basics_testing.MakeAccountData(basics.NotParticipating, basics.MicroAlgos{Raw: 0})
	accts[testSinkAddr] = basics_testing.MakeAccountData(basics.NotParticipating, basics.MicroAlgos{Raw: 0})

	genesisInitState := ledgercore.InitState{
		Accounts:    accts,
		Block:       blk,
		GenesisHash: crypto.Hash([]byte(t.Name())),
	}

	expectedMessages := make(chan string, 100)
	unexpectedMessages := make(chan string, 100)

	const inMem = true
	cfg := config.GetDefaultLocal()
	cfg.Archival = true
	log := loggedMessages{Logger: logging.TestingLog(t), expectedMessages: expectedMessages, unexpectedMessages: unexpectedMessages}
	log.SetLevel(logging.Debug)
	realLedger, err := ledger.OpenLedger(log, t.Name(), inMem, genesisInitState, cfg)
	require.NoError(t, err, "could not open ledger")
	defer realLedger.Close()

	l := Ledger{Ledger: realLedger, log: log}
	l.log.SetLevel(logging.Warn)
	require.NotNil(t, &l)

	totalsRound, _, err := realLedger.LatestTotals()
	require.NoError(t, err)
	require.Equal(t, basics.Round(0), totalsRound)

	errChan := make(chan error, 1)
	defer close(errChan)

	wg := sync.WaitGroup{}
	defer wg.Wait()

	blkChan1 := make(chan bookkeeping.Block, 10)
	blkChan2 := make(chan bookkeeping.Block, 10)
	blkChan3 := make(chan bookkeeping.Block, 10)
	defer close(blkChan1)
	defer close(blkChan2)
	defer close(blkChan3)

	// Add blocks to the ledger via EnsureValidatedBlock. This calls AddValidatedBlock, which simply
	// passes the block to blockQueue. The returned error is handled by EnsureValidatedBlock, which reports
	// in the form of logged error message.
	wg.Add(1)
	go func() {
		i := 0
		for blk := range blkChan1 {
			i++
			vb, err := validatedBlock(l.Ledger, blk)
			if err != nil {
				// AddBlock already added the block
				// This is okay to ignore.
				// This error is generated from ledger.Ledger Validate function, used from:
				// - node blockValidatorImpl Validate
				// - catchup service s.ledger.Validate (Catchup service returns after the first error)
				continue
			}
			l.EnsureValidatedBlock(vb, agreement.Certificate{})
		}
		wg.Done()
	}()

	// Add blocks to the ledger via EnsureBlock. This basically calls AddBlock, but handles
	// the errors by logging them. Checking the logged messages to verify its behavior.
	wg.Add(1)
	go func() {
		i := 0
		for blk := range blkChan2 {
			i++
			l.EnsureBlock(&blk, agreement.Certificate{})
		}
		wg.Done()
	}()

	// Add blocks directly to the ledger
	wg.Add(1)
	go func() {
		i := 0
		for blk := range blkChan3 {
			i++
			err := l.AddBlock(blk, agreement.Certificate{})
			// AddBlock is used in 2 places:
			// - data.ledger.EnsureBlock which reports a log message as Error or Debug
			// - catchup.service.fetchAndWrite which leads to interrupting catchup or skipping the round
			if err != nil {
				switch err.(type) {
				// The following two cases are okay to ignore, since these are expected and handled
				case ledgercore.BlockInLedgerError:
				case ledgercore.ErrNonSequentialBlockEval:
					continue
				default:
					// Make sure unexpected error is not obtained here
					errChan <- err
				}
			}
			l.WaitForCommit(blk.BlockHeader.Round)
		}
		wg.Done()
	}()

	// flush the messages output during the setup
	more := true
	for more {
		select {
		case <-expectedMessages:
		case <-unexpectedMessages:
		default:
			more = false
		}
	}

	for rnd := basics.Round(1); rnd <= basics.Round(2000); rnd++ {
		blk, err := getEmptyBlock(rnd-1, l.Ledger, t.Name(), genesisInitState.Accounts)
		require.NoError(t, err)
		blkChan3 <- blk
		blkChan2 <- blk
		blkChan1 <- blk

		more = true
		for more {
			select {
			case err := <-errChan:
				if strings.Contains(err.Error(), "before dbRound") {
					// handle race eval errors like "round 1933 before dbRound 1934"
					// see explanation in unexpectedMessages
					re := regexp.MustCompile(`round (\d+) before dbRound (\d+)`)
					result := re.FindStringSubmatch(err.Error())
					require.NotNil(t, result)
					require.Len(t, result, 3)
					evalRound, err1 := strconv.Atoi(result[1])
					require.NoError(t, err1)
					dbRound, err1 := strconv.Atoi(result[2])
					require.NoError(t, err1)
					require.GreaterOrEqual(t, int(l.Latest()), dbRound+int(cfg.MaxAcctLookback))
					require.Less(t, evalRound, dbRound)
					err = nil
				}
				require.NoError(t, err)
			case <-expectedMessages:
				// only debug messages should be reported
			case um := <-unexpectedMessages:
				if strings.Contains(um, "before dbRound") {
					// EnsureBlock might log the following:
					// data.EnsureBlock: could not write block 774 to the ledger: round 773 before dbRound 774
					// it happens because of simultaneous EnsureValidatedBlock and EnsureBlock calls
					// that pass round check and then EnsureBlock yields after StartEvaluator.
					// Meanwhile EnsureValidatedBlock finishes and adds the block to the ledger.
					// After that trackersDB commit happen and account data get flushed.
					// The EnsureBlock goroutine then tries to evaluate a first transaction and fails because
					// the trackerDB advanced further.
					// This is okay to ignore if
					// - attempted round is less or equal than dbRound
					// - ledger latest round is greater than dbRound + cfg.MaxAcctLookback
					re := regexp.MustCompile(`could not write block (\d+) to the ledger: round (\d+) before dbRound (\d+)`)
					result := re.FindStringSubmatch(um)
					require.NotNil(t, result)
					require.Len(t, result, 4)
					attemptedRound, err := strconv.Atoi(result[1])
					require.NoError(t, err)
					evalRound, err := strconv.Atoi(result[2])
					require.NoError(t, err)
					dbRound, err := strconv.Atoi(result[3])
					require.NoError(t, err)
					require.Equal(t, attemptedRound, evalRound+1)
					require.LessOrEqual(t, attemptedRound, dbRound)
					require.GreaterOrEqual(t, int(l.Latest()), dbRound+int(cfg.MaxAcctLookback))
					um = ""
				}
				require.Empty(t, um, um)
			default:
				more = false
			}
		}
	}
}

func validatedBlock(l *ledger.Ledger, blk bookkeeping.Block) (vb *ledgercore.ValidatedBlock, err error) {
	backlogPool := execpool.MakeBacklog(nil, 0, execpool.LowPriority, nil)
	defer backlogPool.Shutdown()
	vb, err = l.Validate(context.Background(), blk, backlogPool)
	return
}

func getEmptyBlock(afterRound basics.Round, l *ledger.Ledger, genesisID string, initAccounts map[basics.Address]basics.AccountData) (blk bookkeeping.Block, err error) {
	l.WaitForCommit(afterRound)

	lastBlock, err := l.Block(l.Latest())
	if err != nil {
		return
	}

	proto := config.Consensus[lastBlock.CurrentProtocol]
	blk.BlockHeader = bookkeeping.BlockHeader{
		GenesisID: genesisID,
		Round:     l.Latest() + 1,
		Branch:    lastBlock.Hash(),
		TimeStamp: 0,
	}

	if proto.SupportGenesisHash {
		blk.BlockHeader.GenesisHash = crypto.Hash([]byte(genesisID))
	}

	blk.RewardsPool = testPoolAddr
	blk.FeeSink = testSinkAddr
	blk.CurrentProtocol = lastBlock.CurrentProtocol

	blk.TxnCommitments, err = blk.PaysetCommit()
	if err != nil {
		return
	}
	return
}
