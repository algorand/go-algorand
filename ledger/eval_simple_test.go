// Copyright (C) 2019-2025 Algorand, Inc.
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

package ledger

import (
	"context"
	"encoding/binary"
	"fmt"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/algorand/go-algorand/agreement"
	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/crypto/merklesignature"
	"github.com/algorand/go-algorand/data/basics"
	basics_testing "github.com/algorand/go-algorand/data/basics/testing"
	"github.com/algorand/go-algorand/data/bookkeeping"
	"github.com/algorand/go-algorand/data/committee"
	"github.com/algorand/go-algorand/data/transactions"
	"github.com/algorand/go-algorand/data/txntest"
	"github.com/algorand/go-algorand/ledger/ledgercore"
	ledgertesting "github.com/algorand/go-algorand/ledger/testing"
	"github.com/algorand/go-algorand/logging"
	"github.com/algorand/go-algorand/protocol"
	"github.com/algorand/go-algorand/test/partitiontest"
	"github.com/algorand/go-algorand/util/execpool"
)

func TestBlockEvaluator(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	genesisInitState, addrs, keys := ledgertesting.Genesis(10)

	l, err := OpenLedger(logging.TestingLog(t), t.Name(), true, genesisInitState, config.GetDefaultLocal())
	require.NoError(t, err)
	defer l.Close()

	genesisBlockHeader, err := l.BlockHdr(basics.Round(0))
	require.NoError(t, err)
	newBlock := bookkeeping.MakeBlock(genesisBlockHeader)
	eval, err := l.StartEvaluator(newBlock.BlockHeader, 0, 0, nil)
	require.NoError(t, err)

	genHash := l.GenesisHash()
	txn := transactions.Transaction{
		Type: protocol.PaymentTx,
		Header: transactions.Header{
			Sender:      addrs[0],
			Fee:         minFee,
			FirstValid:  newBlock.Round(),
			LastValid:   newBlock.Round(),
			GenesisHash: genHash,
		},
		PaymentTxnFields: transactions.PaymentTxnFields{
			Receiver: addrs[1],
			Amount:   basics.MicroAlgos{Raw: 100},
		},
	}

	// Correct signature should work
	st := txn.Sign(keys[0])
	err = eval.Transaction(st, transactions.ApplyData{})
	require.NoError(t, err)

	// Broken signature should fail
	stbad := st
	st.Sig[2] ^= 8
	txgroup := []transactions.SignedTxn{stbad}
	err = eval.TestTransactionGroup(txgroup)
	require.Error(t, err)

	// Repeat should fail
	txgroup = []transactions.SignedTxn{st}
	err = eval.TestTransactionGroup(txgroup)
	require.Error(t, err)
	err = eval.Transaction(st, transactions.ApplyData{})
	require.Error(t, err)

	// out of range should fail
	btxn := txn
	btxn.FirstValid++
	btxn.LastValid += 2
	st = btxn.Sign(keys[0])
	txgroup = []transactions.SignedTxn{st}
	err = eval.TestTransactionGroup(txgroup)
	require.Error(t, err)
	err = eval.Transaction(st, transactions.ApplyData{})
	require.Error(t, err)

	// bogus group should fail
	btxn = txn
	btxn.Group[1] = 1
	st = btxn.Sign(keys[0])
	txgroup = []transactions.SignedTxn{st}
	err = eval.TestTransactionGroup(txgroup)
	require.Error(t, err)
	err = eval.Transaction(st, transactions.ApplyData{})
	require.Error(t, err)

	// mixed fields should fail
	btxn = txn
	btxn.XferAsset = 3
	st = btxn.Sign(keys[0])
	txgroup = []transactions.SignedTxn{st}
	err = eval.TestTransactionGroup(txgroup)
	require.Error(t, err)
	// We don't test eval.Transaction() here because it doesn't check txn.WellFormed(), instead relying on that to have already been checked by the transaction pool.
	// err = eval.Transaction(st, transactions.ApplyData{})
	// require.Error(t, err)

	selfTxn := transactions.Transaction{
		Type: protocol.PaymentTx,
		Header: transactions.Header{
			Sender:      addrs[2],
			Fee:         minFee,
			FirstValid:  newBlock.Round(),
			LastValid:   newBlock.Round(),
			GenesisHash: genHash,
		},
		PaymentTxnFields: transactions.PaymentTxnFields{
			Receiver: addrs[2],
			Amount:   basics.MicroAlgos{Raw: 100},
		},
	}
	stxn := selfTxn.Sign(keys[2])

	// TestTransactionGroup() and Transaction() should have the same outcome, but work slightly different code paths.
	txgroup = []transactions.SignedTxn{stxn}
	err = eval.TestTransactionGroup(txgroup)
	require.NoError(t, err)

	err = eval.Transaction(stxn, transactions.ApplyData{})
	require.NoError(t, err)

	t3 := txn
	t3.Amount.Raw++
	t4 := selfTxn
	t4.Amount.Raw++

	// a group without .Group should fail
	s3 := t3.Sign(keys[0])
	s4 := t4.Sign(keys[2])
	txgroup = []transactions.SignedTxn{s3, s4}
	err = eval.TestTransactionGroup(txgroup)
	require.Error(t, err)
	txgroupad := transactions.WrapSignedTxnsWithAD(txgroup)
	err = eval.TransactionGroup(txgroupad)
	require.Error(t, err)

	// Test a group that should work
	var group transactions.TxGroup
	group.TxGroupHashes = []crypto.Digest{crypto.HashObj(t3), crypto.HashObj(t4)}
	t3.Group = crypto.HashObj(group)
	t4.Group = t3.Group
	s3 = t3.Sign(keys[0])
	s4 = t4.Sign(keys[2])
	txgroup = []transactions.SignedTxn{s3, s4}
	err = eval.TestTransactionGroup(txgroup)
	require.NoError(t, err)

	// disagreement on Group id should fail
	t4bad := t4
	t4bad.Group[3] ^= 3
	s4bad := t4bad.Sign(keys[2])
	txgroup = []transactions.SignedTxn{s3, s4bad}
	err = eval.TestTransactionGroup(txgroup)
	require.Error(t, err)
	txgroupad = transactions.WrapSignedTxnsWithAD(txgroup)
	err = eval.TransactionGroup(txgroupad)
	require.Error(t, err)

	// missing part of the group should fail
	txgroup = []transactions.SignedTxn{s3}
	err = eval.TestTransactionGroup(txgroup)
	require.Error(t, err)

	unfinishedBlock, err := eval.GenerateBlock(nil)
	require.NoError(t, err)

	validatedBlock := ledgercore.MakeValidatedBlock(unfinishedBlock.UnfinishedBlock(), unfinishedBlock.UnfinishedDeltas())

	accts := genesisInitState.Accounts
	bal0 := accts[addrs[0]]
	bal1 := accts[addrs[1]]
	bal2 := accts[addrs[2]]

	l.AddValidatedBlock(validatedBlock, agreement.Certificate{})

	bal0new, _, _, err := l.LookupAccount(newBlock.Round(), addrs[0])
	require.NoError(t, err)
	bal1new, _, _, err := l.LookupAccount(newBlock.Round(), addrs[1])
	require.NoError(t, err)
	bal2new, _, _, err := l.LookupAccount(newBlock.Round(), addrs[2])
	require.NoError(t, err)

	require.Equal(t, bal0new.MicroAlgos.Raw, bal0.MicroAlgos.Raw-minFee.Raw-100)
	require.Equal(t, bal1new.MicroAlgos.Raw, bal1.MicroAlgos.Raw+100)
	require.Equal(t, bal2new.MicroAlgos.Raw, bal2.MicroAlgos.Raw-minFee.Raw)
}

// TestPayoutFees ensures that the proper portion of tx fees go to the proposer
func TestPayoutFees(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	// Lots of balance checks that would be messed up by rewards
	genBalances, addrs, _ := ledgertesting.NewTestGenesis(ledgertesting.TurnOffRewards)
	payoutsBegin := 40
	ledgertesting.TestConsensusRange(t, payoutsBegin-1, 0, func(t *testing.T, ver int, cv protocol.ConsensusVersion, cfg config.Local) {
		dl := NewDoubleLedger(t, genBalances, cv, cfg)
		defer dl.Close()

		proposer := basics.Address{0x01, 0x011}
		const eFee = 3_000_000
		dl.txn(
			&txntest.Txn{Type: "pay", Sender: addrs[1],
				Receiver: proposer, Amount: eFee + 50_000_000},
		)

		prp := lookup(dl.t, dl.generator, proposer)
		require.False(t, prp.IncentiveEligible)

		dl.txn(&txntest.Txn{
			Type:         "keyreg",
			Sender:       proposer,
			Fee:          eFee,
			VotePK:       crypto.OneTimeSignatureVerifier{0x01},
			SelectionPK:  crypto.VRFVerifier{0x02},
			StateProofPK: merklesignature.Commitment{0x03},
			VoteFirst:    1, VoteLast: 1000,
		})

		prp = lookup(dl.t, dl.generator, proposer)
		require.Equal(t, ver >= payoutsBegin, prp.IncentiveEligible)

		dl.fullBlock() // start with an empty block, so no payouts from fees are paid at start of next one

		presink := micros(dl.t, dl.generator, genBalances.FeeSink)
		preprop := micros(dl.t, dl.generator, proposer)
		t.Log(" presink", presink)
		t.Log(" preprop", preprop)
		dl.beginBlock()
		pay := txntest.Txn{
			Type:     "pay",
			Sender:   addrs[1],
			Receiver: addrs[2],
			Amount:   100000,
		}
		dl.txns(&pay, pay.Args("again"))
		vb := dl.endBlock(proposer)

		postsink := micros(dl.t, dl.generator, genBalances.FeeSink)
		postprop := micros(dl.t, dl.generator, proposer)
		t.Log(" postsink", postsink)
		t.Log(" postprop", postprop)

		prp = lookup(dl.t, dl.generator, proposer)

		const bonus1 = 10_000_000 // the first bonus value, set in config/consensus.go
		if ver >= payoutsBegin {
			require.True(t, dl.generator.GenesisProto().Payouts.Enabled)    // version sanity check
			require.NotZero(t, dl.generator.GenesisProto().Payouts.Percent) // version sanity check
			// new fields are in the header
			require.EqualValues(t, 2000, vb.Block().FeesCollected.Raw)
			require.EqualValues(t, bonus1, vb.Block().Bonus.Raw)
			require.EqualValues(t, bonus1+1_000, vb.Block().ProposerPayout().Raw)
			// This last one is really only testing the "fake" agreement that
			// happens in dl.endBlock().
			require.EqualValues(t, proposer, vb.Block().Proposer())

			// At the end of the block, part of the fees + bonus have been moved to
			// the proposer.
			require.EqualValues(t, bonus1+1_000, postprop-preprop) // based on 75% in config/consensus.go
			require.EqualValues(t, bonus1-1_000, presink-postsink)
			require.Equal(t, prp.LastProposed, dl.generator.Latest())
		} else {
			require.False(t, dl.generator.GenesisProto().Payouts.Enabled)
			require.Zero(t, dl.generator.GenesisProto().Payouts.Percent) // version sanity check
			require.Zero(t, vb.Block().FeesCollected)
			require.Zero(t, vb.Block().Bonus)
			require.Zero(t, vb.Block().ProposerPayout())
			// fees stayed in the feesink
			require.EqualValues(t, 0, postprop-preprop, "%v", proposer)
			require.EqualValues(t, 2000, postsink-presink)
			require.Zero(t, prp.LastProposed)
		}

		// Do another block, make sure proposer doesn't get paid again. (Sanity
		// check. The code used to award the payout used to be in block n+1).
		vb = dl.fullBlock()
		require.Equal(t, postsink, micros(dl.t, dl.generator, genBalances.FeeSink))
		require.Equal(t, postprop, micros(dl.t, dl.generator, proposer))

		// Rest of the tests only make sense with payout active
		if ver < payoutsBegin {
			return
		}

		// Get the feesink down low, then drain it by proposing.
		feesink := vb.Block().FeeSink
		data := lookup(t, dl.generator, feesink)
		dl.txn(&txntest.Txn{
			Type:     "pay",
			Sender:   feesink,
			Receiver: addrs[1],
			Amount:   data.MicroAlgos.Raw - 12_000_000,
		})
		dl.beginBlock()
		dl.endBlock(proposer)
		require.EqualValues(t, micros(t, dl.generator, feesink), 2_000_000)

		dl.beginBlock()
		dl.endBlock(proposer)
		require.EqualValues(t, micros(t, dl.generator, feesink), 100_000)

		dl.beginBlock()
		dl.endBlock(proposer)
		require.EqualValues(t, micros(t, dl.generator, feesink), 100_000)
	})
}

// TestIncentiveEligible checks that keyreg with extra fee turns on the incentive eligible flag
func TestIncentiveEligible(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	genBalances, addrs, _ := ledgertesting.NewTestGenesis()
	payoutsBegin := 40
	ledgertesting.TestConsensusRange(t, payoutsBegin-1, 0, func(t *testing.T, ver int, cv protocol.ConsensusVersion, cfg config.Local) {
		dl := NewDoubleLedger(t, genBalances, cv, cfg)
		defer dl.Close()

		tooSmall := basics.Address{0x01, 0x011}
		smallest := basics.Address{0x01, 0x022}

		// They begin ineligible
		for _, addr := range []basics.Address{tooSmall, smallest} {
			acct, _, _, err := dl.generator.LookupLatest(addr)
			require.NoError(t, err)
			require.False(t, acct.IncentiveEligible)
		}

		// Fund everyone
		dl.txns(&txntest.Txn{Type: "pay", Sender: addrs[1], Receiver: tooSmall, Amount: 10_000_000},
			&txntest.Txn{Type: "pay", Sender: addrs[1], Receiver: smallest, Amount: 10_000_000},
		)

		// Keyreg (but offline) with various fees. No effect on incentive eligible
		dl.txns(&txntest.Txn{Type: "keyreg", Sender: tooSmall, Fee: 2_000_000 - 1},
			&txntest.Txn{Type: "keyreg", Sender: smallest, Fee: 2_000_000},
		)

		for _, addr := range []basics.Address{tooSmall, smallest} {
			acct, _, _, err := dl.generator.LookupLatest(addr)
			require.NoError(t, err)
			require.False(t, acct.IncentiveEligible)
		}

		// Keyreg to get online with various fees. Sufficient fee gets `smallest` eligible
		keyreg := txntest.Txn{
			Type:         "keyreg",
			VotePK:       crypto.OneTimeSignatureVerifier{0x01},
			SelectionPK:  crypto.VRFVerifier{0x02},
			StateProofPK: merklesignature.Commitment{0x03},
			VoteFirst:    1, VoteLast: 1000,
		}
		tooSmallKR := keyreg
		tooSmallKR.Sender = tooSmall
		tooSmallKR.Fee = 2_000_000 - 1

		smallKR := keyreg
		smallKR.Sender = smallest
		smallKR.Fee = 2_000_000
		dl.txns(&tooSmallKR, &smallKR)
		a, _, _, err := dl.generator.LookupLatest(tooSmall)
		require.NoError(t, err)
		require.False(t, a.IncentiveEligible)
		a, _, _, err = dl.generator.LookupLatest(smallest)
		require.NoError(t, err)
		require.Equal(t, a.IncentiveEligible, ver >= payoutsBegin)
	})
}

// TestAbsentTracking checks that LastProposed and LastHeartbeat are updated
// properly.
func TestAbsentTracking(t *testing.T) {
	partitiontest.PartitionTest(t)

	genBalances, addrs, _ := ledgertesting.NewTestGenesis(func(cfg *ledgertesting.GenesisCfg) {
		cfg.OnlineCount = 2 // So we know proposer should propose every 2 rounds, on average
	}, ledgertesting.TurnOffRewards)
	getOnlineStake := `
		int 0; voter_params_get VoterBalance; itob; log; itob; log;
		int 0; voter_params_get VoterIncentiveEligible; itob; log; itob; log;
		int 1`

	addrIndexes := make(map[basics.Address]int)
	for i, addr := range addrs {
		addrIndexes[addr] = i
	}
	prettyAddrs := func(inAddrs []basics.Address) []string {
		ret := make([]string, len(inAddrs))
		for i, addr := range inAddrs {
			if idx, ok := addrIndexes[addr]; ok {
				ret[i] = fmt.Sprintf("addrs[%d]", idx)
			} else {
				ret[i] = addr.String()
			}
		}
		return ret
	}

	printAbsent := func(vb *ledgercore.ValidatedBlock) {
		t.Helper()
		absent := vb.Block().AbsentParticipationAccounts
		expired := vb.Block().ExpiredParticipationAccounts
		if len(expired) > 0 || len(absent) > 0 {
			t.Logf("rnd %d: expired %d, absent %d (exp %v abs %v)", vb.Block().Round(),
				len(expired), len(absent), prettyAddrs(expired), prettyAddrs(absent))
		}
	}

	checkingBegins := 40
	runTest := func(t *testing.T, cv protocol.ConsensusVersion, cfg config.Local) {
		dl := NewDoubleLedger(t, genBalances, cv, cfg)
		defer dl.Close()

		// we use stakeChecker for testing `voter_params_get` on suspended accounts
		stib := dl.txn(&txntest.Txn{ // #1
			Type:            "appl",
			Sender:          addrs[3], // use non-online account, Totals unchanged
			ApprovalProgram: getOnlineStake,
		})
		stakeChecker := stib.ApplicationID
		require.NotZero(t, stakeChecker)

		checkState := func(addr basics.Address, online bool, eligible bool, expected uint64) {
			t.Helper()
			if !online {
				require.Zero(t, expected)
			}
			stib = dl.txn(&txntest.Txn{
				Type:          "appl",
				Sender:        addr,
				ApplicationID: stakeChecker,
			})
			logs := stib.ApplyData.EvalDelta.Logs
			require.Len(t, logs, 4)
			tBytes := "\x00\x00\x00\x00\x00\x00\x00\x01"
			fBytes := "\x00\x00\x00\x00\x00\x00\x00\x00"
			onlBytes := fBytes
			if online {
				onlBytes = tBytes
			}
			elgBytes := fBytes
			if eligible {
				elgBytes = tBytes
			}
			require.Equal(t, onlBytes, logs[0], "online")
			require.Equal(t, int(expected), int(binary.BigEndian.Uint64([]byte(logs[1]))))
			require.Equal(t, onlBytes, logs[2], "online")
			require.Equal(t, elgBytes, logs[3], "eligible")
		}

		// have addrs[1] go online explicitly, which makes it eligible for suspension.
		// use a large fee, so we can see IncentiveEligible change
		vb := dl.fullBlock(&txntest.Txn{ // #2
			Type:        "keyreg",
			Fee:         10_000_000,
			Sender:      addrs[1],
			VotePK:      [32]byte{1},
			SelectionPK: [32]byte{1},
		})
		addr1Keyreg := vb.Block().Round()
		require.EqualValues(t, 2, addr1Keyreg) // sanity check
		const lookback = 320                   // keyreg puts LastHeartbeat 320 rounds into the future
		require.EqualValues(t, addr1Keyreg+lookback, lookup(t, dl.generator, addrs[1]).LastHeartbeat)

		// as configured above, only the first two accounts should be online
		require.True(t, lookup(t, dl.generator, addrs[0]).Status == basics.Online)
		require.True(t, lookup(t, dl.generator, addrs[1]).Status == basics.Online)
		require.False(t, lookup(t, dl.generator, addrs[2]).Status == basics.Online)
		checkState(addrs[0], true, false, 833_333_333_333_333) // #3
		require.Equal(t, int(lookup(t, dl.generator, addrs[0]).MicroAlgos.Raw), 833_333_333_332_333)
		// although addr[1] just paid to be eligible, it won't be for 320 rounds
		checkState(addrs[1], true, false, 833_333_333_333_333) // #4
		checkState(addrs[2], false, false, 0)                  // #5

		// genesis accounts don't begin IncentiveEligible, even if online
		require.False(t, lookup(t, dl.generator, addrs[0]).IncentiveEligible)
		// but addr[1] paid extra fee. Note this is _current_ state, not really "online"
		require.True(t, lookup(t, dl.generator, addrs[1]).IncentiveEligible)
		require.False(t, lookup(t, dl.generator, addrs[2]).IncentiveEligible)

		vb = dl.fullBlock() // #6
		printAbsent(vb)
		totals, err := dl.generator.Totals(vb.Block().Round())
		require.NoError(t, err)
		require.NotZero(t, totals.Online.Money.Raw)

		// although it's not even online, we'll use addrs[7] as the proposer
		proposer := addrs[7]
		dl.beginBlock()
		dl.txns(&txntest.Txn{
			Type:     "pay",
			Sender:   addrs[1],
			Receiver: addrs[2],
			Amount:   100_000,
		})
		printAbsent(dl.endBlock(proposer)) // #7

		prp := lookup(t, dl.validator, proposer)
		require.Equal(t, prp.LastProposed, dl.validator.Latest())
		require.Zero(t, prp.LastHeartbeat)
		require.False(t, prp.IncentiveEligible)

		// addr[1] paid to an offline account, so Online totals decrease
		newtotals, err := dl.generator.Totals(dl.generator.Latest())
		require.NoError(t, err)
		// payment and fee left the online account
		require.Equal(t, totals.Online.Money.Raw-100_000-1000, newtotals.Online.Money.Raw)
		totals = newtotals

		printAbsent(dl.fullBlock())

		// addrs[2] was already offline
		dl.txns(&txntest.Txn{Type: "keyreg", Sender: addrs[2]}) // OFFLINE keyreg #9
		regger := lookup(t, dl.validator, addrs[2])

		// totals were unchanged by an offline keyreg from an offline account
		newtotals, err = dl.generator.Totals(dl.generator.Latest())
		require.NoError(t, err)
		require.Equal(t, totals.Online.Money.Raw, newtotals.Online.Money.Raw)

		// an offline keyreg transaction records no activity
		require.Zero(t, regger.LastProposed)
		require.Zero(t, regger.LastHeartbeat)

		// ONLINE keyreg without extra fee
		vb = dl.fullBlock(&txntest.Txn{
			Type:        "keyreg",
			Sender:      addrs[2],
			VotePK:      [32]byte{1},
			SelectionPK: [32]byte{1},
		}) // #10
		printAbsent(vb)
		// online totals have grown, addr[2] was added
		newtotals, err = dl.generator.Totals(dl.generator.Latest())
		require.NoError(t, err)
		require.Greater(t, newtotals.Online.Money.Raw, totals.Online.Money.Raw)

		regger = lookup(t, dl.validator, addrs[2])
		require.Zero(t, regger.LastProposed)
		require.True(t, regger.Status == basics.Online)

		// But nothing has changed for voter_params_get, since we're not past 320
		checkState(addrs[0], true, false, 833_333_333_333_333) // #11
		checkState(addrs[1], true, false, 833_333_333_333_333) // #12
		checkState(addrs[2], false, false, 0)                  // #13

		require.NotZero(t, regger.LastHeartbeat) // online keyreg caused update
		require.False(t, regger.IncentiveEligible)

		// ONLINE keyreg with extra fee
		vb = dl.fullBlock(&txntest.Txn{
			Type:        "keyreg",
			Fee:         2_000_000,
			Sender:      addrs[2],
			VotePK:      [32]byte{1},
			SelectionPK: [32]byte{1},
		}) // #14
		printAbsent(vb)
		addr2Eligible := vb.Block().Round()
		require.EqualValues(t, 14, addr2Eligible) // sanity check

		regger = lookup(t, dl.validator, addrs[2])
		require.True(t, regger.IncentiveEligible)
		require.EqualValues(t, 14+320, regger.LastHeartbeat)

		for i := 0; i < 5; i++ {
			printAbsent(dl.fullBlock()) // #15-19
			require.True(t, lookup(t, dl.generator, addrs[0]).Status == basics.Online)
			require.True(t, lookup(t, dl.generator, addrs[1]).Status == basics.Online)
			require.True(t, lookup(t, dl.generator, addrs[2]).Status == basics.Online)
		}

		// all are still online after a few blocks
		require.True(t, lookup(t, dl.generator, addrs[0]).Status == basics.Online)
		require.True(t, lookup(t, dl.generator, addrs[1]).Status == basics.Online)
		require.True(t, lookup(t, dl.generator, addrs[2]).Status == basics.Online)

		var addr1off basics.Round
		var addr2off basics.Round
		// We're at 20, skip ahead by lookback + 60 to see the knockoffs
		const absentFactor = 20
		skip := basics.Round(3) * absentFactor
		for {
			vb := dl.fullBlock()
			printAbsent(vb)

			rnd := vb.Block().Round()
			switch {
			case slices.Contains(vb.Block().AbsentParticipationAccounts, addrs[1]):
				addr1off = rnd
			case slices.Contains(vb.Block().AbsentParticipationAccounts, addrs[2]):
				addr2off = rnd
			default:
				require.Empty(t, vb.Block().AbsentParticipationAccounts)
			}

			if rnd < 100 {
				// `vote_params_get` sees no changes in the early going, because it looks back 320
				checkState(addrs[1], true, false, 833_333_333_333_333) // this also advances a round!
				// to avoid complications from advancing an extra round, we only do this check for 100 rounds
			}

			// addr[1] spent 10A on a fee in rnd 1, so online stake and eligibility adjusted in 323
			if rnd == addr1Keyreg-2+lookback {
				checkState(addrs[1], true, false, 833_333_333_333_333) // check occurs during reg+lookback-1
				checkState(addrs[1], true, true, 833_333_323_333_333)  // check occurs during reg+lookback
			}

			// watch the change across the round that addr2 becomes eligible (by spending 2A in keyreg)
			if rnd == addr2Eligible-2+lookback {
				checkState(addrs[2], true, false, 833_333_333_429_333)
				checkState(addrs[2], true, true, 833_333_331_429_333) // after keyreg w/ 2A is effective
			}

			if rnd > 20+lookback+skip {
				break
			}
		}
		require.Equal(t, addr2Eligible+lookback+skip, addr2off)
		require.Equal(t, addr1Keyreg+lookback+skip+1, addr1off) // addr1 paid out a little bit, extending its lag by 1

		require.Equal(t, basics.Online, lookup(t, dl.generator, addrs[0]).Status) // genesis account
		require.Equal(t, basics.Offline, lookup(t, dl.generator, addrs[1]).Status)
		require.Equal(t, basics.Offline, lookup(t, dl.generator, addrs[2]).Status)
		require.False(t, lookup(t, dl.generator, addrs[2]).IncentiveEligible)

		// now, addrs[2] proposes, so it gets back online, but stays ineligible
		dl.proposer = addrs[2]
		printAbsent(dl.fullBlock())
		require.Equal(t, basics.Online, lookup(t, dl.generator, addrs[2]).Status)
		require.False(t, lookup(t, dl.generator, addrs[2]).IncentiveEligible)

		// The knockoffs have happened, now skip through another lookback rounds
		// to observe the changes with checkstate
		addr1check, addr2check := false, false
		for {
			vb := dl.fullBlock()
			printAbsent(vb)
			rnd := vb.Block().Round()

			// observe addr1 stake going to zero 320 rounds after knockoff
			if rnd == addr1off+lookback-2 {
				checkState(addrs[1], true, true, 833_333_323_188_333)
				checkState(addrs[1], false, false, 0)
				addr1check = true
			}

			// observe addr2 stake going to zero 320 rounds after knockoff
			if rnd == addr2off+lookback-2 {
				checkState(addrs[2], true, true, 833_333_331_427_333) // still "online"
				checkState(addrs[2], false, false, 0)
				addr2check = true
			}

			if rnd > 20+2*lookback+skip {
				break
			}
		}
		// sanity check that we didn't skip one because of checkstate advancing a round
		require.True(t, addr1check)
		require.True(t, addr2check)

		checkState(addrs[0], true, false, 833_333_333_331_333) // addr 0 didn't get suspended (genesis)
	}

	ledgertesting.TestConsensusRange(t, checkingBegins, 0, func(t *testing.T, ver int, cv protocol.ConsensusVersion, cfg config.Local) {
		runTest(t, cv, cfg)
	})
}

// TestAbsenteeChallenges ensures that online accounts that don't (do) respond
// to challenges end up off (on) line.
func TestAbsenteeChallenges(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	genBalances, addrs, _ := ledgertesting.NewTestGenesis(func(cfg *ledgertesting.GenesisCfg) {
		// Get some big accounts online, so the accounts we create here will be
		// a tiny fraction, not expected to propose often.
		cfg.OnlineCount = 5
	})
	checkingBegins := 40

	ledgertesting.TestConsensusRange(t, checkingBegins-1, 0, func(t *testing.T, ver int, cv protocol.ConsensusVersion, cfg config.Local) {
		dl := NewDoubleLedger(t, genBalances, cv, cfg)
		defer dl.Close()

		// This address ends up being used as a proposer, because that's how we
		// jam a specific seed into the block to control the challenge.
		// Therefore, it must be an existing account.
		seedAndProp := basics.Address{0xaa}

		// We'll generate a challenge for accounts that start with 0xaa.
		propguy := basics.Address{0xaa, 0xaa, 0xaa} // Will propose during the challenge window
		regguy := basics.Address{0xaa, 0xbb, 0xbb}  // Will re-reg during the challenge window
		badguy := basics.Address{0xaa, 0x11, 0x11}  // Will ignore the challenge

		// Fund them all and have them go online. That makes them eligible to be challenged
		for i, guy := range []basics.Address{seedAndProp, propguy, regguy, badguy} {
			dl.txns(&txntest.Txn{
				Type:     "pay",
				Sender:   addrs[0],
				Receiver: guy,
				Amount:   10_000_000,
			}, &txntest.Txn{
				Type:        "keyreg",
				Fee:         5_000_000, // enough to be incentive eligible
				Sender:      guy,
				VotePK:      [32]byte{byte(i + 1)},
				SelectionPK: [32]byte{byte(i + 1)},
			})
			acct := lookup(t, dl.generator, guy)
			require.Equal(t, basics.Online, acct.Status)
			require.Equal(t, ver >= checkingBegins, acct.IncentiveEligible, guy)
		}

		for vb := dl.fullBlock(); vb.Block().Round() < 999; vb = dl.fullBlock() {
			// we just advancing to one before the challenge round
		}
		// All still online, same eligibility
		for _, guy := range []basics.Address{propguy, regguy, badguy} {
			acct := lookup(t, dl.generator, guy)
			require.Equal(t, basics.Online, acct.Status)
			require.Equal(t, ver >= checkingBegins, acct.IncentiveEligible, guy)
		}
		// make the BlockSeed start with 0xa in the challenge round
		dl.beginBlock()
		dl.endBlock(seedAndProp) // This becomes the seed, which is used for the challenge

		for vb := dl.fullBlock(); vb.Block().Round() < 1199; vb = dl.fullBlock() {
			// advance through first grace period: no one marked absent
			require.Empty(t, vb.Block().AbsentParticipationAccounts)
		}

		// regguy keyregs before he's caught, which is a heartbeat, he stays on as well
		vb := dl.fullBlock(&txntest.Txn{
			Type:        "keyreg", // Does not pay extra fee, since he's still eligible
			Sender:      regguy,
			VotePK:      [32]byte{1},
			SelectionPK: [32]byte{1},
		})
		require.Equal(t, basics.Round(1200), vb.Block().Round())
		require.Empty(t, vb.Block().AbsentParticipationAccounts)
		acct := lookup(t, dl.generator, regguy)
		require.Equal(t, basics.Online, acct.Status)
		require.Equal(t, ver >= checkingBegins, acct.IncentiveEligible)

		dl.beginBlock()
		vb = dl.endBlock(propguy) // propose, which is a fine (though less likely) way to respond

		// propguy could be suspended in 1201 here, but won't, because they are proposer
		require.Equal(t, basics.Round(1201), vb.Block().Round())

		require.NotContains(t, vb.Block().AbsentParticipationAccounts, []basics.Address{propguy})
		require.NotContains(t, vb.Block().AbsentParticipationAccounts, regguy)
		if ver >= checkingBegins {
			// badguy and regguy will both be suspended in 1201
			require.Contains(t, vb.Block().AbsentParticipationAccounts, badguy)
		}

		// propguy & regguy still online, badguy suspended (depending on consensus version)
		for _, guy := range []basics.Address{propguy, regguy, badguy} {
			acct := lookup(t, dl.generator, guy)
			switch guy {
			case propguy, regguy:
				require.Equal(t, basics.Online, acct.Status)
				require.Equal(t, ver >= checkingBegins, acct.IncentiveEligible)
				require.False(t, acct.VoteID.IsEmpty())
			case badguy:
				// if checking, badguy fails
				require.Equal(t, ver >= checkingBegins, basics.Offline == acct.Status)
				require.False(t, acct.IncentiveEligible)
			}
			// whether suspended or online, all still have VoteID
			require.False(t, acct.VoteID.IsEmpty())
		}

		if ver < checkingBegins {
			for vb := dl.fullBlock(); vb.Block().Round() < 1220; vb = dl.fullBlock() {
				// advance into knockoff period.
			}
			// All still online, same eligibility
			for _, guy := range []basics.Address{propguy, regguy, badguy} {
				acct := lookup(t, dl.generator, guy)
				require.Equal(t, basics.Online, acct.Status)
				require.False(t, acct.IncentiveEligible)
			}
		}
	})
}

func TestDoubleLedgerGetKnockoffCandidates(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	const onlineCount = 5
	genBalances, addrs, _ := ledgertesting.NewTestGenesis(func(cfg *ledgertesting.GenesisCfg) {
		cfg.OnlineCount = onlineCount
		ledgertesting.TurnOffRewards(cfg)
	})
	payoutsBegin := 40

	// txn to send in round 1, to change the balances to be different from genesis
	payTxn := &txntest.Txn{Type: "pay", Sender: addrs[1], Receiver: addrs[2], Amount: 1_000_000}

	checkAccts := func(l *Ledger, rnd basics.Round, cv protocol.ConsensusVersion) {
		accts, err := l.GetKnockOfflineCandidates(rnd, config.Consensus[cv])
		require.NoError(t, err)
		require.NotEmpty(t, accts)

		// get online genesis accounts
		onlineCnt := 0
		genesisOnlineAccts := make(map[basics.Address]basics.OnlineAccountData)
		afterPayTxnOnlineAccts := make(map[basics.Address]basics.OnlineAccountData)
		for addr, ad := range genBalances.Balances {
			if ad.Status == basics.Online {
				onlineCnt++
				genesisOnlineAccts[addr] = basics_testing.OnlineAccountData(ad)
				afterPayTxnOnlineAccts[addr] = basics_testing.OnlineAccountData(ad)
			}
		}

		// calculate expected balances after applying payTxn
		payTxnReceiver := afterPayTxnOnlineAccts[payTxn.Receiver]
		payTxnReceiver.MicroAlgosWithRewards.Raw += payTxn.Amount
		payTxnSender := afterPayTxnOnlineAccts[payTxn.Sender]
		payTxnSender.MicroAlgosWithRewards.Raw -= (payTxn.Amount + config.Consensus[cv].MinTxnFee)
		afterPayTxnOnlineAccts[payTxn.Receiver] = payTxnReceiver
		afterPayTxnOnlineAccts[payTxn.Sender] = payTxnSender

		require.Equal(t, onlineCount, onlineCnt)
		require.Len(t, accts, onlineCnt)
		if rnd == 0 {
			// balances should be same as genesis
			require.Equal(t, genesisOnlineAccts, accts)
		} else {
			// balances > rnd 1 should reflect payTxn change
			require.Equal(t, afterPayTxnOnlineAccts, accts, "rnd %d", rnd)
		}

	}

	ledgertesting.TestConsensusRange(t, payoutsBegin-1, 0, func(t *testing.T, ver int, cv protocol.ConsensusVersion, cfg config.Local) {
		dl := NewDoubleLedger(t, genBalances, cv, cfg)
		defer dl.Close()

		checkAccts(dl.generator, basics.Round(0), cv)
		checkAccts(dl.validator, basics.Round(0), cv)

		// change two accounts' balances to be different from genesis
		payTxn.GenesisHash = crypto.Digest{} // clear if set from previous run
		dl.fullBlock(payTxn)

		// run up to round 240
		proto := config.Consensus[cv]
		upToRound := basics.Round(proto.StateProofInterval - proto.StateProofVotersLookback)
		require.Equal(t, basics.Round(240), upToRound)
		for rnd := dl.fullBlock().Block().Round(); rnd < upToRound; rnd = dl.fullBlock().Block().Round() {
			checkAccts(dl.generator, rnd, cv)
			checkAccts(dl.validator, rnd, cv)
		}
	})
}

// TestVoterAccess ensures that the `voter` opcode works properly when hooked up
// to a real ledger.
func TestVoterAccess(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	genBalances, addrs, _ := ledgertesting.NewTestGenesis(
		ledgertesting.TurnOffRewards,
		func(cfg *ledgertesting.GenesisCfg) {
			cfg.OnlineCount = 1 // So that one is online from the start
		})
	getOnlineStake := `int 0; voter_params_get VoterBalance; itob; log; itob; log; online_stake; itob; log; int 1`

	// `voter_params_get` introduced in 40
	ledgertesting.TestConsensusRange(t, 40, 0, func(t *testing.T, ver int, cv protocol.ConsensusVersion, cfg config.Local) {
		dl := NewDoubleLedger(t, genBalances, cv, cfg)
		defer dl.Close()

		stib := dl.txn(&txntest.Txn{
			Type:            "appl",
			Sender:          addrs[0],
			ApprovalProgram: getOnlineStake,
		})
		stakeChecker := stib.ApplicationID
		require.NotZero(t, stakeChecker)

		// have addrs[1] go online, though it won't be visible right away
		dl.txn(&txntest.Txn{
			Type:        "keyreg",
			Sender:      addrs[1],
			VotePK:      [32]byte{0xaa},
			SelectionPK: [32]byte{0xbb},
		})

		one := basics.Address{0xaa, 0x11}
		two := basics.Address{0xaa, 0x22}
		three := basics.Address{0xaa, 0x33}

		checkState := func(addr basics.Address, online bool, expected uint64, total uint64) {
			t.Helper()
			if !online {
				require.Zero(t, expected)
			}
			stib = dl.txn(&txntest.Txn{
				Type:          "appl",
				Sender:        addr,
				ApplicationID: stakeChecker,
			})
			logs := stib.ApplyData.EvalDelta.Logs
			require.Len(t, logs, 3)
			if online {
				require.Equal(t, "\x00\x00\x00\x00\x00\x00\x00\x01", logs[0])
				require.Equal(t, int(expected), int(binary.BigEndian.Uint64([]byte(logs[1]))))
			} else {
				require.Equal(t, "\x00\x00\x00\x00\x00\x00\x00\x00", logs[0])
				require.Equal(t, int(expected), int(binary.BigEndian.Uint64([]byte(logs[1]))))
			}
			require.Equal(t, int(total), int(binary.BigEndian.Uint64([]byte(logs[2]))))
		}

		checkState(addrs[0], true, 833_333_333_333_333, 833_333_333_333_333)
		// checking again because addrs[0] just paid a fee, but we show online balance hasn't changed yet
		checkState(addrs[0], true, 833_333_333_333_333, 833_333_333_333_333)
		for i := 1; i < 10; i++ {
			checkState(addrs[i], false, 0, 833_333_333_333_333)
		}

		// Fund the new accounts and have them go online.
		for i, addr := range []basics.Address{one, two, three} {
			dl.txns(&txntest.Txn{
				Type:     "pay",
				Sender:   addrs[0],
				Receiver: addr,
				Amount:   (uint64(i) + 1) * 1_000_000_000,
			}, &txntest.Txn{
				Type:        "keyreg",
				Sender:      addr,
				VotePK:      [32]byte{byte(i + 1)},
				SelectionPK: [32]byte{byte(i + 1)},
			})
		}
		// they don't have online stake yet
		for _, addr := range []basics.Address{one, two, three} {
			checkState(addr, false, 0, 833_333_333_333_333)
		}
		for i := 0; i < 320; i++ {
			dl.fullBlock()
		}
		// addr[1] is now visibly online. the total is across all five that are now online, minus various fees paid
		checkState(addrs[1], true, 833_333_333_333_333-2000, 2*833_333_333_333_333-14000)
		for i := 2; i < 10; i++ { // addrs[2-9] never came online
			checkState(addrs[i], false, 0, 2*833_333_333_333_333-14000)
		}
		for i, addr := range []basics.Address{one, two, three} {
			checkState(addr, true, (uint64(i)+1)*1_000_000_000-2000, 2*833_333_333_333_333-14000)
		}
	})
}

// TestHoldingGet tests some of the corner cases for the asset_holding_get
// opcode: the asset doesn't exist, the account doesn't exist, account not opted
// in, vs it has none of the asset. This is tested here, even though it should
// be well tested in 'logic' package, because we want to make sure that errors
// come out of the real ledger in the way that the logic package expects (it
// uses a mock ledger for testing).
func TestHoldingGet(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	genBalances, addrs, _ := ledgertesting.NewTestGenesis()
	// 24 is first version with apps
	ledgertesting.TestConsensusRange(t, 24, 0, func(t *testing.T, ver int, cv protocol.ConsensusVersion, cfg config.Local) {
		dl := NewDoubleLedger(t, genBalances, cv, cfg)
		defer dl.Close()

		makegold := txntest.Txn{
			Type:   protocol.AssetConfigTx,
			Sender: addrs[0],
			AssetParams: basics.AssetParams{
				Total:     10,
				UnitName:  "gold",
				AssetName: "oz",
			},
		}

		// written without assert or swap, so we can use teal v2 and test back to consensus v24
		source := `
#pragma version 2
txn ApplicationID
bnz main
int 1; return
main:
 txn NumAccounts				// Sender, or Accounts[n]
 txn ApplicationArgs 0; btoi
 asset_holding_get AssetBalance
 txn ApplicationArgs 1; btoi; ==; bz bad
 txn ApplicationArgs 2; btoi; ==; return
bad: err
`

		// Advance the ledger so that there's ambiguity of asset index or foreign array index
		for i := 0; i < 10; i++ {
			dl.fullBlock(&txntest.Txn{Type: "pay", Sender: addrs[2], Receiver: addrs[2]})
		}

		create := txntest.Txn{
			Type:            protocol.ApplicationCallTx,
			Sender:          addrs[0],
			ApprovalProgram: source,
		}

		vb := dl.fullBlock(&create) // create the app
		checker := basics.AppIndex(vb.Block().TxnCounter)
		gold := basics.AssetIndex(checker + 2) // doesn't exist yet
		goldBytes := make([]byte, 8)
		binary.BigEndian.PutUint64(goldBytes, uint64(gold))

		check := txntest.Txn{
			Type:            protocol.ApplicationCallTx,
			Sender:          addrs[0],
			ApplicationID:   checker,
			ApplicationArgs: [][]byte{goldBytes, {0}, {0}}, // exist=0 value=0
		}

		dl.fullBlock(&check)
		vb = dl.fullBlock(&makegold) // Works, despite asset not existing
		require.EqualValues(t, gold, vb.Block().TxnCounter)

		// confirm hardcoded "gold" is correct
		b, ok := holding(t, dl.generator, addrs[0], gold)
		require.True(t, ok)
		require.EqualValues(t, 10, b)

		// The asset exists now. asset_holding_get gives 1,10 for the creator
		// (who is auto-opted in)
		check.ApplicationArgs = [][]byte{goldBytes, {1}, {10}} // exist=1 value=10
		dl.fullBlock(&check)

		// but still gives 0,0 for un opted-in addrs[1], because it means
		// "exists" in the given account, i.e. opted in
		check.Sender = addrs[1]
		check.ApplicationArgs = [][]byte{goldBytes, {0}, {0}}
		dl.fullBlock(&check)

		// opt-in addr[1]
		dl.fullBlock(&txntest.Txn{Type: "axfer", XferAsset: gold, Sender: addrs[1], AssetReceiver: addrs[1]})
		check.ApplicationArgs = [][]byte{goldBytes, {1}, {0}}
		dl.fullBlock(&check)

		// non-existent account, with existing asset, cleanly reports exists=0, value=0
		check.Accounts = []basics.Address{{0x01, 0x02}}
		check.ApplicationArgs = [][]byte{goldBytes, {0}, {0}}
		dl.fullBlock(&check)
	})
}

// TestLocalGetEx tests some of the corner cases for the app_local_get_ex
// opcode: the app doesn't exist, the account doesn't exist, account not opted
// in, local key doesn't exists. This is tested here, even though it should be
// well tested in 'logic' package, because we want to make sure that errors come
// out of the real ledger in the way that the logic package expects (it uses a
// mock ledger for testing).
func TestLocalGetEx(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	genBalances, addrs, _ := ledgertesting.NewTestGenesis()
	// 24 is first version with apps
	ledgertesting.TestConsensusRange(t, 24, 0, func(t *testing.T, ver int, cv protocol.ConsensusVersion, cfg config.Local) {
		dl := NewDoubleLedger(t, genBalances, cv, cfg)
		defer dl.Close()

		makeapp := txntest.Txn{
			Type:   "appl",
			Sender: addrs[0],
			LocalStateSchema: basics.StateSchema{
				NumUint: 1,
			},
			GlobalStateSchema: basics.StateSchema{
				NumByteSlice: 3,
			},
		}

		// written without assert or swap, so we can use teal v2 and test back to consensus v24
		source := `
#pragma version 2
txn ApplicationID
bnz main
int 1; return
main:
 txn NumAccounts				// Sender, or Accounts[n]
 txn ApplicationArgs 0; btoi
 byte "KEY"
 app_local_get_ex
 txn ApplicationArgs 1; btoi; ==; bz bad
 txn ApplicationArgs 2; btoi; ==; return
bad: err
`

		// Advance the ledger so that there's no ambiguity of app ID or foreign array slot
		for i := 0; i < 10; i++ {
			dl.fullBlock(&txntest.Txn{Type: "pay", Sender: addrs[2], Receiver: addrs[2]})
		}

		create := txntest.Txn{
			Type:            protocol.ApplicationCallTx,
			Sender:          addrs[0],
			ApprovalProgram: source,
		}

		vb := dl.fullBlock(&create) // create the checker app
		// Since we are testing back to v24, we can't get appID from EvalDelta
		checker := basics.AppIndex(vb.Block().TxnCounter)
		state := checker + 1 // doesn't exist yet
		stateBytes := make([]byte, 8)
		binary.BigEndian.PutUint64(stateBytes, uint64(state))
		check := txntest.Txn{
			Type:            protocol.ApplicationCallTx,
			Sender:          addrs[0],
			ApplicationID:   checker,
			ApplicationArgs: [][]byte{stateBytes, {0}, {0}}, // exist=0 value=0
		}

		// unlike assets, you can't even do `app_local_get_ex` for an address
		// that has not been opted into the app.  For local state, the existence
		// bit is only used to distinguish "key existence". The local state
		// bundle MUST exist or the program fails.
		dl.txn(&check, "cannot fetch key")

		// so we make the app and try again
		dl.fullBlock(&makeapp)
		// confirm hardcoded "state" index is correct
		g, ok := globals(t, dl.generator, addrs[0], state)
		require.True(t, ok)
		require.EqualValues(t, 3, g.GlobalStateSchema.NumByteSlice)

		// still no good, because creating an app does not opt in the creator
		dl.txn(&check, "cannot fetch key")

		// opt-in addr[0]
		dl.fullBlock(&txntest.Txn{Type: "appl", ApplicationID: state, Sender: addrs[0], OnCompletion: transactions.OptInOC})
		check.ApplicationArgs = [][]byte{stateBytes, {0}, {0}}
		dl.fullBlock(&check)
	})
}

func TestRekeying(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	// Bring up a ledger
	genesisInitState, addrs, keys := ledgertesting.Genesis(10)

	l, err := OpenLedger(logging.TestingLog(t), t.Name(), true, genesisInitState, config.GetDefaultLocal())
	require.NoError(t, err)
	defer l.Close()

	// Make a new block
	nextRound := l.Latest() + basics.Round(1)
	genHash := l.GenesisHash()

	// Test plan
	// Syntax: [A -> B][C, D] means transaction from A that rekeys to B with authaddr C and actual sig from D
	makeTxn := func(sender, rekeyto, authaddr basics.Address, signer *crypto.SignatureSecrets, uniq uint8) transactions.SignedTxn {
		txn := transactions.Transaction{
			Type: protocol.PaymentTx,
			Header: transactions.Header{
				Sender:      sender,
				Fee:         minFee,
				FirstValid:  nextRound,
				LastValid:   nextRound,
				GenesisHash: genHash,
				RekeyTo:     rekeyto,
				Note:        []byte{uniq},
			},
			PaymentTxnFields: transactions.PaymentTxnFields{
				Receiver: sender,
			},
		}
		sig := signer.Sign(txn)
		return transactions.SignedTxn{Txn: txn, Sig: sig, AuthAddr: authaddr}
	}

	tryBlock := func(stxns []transactions.SignedTxn) error {
		// We'll make a block using the evaluator.
		// When generating a block, the evaluator doesn't check transaction sigs -- it assumes the transaction pool already did that.
		// So the ValidatedBlock that comes out isn't necessarily actually a valid block. We'll call Validate ourselves.
		genesisHdr, err := l.BlockHdr(basics.Round(0))
		require.NoError(t, err)
		newBlock := bookkeeping.MakeBlock(genesisHdr)
		eval, err := l.StartEvaluator(newBlock.BlockHeader, 0, 0, nil)
		require.NoError(t, err)

		for _, stxn := range stxns {
			err = eval.Transaction(stxn, transactions.ApplyData{})
			if err != nil {
				return err
			}
		}
		unfinishedBlock, err := eval.GenerateBlock(nil)
		if err != nil {
			return err
		}
		fb := unfinishedBlock.FinishBlock(committee.Seed{0x01}, basics.Address{0x01}, false)

		backlogPool := execpool.MakeBacklog(nil, 0, execpool.LowPriority, nil)
		defer backlogPool.Shutdown()
		_, err = l.Validate(context.Background(), fb, backlogPool)
		return err
	}

	// Preamble transactions, which all of the blocks in this test will start with
	// [A -> 0][0,A] (normal transaction)
	// [A -> B][0,A] (rekey)
	txn0 := makeTxn(addrs[0], basics.Address{}, basics.Address{}, keys[0], 0) // Normal transaction
	txn1 := makeTxn(addrs[0], addrs[1], basics.Address{}, keys[0], 1)         // Rekey transaction

	// Test 1: Do only good things
	// (preamble)
	// [A -> 0][B,B] (normal transaction using new key)
	// [A -> A][B,B] (rekey back to A, transaction still signed by B)
	// [A -> 0][0,A] (normal transaction again)
	test1txns := []transactions.SignedTxn{
		txn0, txn1, // (preamble)
		makeTxn(addrs[0], basics.Address{}, addrs[1], keys[1], 2),         // [A -> 0][B,B]
		makeTxn(addrs[0], addrs[0], addrs[1], keys[1], 3),                 // [A -> A][B,B]
		makeTxn(addrs[0], basics.Address{}, basics.Address{}, keys[0], 4), // [A -> 0][0,A]
	}
	err = tryBlock(test1txns)
	require.NoError(t, err)

	// Test 2: Use old key after rekeying
	// (preamble)
	// [A -> A][0,A] (rekey back to A, but signed by A instead of B)
	test2txns := []transactions.SignedTxn{
		txn0, txn1, // (preamble)
		makeTxn(addrs[0], addrs[0], basics.Address{}, keys[0], 2), // [A -> A][0,A]
	}
	err = tryBlock(test2txns)
	require.Error(t, err)

	// TODO: More tests
}

func testEvalAppPoolingGroup(t *testing.T, schema basics.StateSchema, approvalProgram string, consensusVersion protocol.ConsensusVersion) error {
	genBalances, addrs, _ := ledgertesting.NewTestGenesis()
	cfg := config.GetDefaultLocal()
	l := newSimpleLedgerWithConsensusVersion(t, genBalances, consensusVersion, cfg)
	defer l.Close()

	eval := nextBlock(t, l)

	appcall1 := txntest.Txn{
		Sender:            addrs[0],
		Type:              protocol.ApplicationCallTx,
		GlobalStateSchema: schema,
		ApprovalProgram:   approvalProgram,
	}

	appcall2 := txntest.Txn{
		Sender:        addrs[0],
		Type:          protocol.ApplicationCallTx,
		ApplicationID: basics.AppIndex(1),
	}

	appcall3 := txntest.Txn{
		Sender:        addrs[1],
		Type:          protocol.ApplicationCallTx,
		ApplicationID: basics.AppIndex(1),
	}

	return txgroup(t, l, eval, &appcall1, &appcall2, &appcall3)
}

// TestEvalAppPooledBudgetWithTxnGroup ensures 3 app call txns can successfully pool
// budgets in a group txn and return an error if the budget is exceeded
func TestEvalAppPooledBudgetWithTxnGroup(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	source := func(n int, m int) string {
		return "#pragma version 4\nbyte 0x1337BEEF\n" + strings.Repeat("keccak256\n", n) +
			strings.Repeat("substring 0 4\n", m) + "pop\nint 1\n"
	}

	params := []protocol.ConsensusVersion{
		protocol.ConsensusV29,
		protocol.ConsensusFuture,
	}

	cases := []struct {
		prog                 string
		isSuccessV29         bool
		isSuccessVFuture     bool
		expectedErrorV29     string
		expectedErrorVFuture string
	}{
		{source(5, 47), true, true,
			"",
			""},
		{source(5, 48), false, true,
			"pc=157 dynamic cost budget exceeded, executing pushint",
			""},
		{source(16, 17), false, true,
			"pc= 12 dynamic cost budget exceeded, executing keccak256",
			""},
		{source(16, 18), false, false,
			"pc= 12 dynamic cost budget exceeded, executing keccak256",
			"pc= 78 dynamic cost budget exceeded, executing pushint"},
	}

	for i, param := range params {
		for j, testCase := range cases {
			t.Run(fmt.Sprintf("i=%d,j=%d", i, j), func(t *testing.T) {
				err := testEvalAppPoolingGroup(t, basics.StateSchema{NumByteSlice: 3}, testCase.prog, param)
				if !testCase.isSuccessV29 && reflect.DeepEqual(param, protocol.ConsensusV29) {
					require.Error(t, err)
					require.Contains(t, err.Error(), testCase.expectedErrorV29)
				} else if !testCase.isSuccessVFuture && reflect.DeepEqual(param, protocol.ConsensusFuture) {
					require.Error(t, err)
					require.Contains(t, err.Error(), testCase.expectedErrorVFuture)
				}
			})
		}
	}
}

func TestMinBalanceChanges(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	genBalances, addrs, _ := ledgertesting.NewTestGenesis()
	cfg := config.GetDefaultLocal()
	l := newSimpleLedgerWithConsensusVersion(t, genBalances, protocol.ConsensusCurrentVersion, cfg)
	defer l.Close()

	createTxn := txntest.Txn{
		Type:   "acfg",
		Sender: addrs[0],
		AssetParams: basics.AssetParams{
			Total:    3,
			Manager:  addrs[1],
			Reserve:  addrs[2],
			Freeze:   addrs[3],
			Clawback: addrs[4],
		},
	}

	const expectedID basics.AssetIndex = 1001
	optInTxn := txntest.Txn{
		Type:          "axfer",
		Sender:        addrs[5],
		XferAsset:     expectedID,
		AssetReceiver: addrs[5],
	}

	ad0init, _, _, err := l.LookupLatest(addrs[0])
	require.NoError(t, err)
	ad5init, _, _, err := l.LookupLatest(addrs[5])
	require.NoError(t, err)

	eval := nextBlock(t, l)
	txns(t, l, eval, &createTxn, &optInTxn)
	endBlock(t, l, eval)

	ad0new, _, _, err := l.LookupLatest(addrs[0])
	require.NoError(t, err)
	ad5new, _, _, err := l.LookupLatest(addrs[5])
	require.NoError(t, err)

	proto := l.GenesisProto()
	// Check balance and min balance requirement changes
	require.Equal(t, ad0init.MicroAlgos.Raw, ad0new.MicroAlgos.Raw+1000) // fee
	reqs := proto.BalanceRequirements()
	require.Equal(t, ad0init.MinBalance(reqs).Raw, ad0new.MinBalance(reqs).Raw-100000) // create
	require.Equal(t, ad5init.MicroAlgos.Raw, ad5new.MicroAlgos.Raw+1000)               // fee
	require.Equal(t, ad5init.MinBalance(reqs).Raw, ad5new.MinBalance(reqs).Raw-100000) // optin

	optOutTxn := txntest.Txn{
		Type:          "axfer",
		Sender:        addrs[5],
		XferAsset:     expectedID,
		AssetReceiver: addrs[0],
		AssetCloseTo:  addrs[0],
	}

	closeTxn := txntest.Txn{
		Type:        "acfg",
		Sender:      addrs[1], // The manager, not the creator
		ConfigAsset: expectedID,
	}

	eval = nextBlock(t, l)
	txns(t, l, eval, &optOutTxn, &closeTxn)
	endBlock(t, l, eval)

	ad0final, _, _, err := l.LookupLatest(addrs[0])
	require.NoError(t, err)
	ad5final, _, _, err := l.LookupLatest(addrs[5])
	require.NoError(t, err)
	// Check we got our balance "back"
	require.Equal(t, ad0final.MinBalance(reqs), ad0init.MinBalance(reqs))
	require.Equal(t, ad5final.MinBalance(reqs), ad5init.MinBalance(reqs))
}

// TestAppInsMinBalance checks that accounts with MaxAppsOptedIn are accepted by block evaluator
// and do not cause any MaximumMinimumBalance problems
func TestAppInsMinBalance(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	genBalances, addrs, _ := ledgertesting.NewTestGenesis()
	cfg := config.GetDefaultLocal()
	l := newSimpleLedgerWithConsensusVersion(t, genBalances, protocol.ConsensusV30, cfg)
	defer l.Close()

	const appID basics.AppIndex = 1

	maxAppsOptedIn := config.Consensus[protocol.ConsensusV30].MaxAppsOptedIn
	require.Greater(t, maxAppsOptedIn, 0)
	maxAppsCreated := config.Consensus[protocol.ConsensusV30].MaxAppsCreated
	require.Greater(t, maxAppsCreated, 0)
	maxLocalSchemaEntries := config.Consensus[protocol.ConsensusV30].MaxLocalSchemaEntries
	require.Greater(t, maxLocalSchemaEntries, uint64(0))

	txnsCreate := make([]*txntest.Txn, 0, maxAppsOptedIn)
	txnsOptIn := make([]*txntest.Txn, 0, maxAppsOptedIn)
	appsCreated := make(map[basics.Address]int, len(addrs)-1)

	acctIdx := 0
	for i := 0; i < maxAppsOptedIn; i++ {
		creator := addrs[acctIdx]
		createTxn := txntest.Txn{
			Type:             protocol.ApplicationCallTx,
			Sender:           creator,
			ApprovalProgram:  "int 1",
			LocalStateSchema: basics.StateSchema{NumByteSlice: maxLocalSchemaEntries},
			Note:             ledgertesting.RandomNote(),
		}
		txnsCreate = append(txnsCreate, &createTxn)
		count := appsCreated[creator]
		count++
		appsCreated[creator] = count
		if count == maxAppsCreated {
			acctIdx++
		}

		optInTxn := txntest.Txn{
			Type:          protocol.ApplicationCallTx,
			Sender:        addrs[9],
			ApplicationID: appID + basics.AppIndex(i),
			OnCompletion:  transactions.OptInOC,
		}
		txnsOptIn = append(txnsOptIn, &optInTxn)
	}

	eval := nextBlock(t, l)
	txns1 := append(txnsCreate, txnsOptIn...)
	txns(t, l, eval, txns1...)
	vb := endBlock(t, l, eval)
	mods := vb.Delta()
	appAppResources := mods.Accts.GetAllAppResources()
	appParamsCount := 0
	appLocalStatesCount := 0
	for _, ap := range appAppResources {
		if ap.Params.Params != nil {
			appParamsCount++
		}
		if ap.State.LocalState != nil {
			appLocalStatesCount++
		}
	}
	require.Equal(t, appLocalStatesCount, 50)
	require.Equal(t, appParamsCount, 50)
}
