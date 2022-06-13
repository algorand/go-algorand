// Copyright (C) 2019-2022 Algorand, Inc.
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

package internal_test

import (
	"testing"

	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/bookkeeping"
	"github.com/algorand/go-algorand/data/transactions"
	"github.com/algorand/go-algorand/data/txntest"
	"github.com/algorand/go-algorand/ledger"
	"github.com/algorand/go-algorand/ledger/internal"
	"github.com/algorand/go-algorand/ledger/ledgercore"
	"github.com/algorand/go-algorand/protocol"
	"github.com/stretchr/testify/require"
)

// DoubleLedger allows for easy "Double Entry bookkeeping" as a way to write
// fairly extensive ledger tests. In addition to simplifying the addition of
// txns and txgroups to a ledger (and then allowing for inspection of the
// created blocks), it also does a double check on correctness by marshalling
// the created blocks, evaluating the transactions in a ledger copy, and
// asserting that it comes out the same.  During the insertion of those
// transactions, the validator ledger is not in `generate` mode - so it
// evaluates and validates, checking that the ApplyDatas that come from the
// first ledger match the ADs created by the second. The validator ledger is
// then temporarily placed in `generate` mode so that the entire block can be
// generated in the copy second ledger, and compared.
type DoubleLedger struct {
	t *testing.T

	generator *ledger.Ledger
	validator *ledger.Ledger

	eval *internal.BlockEvaluator
}

func (dl DoubleLedger) Close() {
	dl.generator.Close()
	dl.validator.Close()
}

// NewDoubleLedger creates a new DoubleLedger with the supplied balances and consensus version.
func NewDoubleLedger(t *testing.T, balances bookkeeping.GenesisBalances, cv protocol.ConsensusVersion) DoubleLedger {
	g := newTestLedgerWithConsensusVersion(t, balances, cv)
	v := newTestLedgerFull(t, balances, cv, g.GenesisHash())
	return DoubleLedger{t, g, v, nil}
}

func (dl *DoubleLedger) beginBlock() *internal.BlockEvaluator {
	dl.eval = nextBlock(dl.t, dl.generator)
	return dl.eval
}

func (dl *DoubleLedger) txn(tx *txntest.Txn, problem ...string) {
	dl.t.Helper()
	if dl.eval == nil {
		dl.beginBlock()
		defer dl.endBlock()
	}
	txn(dl.t, dl.generator, dl.eval, tx, problem...)
}

func (dl *DoubleLedger) txns(txns ...*txntest.Txn) {
	dl.t.Helper()
	if dl.eval == nil {
		dl.beginBlock()
		defer dl.endBlock()
	}
	for _, tx := range txns {
		dl.txn(tx)
	}
}

func (dl *DoubleLedger) txgroup(problem string, txns ...*txntest.Txn) {
	dl.t.Helper()
	if dl.eval == nil {
		dl.beginBlock()
		defer dl.endBlock()
	}
	err := txgroup(dl.t, dl.generator, dl.eval, txns...)
	if problem == "" {
		require.NoError(dl.t, err)
	} else {
		require.Error(dl.t, err)
		require.Contains(dl.t, err.Error(), problem)
	}
}

func (dl *DoubleLedger) fullBlock(txs ...*txntest.Txn) *ledgercore.ValidatedBlock {
	dl.t.Helper()
	dl.beginBlock()
	dl.txns(txs...)
	return dl.endBlock()
}

func (dl *DoubleLedger) endBlock() *ledgercore.ValidatedBlock {
	vb := endBlock(dl.t, dl.generator, dl.eval)
	if dl.validator != nil { // Allows setting to nil while debugging, to simplify
		checkBlock(dl.t, dl.validator, vb)
	}
	dl.eval = nil // Ensure it's not used again
	return vb
}

func (dl *DoubleLedger) fundedApp(sender basics.Address, amount uint64, source string) basics.AppIndex {
	createapp := txntest.Txn{
		Type:            "appl",
		Sender:          sender,
		ApprovalProgram: source,
	}
	vb := dl.fullBlock(&createapp)
	appIndex := vb.Block().Payset[0].ApplyData.ApplicationID

	fund := txntest.Txn{
		Type:     "pay",
		Sender:   sender,
		Receiver: appIndex.Address(),
		Amount:   amount,
	}

	dl.txn(&fund)
	return appIndex
}

func checkBlock(t *testing.T, checkLedger *ledger.Ledger, vb *ledgercore.ValidatedBlock) {
	bl := vb.Block()
	msg := bl.MarshalMsg(nil)
	var reconstituted bookkeeping.Block
	_, err := reconstituted.UnmarshalMsg(msg)
	require.NoError(t, err)

	check := nextCheckBlock(t, checkLedger, reconstituted.RewardsState)
	var group []transactions.SignedTxnWithAD
	for _, stib := range reconstituted.Payset {
		stxn, ad, err := reconstituted.BlockHeader.DecodeSignedTxn(stib)
		require.NoError(t, err)
		stad := transactions.SignedTxnWithAD{SignedTxn: stxn, ApplyData: ad}
		// If txn we're looking at belongs in the current group, append
		if group == nil || (!stxn.Txn.Group.IsZero() && group[0].Txn.Group == stxn.Txn.Group) {
			group = append(group, stad)
		} else if group != nil {
			err := check.TransactionGroup(group)
			require.NoError(t, err)
			group = []transactions.SignedTxnWithAD{stad}
		}
	}
	if group != nil {
		err := check.TransactionGroup(group)
		require.NoError(t, err, "%+v", reconstituted.Payset)
	}
	check.SetGenerate(true)
	cb := endBlock(t, checkLedger, check)
	check.SetGenerate(false)
	require.Equal(t, vb.Block(), cb.Block())

	// vb.Delta() need not actually be Equal, in the sense of require.Equal
	// because the order of the records in Accts is determined by the way the
	// cb.sdeltas map (and then the maps in there) is iterated when the
	// StateDelta is constructed by roundCowState.deltas().  They should be
	// semantically equivalent, but those fields are not exported, so checking
	// equivalence is hard.  If vb.Delta() is, in fact, different, even though
	// vb.Block() is the same, then there is something seriously broken going
	// on, that is unlikely to have anything to do with these tests.  So upshot:
	// we skip trying a complicated equality check.

	// This is the part of checking Delta() equality that wouldn't work right.
	// require.Equal(t, vb.Delta().Accts, cb.Delta().Accts)
}

func nextCheckBlock(t testing.TB, ledger *ledger.Ledger, rs bookkeeping.RewardsState) *internal.BlockEvaluator {
	rnd := ledger.Latest()
	hdr, err := ledger.BlockHdr(rnd)
	require.NoError(t, err)

	nextHdr := bookkeeping.MakeBlock(hdr).BlockHeader
	nextHdr.RewardsState = rs
	// follow nextBlock, which does this for determinism
	nextHdr.TimeStamp = hdr.TimeStamp + 1
	eval, err := internal.StartEvaluator(ledger, nextHdr, internal.EvaluatorOptions{
		Generate: false,
		Validate: true, // Do the complete checks that a new txn would be subject to
	})
	require.NoError(t, err)
	return eval
}
