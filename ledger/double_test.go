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
	"testing"

	"github.com/algorand/go-algorand/agreement"
	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/bookkeeping"
	"github.com/algorand/go-algorand/data/transactions"
	"github.com/algorand/go-algorand/data/txntest"
	"github.com/algorand/go-algorand/ledger/eval"
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
	t testing.TB

	generator *Ledger
	validator *Ledger

	eval *eval.BlockEvaluator

	// proposer is the default proposer unless one is supplied to endBlock.
	proposer basics.Address
}

func (dl DoubleLedger) Close() {
	dl.generator.Close()
	dl.validator.Close()
}

// NewDoubleLedger creates a new DoubleLedger with the supplied balances and consensus version.
func NewDoubleLedger(t testing.TB, balances bookkeeping.GenesisBalances, cv protocol.ConsensusVersion, cfg config.Local, opts ...simpleLedgerOption) DoubleLedger {
	g := newSimpleLedgerWithConsensusVersion(t, balances, cv, cfg, opts...)
	v := newSimpleLedgerFull(t, balances, cv, g.GenesisHash(), cfg, opts...)
	// FeeSink as proposer will make old tests work as expected, because payouts will stay put.
	return DoubleLedger{t, g, v, nil, balances.FeeSink}
}

func (dl *DoubleLedger) beginBlock() *eval.BlockEvaluator {
	dl.eval = nextBlock(dl.t, dl.generator)
	return dl.eval
}

// txn will add a transaction to the current block. If no block is
// currently being built, it will start one, and end it after the
// transaction is added. If a problem is specified, it will be
// expected to fail, and the block will not be ended.
func (dl *DoubleLedger) txn(tx *txntest.Txn, problem ...string) (stib *transactions.SignedTxnInBlock) {
	dl.t.Helper()
	if dl.eval == nil {
		dl.beginBlock()
		defer func() {
			// only advance if the txn was supposed to succeed
			if len(problem) > 0 {
				dl.eval = nil
			} else {
				vb := dl.endBlock()
				// It should have a stib, but don't panic here because of an earlier problem.
				if len(vb.Block().Payset) > 0 {
					stib = &vb.Block().Payset[0]
				}
			}
		}()
	}
	txn(dl.t, dl.generator, dl.eval, tx, problem...)
	return nil
}

func (dl *DoubleLedger) txns(txns ...*txntest.Txn) (payset []transactions.SignedTxnInBlock) {
	dl.t.Helper()
	if dl.eval == nil {
		dl.beginBlock()
		defer func() {
			vb := dl.endBlock()
			payset = vb.Block().Payset
		}()
	}
	for _, tx := range txns {
		dl.txn(tx)
	}
	return nil
}

func (dl *DoubleLedger) txgroup(problem string, txns ...*txntest.Txn) (payset []transactions.SignedTxnInBlock) {
	dl.t.Helper()
	if dl.eval == nil {
		dl.beginBlock()
		defer func() {
			// only advance if the txgroup was supposed to succeed
			if problem != "" {
				dl.eval = nil
			} else {
				vb := dl.endBlock()
				payset = vb.Block().Payset
			}
		}()
	}
	err := txgroup(dl.t, dl.generator, dl.eval, txns...)
	if problem == "" {
		require.NoError(dl.t, err)
	} else {
		require.Error(dl.t, err)
		require.Contains(dl.t, err.Error(), problem)
	}
	return nil
}

func (dl *DoubleLedger) fullBlock(txs ...*txntest.Txn) *ledgercore.ValidatedBlock {
	dl.t.Helper()
	dl.beginBlock()
	dl.txns(txs...)
	return dl.endBlock()
}

func (dl *DoubleLedger) endBlock(proposer ...basics.Address) *ledgercore.ValidatedBlock {
	prp := dl.proposer
	if len(proposer) > 0 {
		require.Len(dl.t, proposer, 1, "endBlock() cannot specify multiple proposers")
		prp = proposer[0]
	}
	vb := endBlock(dl.t, dl.generator, dl.eval, prp)
	if dl.validator != nil { // Allows setting to nil while debugging, to simplify
		checkBlock(dl.t, dl.validator, vb)
	}
	dl.eval = nil // Ensure it's not used again
	return vb
}

func (dl *DoubleLedger) createApp(sender basics.Address, source string, schemas ...basics.StateSchema) basics.AppIndex {
	createapp := txntest.Txn{
		Type:            "appl",
		Sender:          sender,
		ApprovalProgram: source,
	}
	switch len(schemas) {
	case 0:
	case 1:
		createapp.GlobalStateSchema = schemas[0]
	case 2:
		createapp.GlobalStateSchema = schemas[0]
		createapp.LocalStateSchema = schemas[1]
	}
	vb := dl.fullBlock(&createapp)
	return basics.AppIndex(vb.Block().BlockHeader.TxnCounter)
	// The following only works for v30 and above, when we start recording the id in AD.
	// return vb.Block().Payset[0].ApplyData.ApplicationID
}

func (dl *DoubleLedger) fundedApp(sender basics.Address, amount uint64, source string) basics.AppIndex {
	appIndex := dl.createApp(sender, source)
	dl.fullBlock(&txntest.Txn{
		Type:     "pay",
		Sender:   sender,
		Receiver: appIndex.Address(),
		Amount:   amount,
	})
	return appIndex
}

func (dl *DoubleLedger) reloadLedgers() {
	require.NoError(dl.t, dl.generator.reloadLedger())
	require.NoError(dl.t, dl.validator.reloadLedger())
}

func checkBlock(t testing.TB, checkLedger *Ledger, gvb *ledgercore.ValidatedBlock) {
	bl := gvb.Block()
	msg := bl.MarshalMsg(nil)
	var reconstituted bookkeeping.Block
	_, err := reconstituted.UnmarshalMsg(msg)
	require.NoError(t, err)

	cvb, err := validateWithoutSignatures(t, checkLedger, reconstituted)
	require.NoError(t, err)
	cvbd := cvb.Delta()
	cvbd.Dehydrate()
	gvbd := gvb.Delta()
	gvbd.Dehydrate()

	// There are some things in the deltas that won't be identical. Erase them.
	// Hdr was put in here at _start_ of block, and not updated. So gvb is in
	// initial state, cvd got to see the whole thing.
	gvbd.Hdr = nil
	cvbd.Hdr = nil

	require.Equal(t, gvbd, cvbd)

	// Hydration/Dehydration is done in-place, so rehydrate so to avoid external evidence
	cvbd.Hydrate()
	gvbd.Hydrate()

	err = checkLedger.AddValidatedBlock(*cvb, agreement.Certificate{})
	require.NoError(t, err)
}

func nextCheckBlock(t testing.TB, ledger *Ledger, rs bookkeeping.RewardsState) *eval.BlockEvaluator {
	rnd := ledger.Latest()
	hdr, err := ledger.BlockHdr(rnd)
	require.NoError(t, err)

	nextHdr := bookkeeping.MakeBlock(hdr).BlockHeader
	nextHdr.RewardsState = rs
	// follow nextBlock, which does this for determinism
	nextHdr.TimeStamp = hdr.TimeStamp + 1
	eval, err := eval.StartEvaluator(ledger, nextHdr, eval.EvaluatorOptions{
		Generate: false,
		Validate: true, // Do the complete checks that a new txn would be subject to
	})
	require.NoError(t, err)
	return eval
}
