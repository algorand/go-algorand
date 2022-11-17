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

package ledger

import (
	"fmt"
	"strings"
	"testing"

	"github.com/algorand/go-algorand/agreement"
	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/bookkeeping"
	"github.com/algorand/go-algorand/data/transactions"
	"github.com/algorand/go-algorand/data/txntest"
	"github.com/algorand/go-algorand/ledger/internal"
	"github.com/algorand/go-algorand/ledger/ledgercore"
	"github.com/algorand/go-algorand/logging"
	"github.com/algorand/go-algorand/protocol"
	"github.com/stretchr/testify/require"
)

func newSimpleLedger(t testing.TB, balances bookkeeping.GenesisBalances) *Ledger {
	return newSimpleLedgerWithConsensusVersion(t, balances, protocol.ConsensusFuture)
}

func newSimpleLedgerWithConsensusVersion(t testing.TB, balances bookkeeping.GenesisBalances, cv protocol.ConsensusVersion) *Ledger {
	var genHash crypto.Digest
	crypto.RandBytes(genHash[:])
	return newSimpleLedgerFull(t, balances, cv, genHash)
}

func newSimpleLedgerFull(t testing.TB, balances bookkeeping.GenesisBalances, cv protocol.ConsensusVersion, genHash crypto.Digest) *Ledger {
	genBlock, err := bookkeeping.MakeGenesisBlock(cv, balances, "test", genHash)
	require.NoError(t, err)
	require.False(t, genBlock.FeeSink.IsZero())
	require.False(t, genBlock.RewardsPool.IsZero())
	dbName := fmt.Sprintf("%s.%d", t.Name(), crypto.RandUint64())
	cfg := config.GetDefaultLocal()
	cfg.Archival = true
	l, err := OpenLedger(logging.Base(), dbName, true, ledgercore.InitState{
		Block:       genBlock,
		Accounts:    balances.Balances,
		GenesisHash: genHash,
	}, cfg)
	require.NoError(t, err)
	return l
}

// nextBlock begins evaluation of a new block, after ledger creation or endBlock()
func nextBlock(t testing.TB, ledger *Ledger) *internal.BlockEvaluator {
	rnd := ledger.Latest()
	hdr, err := ledger.BlockHdr(rnd)
	require.NoError(t, err)

	nextHdr := bookkeeping.MakeBlock(hdr).BlockHeader
	nextHdr.TimeStamp = hdr.TimeStamp + 1 // ensure deterministic tests
	eval, err := internal.StartEvaluator(ledger, nextHdr, internal.EvaluatorOptions{
		Generate: true,
		Validate: true, // Do the complete checks that a new txn would be subject to
	})
	require.NoError(t, err)
	return eval
}

func fillDefaults(t testing.TB, ledger *Ledger, eval *internal.BlockEvaluator, txn *txntest.Txn) {
	if txn.GenesisHash.IsZero() && ledger.GenesisProto().SupportGenesisHash {
		txn.GenesisHash = ledger.GenesisHash()
	}
	if txn.FirstValid == 0 {
		txn.FirstValid = eval.Round()
	}

	txn.FillDefaults(ledger.GenesisProto())
}

func txns(t testing.TB, ledger *Ledger, eval *internal.BlockEvaluator, txns ...*txntest.Txn) {
	t.Helper()
	for _, txn1 := range txns {
		txn(t, ledger, eval, txn1)
	}
}

func txn(t testing.TB, ledger *Ledger, eval *internal.BlockEvaluator, txn *txntest.Txn, problem ...string) {
	t.Helper()
	fillDefaults(t, ledger, eval, txn)
	err := eval.Transaction(txn.SignedTxn(), transactions.ApplyData{})
	if err != nil {
		if len(problem) == 1 && problem[0] != "" {
			require.Contains(t, err.Error(), problem[0])
		} else {
			require.NoError(t, err) // Will obviously fail
		}
		return
	}
	require.True(t, len(problem) == 0 || problem[0] == "")
}

func txgroup(t testing.TB, ledger *Ledger, eval *internal.BlockEvaluator, txns ...*txntest.Txn) error {
	t.Helper()
	for _, txn := range txns {
		fillDefaults(t, ledger, eval, txn)
	}
	txgroup := txntest.SignedTxns(txns...)

	return eval.TransactionGroup(transactions.WrapSignedTxnsWithAD(txgroup))
}

// endBlock completes the block being created, returns the ValidatedBlock for inspection
func endBlock(t testing.TB, ledger *Ledger, eval *internal.BlockEvaluator) *ledgercore.ValidatedBlock {
	validatedBlock, err := eval.GenerateBlock()
	require.NoError(t, err)
	err = ledger.AddValidatedBlock(*validatedBlock, agreement.Certificate{})
	require.NoError(t, err)
	// `rndBQ` gives the latest known block round added to the ledger
	// we should wait until `rndBQ` block to be committed to blockQueue,
	// in case there is a data race, noted in
	// https://github.com/algorand/go-algorand/issues/4349
	// where writing to `callTxnGroup` after `dl.fullBlock` caused data race,
	// because the underlying async goroutine `go bq.syncer()` is reading `callTxnGroup`.
	// A solution here would be wait until all new added blocks are committed,
	// then we return the result and continue the execution.
	rndBQ := ledger.Latest()
	ledger.WaitForCommit(rndBQ)
	return validatedBlock
}

// main wraps up some TEAL source in a header and footer so that it is
// an app that does nothing at create time, but otherwise runs source,
// then approves, if the source avoids panicing and leaves the stack
// empty.
func main(source string) string {
	return strings.Replace(fmt.Sprintf(`txn ApplicationID
		bz end
		%s
end:	int 1`, source), ";", "\n", -1)
}

// lookup gets the current accountdata for an address
func lookup(t testing.TB, ledger *Ledger, addr basics.Address) basics.AccountData {
	ad, _, _, err := ledger.LookupLatest(addr)
	require.NoError(t, err)
	return ad
}

// micros gets the current microAlgo balance for an address
func micros(t testing.TB, ledger *Ledger, addr basics.Address) uint64 {
	return lookup(t, ledger, addr).MicroAlgos.Raw
}

// holding gets the current balance and optin status for some asa for an address
func holding(t testing.TB, ledger *Ledger, addr basics.Address, asset basics.AssetIndex) (uint64, bool) {
	if holding, ok := lookup(t, ledger, addr).Assets[asset]; ok {
		return holding.Amount, true
	}
	return 0, false
}

// asaParams gets the asset params for a given asa index
func asaParams(t testing.TB, ledger *Ledger, asset basics.AssetIndex) (basics.AssetParams, error) {
	creator, ok, err := ledger.GetCreator(basics.CreatableIndex(asset), basics.AssetCreatable)
	if err != nil {
		return basics.AssetParams{}, err
	}
	if !ok {
		return basics.AssetParams{}, fmt.Errorf("no asset (%d)", asset)
	}
	if params, ok := lookup(t, ledger, creator).AssetParams[asset]; ok {
		return params, nil
	}
	return basics.AssetParams{}, fmt.Errorf("bad lookup (%d)", asset)
}
