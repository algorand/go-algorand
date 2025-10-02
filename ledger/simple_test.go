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
	"fmt"
	"path/filepath"
	"strings"
	"testing"

	"github.com/algorand/go-algorand/agreement"
	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/bookkeeping"
	"github.com/algorand/go-algorand/data/committee"
	"github.com/algorand/go-algorand/data/transactions"
	"github.com/algorand/go-algorand/data/transactions/logic"
	"github.com/algorand/go-algorand/data/transactions/verify"
	"github.com/algorand/go-algorand/data/txntest"
	"github.com/algorand/go-algorand/ledger/eval"
	"github.com/algorand/go-algorand/ledger/ledgercore"
	"github.com/algorand/go-algorand/logging"
	"github.com/algorand/go-algorand/protocol"
	"github.com/stretchr/testify/require"
)

type simpleLedgerCfg struct {
	onDisk      bool // default is in-memory
	notArchival bool // default is archival
	logger      logging.Logger
}

type simpleLedgerOption func(*simpleLedgerCfg)

func simpleLedgerOnDisk() simpleLedgerOption {
	return func(cfg *simpleLedgerCfg) { cfg.onDisk = true }
}

func simpleLedgerNotArchival() simpleLedgerOption {
	return func(cfg *simpleLedgerCfg) { cfg.notArchival = true }
}

func simpleLedgerLogger(l logging.Logger) simpleLedgerOption {
	return func(cfg *simpleLedgerCfg) { cfg.logger = l }
}

func newSimpleLedgerWithConsensusVersion(t testing.TB, balances bookkeeping.GenesisBalances, cv protocol.ConsensusVersion, cfg config.Local, opts ...simpleLedgerOption) *Ledger {
	var genHash crypto.Digest
	crypto.RandBytes(genHash[:])
	return newSimpleLedgerFull(t, balances, cv, genHash, cfg, opts...)
}

func newSimpleLedgerFull(t testing.TB, balances bookkeeping.GenesisBalances, cv protocol.ConsensusVersion, genHash crypto.Digest, cfg config.Local, opts ...simpleLedgerOption) *Ledger {
	var slCfg simpleLedgerCfg
	for _, opt := range opts {
		opt(&slCfg)
	}
	genBlock, err := bookkeeping.MakeGenesisBlock(cv, balances, "test", genHash)
	require.NoError(t, err)
	require.False(t, genBlock.FeeSink.IsZero())
	require.False(t, genBlock.RewardsPool.IsZero())
	tempDir := t.TempDir()
	dbName := fmt.Sprintf("%s.%d", t.Name(), crypto.RandUint64())
	dbName = strings.Replace(dbName, "/", "_", -1)
	dbName = filepath.Join(tempDir, dbName)
	cfg.Archival = !slCfg.notArchival
	log := slCfg.logger
	if log == nil {
		log = logging.Base()
	}
	l, err := OpenLedger(log, dbName, !slCfg.onDisk, ledgercore.InitState{
		Block:       genBlock,
		Accounts:    balances.Balances,
		GenesisHash: genHash,
	}, cfg)
	require.NoError(t, err)
	return l
}

// nextBlock begins evaluation of a new block, after ledger creation or endBlock()
func nextBlock(t testing.TB, ledger *Ledger) *eval.BlockEvaluator {
	rnd := ledger.Latest()
	hdr, err := ledger.BlockHdr(rnd)
	require.NoError(t, err)

	nextHdr := bookkeeping.MakeBlock(hdr).BlockHeader
	nextHdr.TimeStamp = hdr.TimeStamp + 1 // ensure deterministic tests
	eval, err := eval.StartEvaluator(ledger, nextHdr, eval.EvaluatorOptions{
		Generate: true,
		Validate: true, // Do the complete checks that a new txn would be subject to
		Tracer:   logic.EvalErrorDetailsTracer{},
	})
	require.NoError(t, err)
	return eval
}

func fillDefaults(t testing.TB, ledger *Ledger, eval *eval.BlockEvaluator, txn *txntest.Txn) {
	if txn.GenesisHash.IsZero() && ledger.GenesisProto().SupportGenesisHash {
		txn.GenesisHash = ledger.GenesisHash()
	}
	if txn.FirstValid == 0 {
		txn.FirstValid = eval.Round()
	}
	if txn.Type == protocol.KeyRegistrationTx && txn.VoteFirst == 0 &&
		// check this is not an offline txn
		(!txn.VotePK.IsEmpty() || !txn.SelectionPK.IsEmpty()) {
		txn.VoteFirst = eval.Round()
	}

	txn.FillDefaults(ledger.GenesisProto())
}

func txns(t testing.TB, ledger *Ledger, eval *eval.BlockEvaluator, txns ...*txntest.Txn) {
	t.Helper()
	for _, txn1 := range txns {
		txn(t, ledger, eval, txn1)
	}
}

func txn(t testing.TB, ledger *Ledger, eval *eval.BlockEvaluator, txn *txntest.Txn, problem ...string) {
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
	require.True(t, len(problem) == 0 || problem[0] == "", "Transaction did not fail. Expected: %v", problem)
}

func txgroup(t testing.TB, ledger *Ledger, eval *eval.BlockEvaluator, txns ...*txntest.Txn) error {
	t.Helper()
	for _, txn := range txns {
		fillDefaults(t, ledger, eval, txn)
	}
	txgroup := txntest.Group(txns...)

	return eval.TransactionGroup(transactions.WrapSignedTxnsWithAD(txgroup))
}

// endBlock completes the block being created, returning the ValidatedBlock for
// inspection. Proposer is optional - if unset, blocks will be finished with
// ZeroAddress proposer.
func endBlock(t testing.TB, ledger *Ledger, eval *eval.BlockEvaluator, proposer ...basics.Address) *ledgercore.ValidatedBlock {
	// pass proposers to GenerateBlock, if provided
	ub, err := eval.GenerateBlock(proposer)
	require.NoError(t, err)

	// We fake some things that agreement would do, like setting proposer
	validatedBlock := ledgercore.MakeValidatedBlock(ub.UnfinishedBlock(), ub.UnfinishedDeltas())
	gvb := &validatedBlock

	// Making the proposer the feesink unless specified causes less disruption
	// to existing tests. (Because block payouts don't change balances.)
	prp := gvb.Block().BlockHeader.FeeSink
	if len(proposer) > 0 {
		prp = proposer[0]
	}

	// Since we can't do agreement, we have this backdoor way to install a
	// proposer or seed into the header for tests. Doesn't matter that it makes
	// them both the same.  Since this can't call the agreement code, the
	// eligibility of the prp is not considered.
	if ledger.GenesisProto().Payouts.Enabled {
		*gvb = ledgercore.MakeValidatedBlock(gvb.Block().WithProposer(committee.Seed(prp), prp, true), gvb.Delta())
	} else {
		// To more closely mimic the agreement code, we don't
		// write the proposer when !Payouts.Enabled.
		*gvb = ledgercore.MakeValidatedBlock(gvb.Block().WithProposer(committee.Seed(prp), basics.Address{}, false), gvb.Delta())
	}

	vvb, err := validateWithoutSignatures(t, ledger, gvb.Block())
	require.NoError(t, err)

	// we could add some checks that ensure gvb and vvb are quite similar, but
	// they will differ a bit, as noted above.

	err = ledger.AddValidatedBlock(*vvb, agreement.Certificate{})
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
	return vvb
}

func validateWithoutSignatures(t testing.TB, ledger *Ledger, blk bookkeeping.Block) (*ledgercore.ValidatedBlock, error) {
	save := ledger.verifiedTxnCache
	defer func() { ledger.verifiedTxnCache = save }()
	ledger.verifiedTxnCache = verify.GetMockedCache(true) // validate the txns, but not signatures
	return ledger.Validate(context.Background(), blk, nil)
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

// globals gets the AppParams for an address, app index pair (only works if addr is the creator)
func globals(t testing.TB, ledger *Ledger, addr basics.Address, app basics.AppIndex) (basics.AppParams, bool) {
	if globals, ok := lookup(t, ledger, addr).AppParams[app]; ok {
		return globals, true
	}
	return basics.AppParams{}, false
}

// locals gets the AppLocalState for an address, app index pair
func locals(t testing.TB, ledger *Ledger, addr basics.Address, app basics.AppIndex) (basics.AppLocalState, bool) {
	if locals, ok := lookup(t, ledger, addr).AppLocalStates[app]; ok {
		return locals, true
	}
	return basics.AppLocalState{}, false
}
