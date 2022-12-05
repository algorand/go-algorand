package ledger

import (
	"context"
	"database/sql"
	"sync"

	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/bookkeeping"
	"github.com/algorand/go-algorand/ledger/ledgercore"
	"github.com/algorand/go-deadlock"
)

type stateProofExtractor struct {
	mu            deadlock.Mutex
	cond          *sync.Cond
	listeners     []BlockListener
	pendingBlocks []blockDeltaPair
	running       bool
	// closing is the waitgroup used to synchronize closing the worker goroutine. It's being increased during loadFromDisk, and the worker is responsible to call Done on it once it's aborting it's goroutine. The close function waits on this to complete.
	closing sync.WaitGroup
}

func (spe *stateProofExtractor) loadFromDisk(ledgerForTracker, basics.Round) error {
	return nil
}

func (spe *stateProofExtractor) newBlock(bookkeeping.Block, ledgercore.StateDelta) {
}

func (spe *stateProofExtractor) committedUpTo(rnd basics.Round) (_, _ basics.Round) {
	return rnd, basics.Round(0)
}

func (spe *stateProofExtractor) produceCommittingTask(_ basics.Round, _ basics.Round, dcr *deferredCommitRange) *deferredCommitRange {
	return dcr
}

func (spe *stateProofExtractor) prepareCommit(dcc *deferredCommitContext) error {
	return nil
}

func (spe *stateProofExtractor) commitRound(context.Context, *sql.Tx, *deferredCommitContext) error {
	return nil
}

func (spe *stateProofExtractor) postCommit(context.Context, *deferredCommitContext) {
}

func (spe *stateProofExtractor) postCommitUnlocked(context.Context, *deferredCommitContext) {
}

func (spe *stateProofExtractor) handleUnorderedCommit(*deferredCommitContext) {
}

func (spe *stateProofExtractor) close() {
}
