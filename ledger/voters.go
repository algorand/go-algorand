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

package ledger

import (
	"fmt"
	"sync"

	"github.com/algorand/go-deadlock"

	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/bookkeeping"
	"github.com/algorand/go-algorand/ledger/ledgercore"
	"github.com/algorand/go-algorand/protocol"
	"github.com/algorand/go-algorand/stateproof"
)

// votersFetcher is used to provide safe access to the ledger while creating the state proof builder. Since the operation
// is being run under the ledger's commit operation, this implementation guarantees lockless access to the VotersForStateProof function.
type votersFetcher struct {
	vt *votersTracker
}

func (vf *votersFetcher) VotersForStateProof(rnd basics.Round) (*ledgercore.VotersForRound, error) {
	return vf.vt.VotersForStateProof(rnd)
}

func (vf *votersFetcher) BlockHdr(rnd basics.Round) (bookkeeping.BlockHeader, error) {
	return vf.vt.l.BlockHdr(rnd)
}

// The votersTracker maintains the vector commitment for the most recent
// commitments to online accounts for state proofs.
//
// We maintain multiple vector commitment: we might commit to a new VC in
// block X, but we need the VC from block X-params.StateProofBlocks
// to build the state proof for block X.
//
// votersTracker is kind-of like a tracker, but hangs off the acctupdates
// rather than a direct ledger tracker.  We don't have an explicit interface
// for such an "accounts tracker" yet, however.
type votersTracker struct {
	// votersForRoundCache contains the top online accounts in a given Round.
	//
	// To avoid increasing block latency, we include a vector commitment
	// to the top online accounts as of block X in the block header of
	// block X+StateProofVotersLookback.  This gives each node some time
	// to construct this vector commitment, before its root is needed in a block.
	//
	// This votersForRoundCache map is indexed by the block X, using the terminology from
	// the above example, to be used in X+StateProofVotersLookback.
	//
	// We maintain votersForRoundCache entries for two reasons:
	//
	// The first is to maintain the tree for an upcoming block -- that is,
	// if X+Loookback<Latest.  The block evaluator can ask for the root of
	// the tree to propose and validate a block.
	//
	// The second is to construct state proof.  State proofs
	// are formed for blocks that are a multiple of StateProofInterval, using
	// the vector commitment to online accounts from the previous such block.
	// Thus, we maintain X in the votersForRoundCache map until we form a stateproof
	// for round X+StateProofVotersLookback+StateProofInterval.
	//
	// In case state proof chain stalls this map would be bounded to StateProofMaxRecoveryIntervals + 3 in respect
	// to the db round.
	// + 1 - since votersForRoundCache needs to contain an entry for a future state proof
	// + 1 - since votersForRoundCache needs to contain an entry to verify the earliest state proof
	// in the recovery interval. i.e. it needs to have an entry for R-StateProofMaxRecoveryIntervals-StateProofInterval
	// to verify R-StateProofMaxRecoveryIntervals
	// + 1 would only appear if the sampled round R is:  interval - lookback < R < interval.
	// in this case, the tracker would not yet remove the old one but will create a new one for future state proof.
	// Additionally, the tracker would contain an entry for every state proof interval between the latest round in the
	// ledger and the db round.
	votersForRoundCache map[basics.Round]*ledgercore.VotersForRound
	votersMu            deadlock.RWMutex

	l                     ledgerForTracker
	onlineAccountsFetcher ledgercore.OnlineAccountsFetcher

	// loadWaitGroup syncronizing the completion of the loadTree call so that we can
	// shutdown the tracker without leaving any running go-routines.
	loadWaitGroup sync.WaitGroup

	// commitListener provides a callback to call on each prepare commit. This callback receives access to the voters
	// cache.
	commitListener   ledgercore.VotersCommitListener
	commitListenerMu deadlock.RWMutex
}

// votersRoundForStateProofRound computes the round number whose voting participants
// will be used to sign the state proof for stateProofRnd.
func votersRoundForStateProofRound(stateProofRnd basics.Round, proto *config.ConsensusParams) basics.Round {
	// To form a state proof on period that ends on stateProofRnd,
	// we need a commitment to the voters StateProofInterval rounds
	// before that, and the voters information from
	// StateProofVotersLookback before that.
	return stateProofRnd.SubSaturate(basics.Round(proto.StateProofInterval)).SubSaturate(basics.Round(proto.StateProofVotersLookback))
}

func (vt *votersTracker) loadFromDisk(l ledgerForTracker, fetcher ledgercore.OnlineAccountsFetcher, latestDbRound basics.Round) error {
	vt.votersMu.Lock()
	vt.l = l
	vt.onlineAccountsFetcher = fetcher
	vt.votersForRoundCache = make(map[basics.Round]*ledgercore.VotersForRound)
	vt.votersMu.Unlock()

	latestRoundInLedger := l.Latest()
	hdr, err := l.BlockHdr(latestRoundInLedger)
	if err != nil {
		return err
	}
	proto := config.Consensus[hdr.CurrentProtocol]

	if proto.StateProofInterval == 0 || hdr.StateProofTracking[protocol.StateProofBasic].StateProofNextRound == 0 {
		// Disabled, nothing to load.
		return nil
	}

	startR := stateproof.GetOldestExpectedStateProof(&hdr)
	startR = votersRoundForStateProofRound(startR, &proto)

	// Sanity check: we should never underflow or even reach 0.
	if startR == 0 {
		return fmt.Errorf("votersTracker: underflow: %d - %d - %d = %d",
			hdr.StateProofTracking[protocol.StateProofBasic].StateProofNextRound, proto.StateProofInterval, proto.StateProofVotersLookback, startR)
	}

	// we recreate the trees for old rounds. we stop at latestDbRound (where latestDbRound <= latestRoundInLedger) since
	// future blocks would be given as part of the replay
	for r := startR; r <= latestDbRound; r += basics.Round(proto.StateProofInterval) {
		hdr, err = l.BlockHdr(r)
		if err != nil {
			return err
		}

		vt.loadTree(hdr)
	}

	return nil
}

func (vt *votersTracker) loadTree(hdr bookkeeping.BlockHeader) {
	r := hdr.Round

	_, exists := vt.getVoters(r)
	if exists {
		// Already loaded.
		return
	}

	proto := config.Consensus[hdr.CurrentProtocol]
	if proto.StateProofInterval == 0 {
		// No StateProofs.
		return
	}

	tr := ledgercore.MakeVotersForRound()
	tr.Proto = proto

	vt.setVoters(r, tr)

	vt.loadWaitGroup.Add(1)
	go func() {
		defer vt.loadWaitGroup.Done()
		err := tr.LoadTree(vt.onlineAccountsFetcher, hdr)
		if err != nil {
			vt.l.trackerLog().Warnf("votersTracker.loadTree(%d): %v", hdr.Round, err)

			tr.BroadcastError(err)
		}
	}()
}

// close waits until all the internal spawned go-routines are done before returning, allowing clean
// shutdown.
func (vt *votersTracker) close() {
	vt.loadWaitGroup.Wait()
}

func (vt *votersTracker) newBlock(hdr bookkeeping.BlockHeader) {
	proto := config.Consensus[hdr.CurrentProtocol]
	if proto.StateProofInterval == 0 {
		// No StateProofs
		return
	}

	// This might be a block where we snapshot the online participants,
	// to eventually construct a vector commitment in a later
	// block.
	r := hdr.Round
	if (uint64(r)+proto.StateProofVotersLookback)%proto.StateProofInterval != 0 {
		return
	}

	_, exists := vt.getVoters(r)
	if exists {
		vt.l.trackerLog().Errorf("votersTracker.newBlock: round %d already present", r)
	} else {
		vt.loadTree(hdr)
	}

}

func (vt *votersTracker) prepareCommit(dcc *deferredCommitContext) error {
	vt.commitListenerMu.RLock()
	defer vt.commitListenerMu.RUnlock()

	if vt.commitListener == nil {
		return nil
	}

	commitListener := vt.commitListener
	vf := votersFetcher{vt: vt}
	// In case the listener's function fails, we do not want to break the commit process.
	// To implement this hierarchy we've decided to not include a return value in OnPrepareVoterCommit function
	commitListener.OnPrepareVoterCommit(dcc.oldBase, dcc.newBase(), &vf)

	return nil
}

func (vt *votersTracker) postCommit(dcc *deferredCommitContext) {
	lastHeaderCommitted, err := vt.l.BlockHdr(dcc.newBase())
	if err != nil {
		vt.l.trackerLog().Errorf("votersTracker.postCommit: could not retrieve header for round %d: %v", dcc.newBase(), err)
		return
	}

	// Voters older than lastHeaderCommitted.Round() - StateProofMaxRecoveryIntervals * StateProofInterval are
	// guaranteed to be removed here.
	vt.removeOldVoters(lastHeaderCommitted)
}

// removeOldVoters removes voters data form the tracker and allows the database to commit previous rounds.
// voters would be removed if one of the two condition is met
// 1 - Voters are for a round which was already been confirmed by stateproof
// 2 - Voters are for a round which is older than the allowed recovery interval.
//
// It is possible to optimize this function and not to travers votersForRoundCache on every round.
// Since the map is small (Usually  0 - 2 elements) we decided to keep the code simple
// and check for deletion in every round.
func (vt *votersTracker) removeOldVoters(hdr bookkeeping.BlockHeader) {
	lowestStateProofRound := stateproof.GetOldestExpectedStateProof(&hdr)

	vt.votersMu.Lock()
	defer vt.votersMu.Unlock()

	for r, tr := range vt.votersForRoundCache {
		commitRound := r + basics.Round(tr.Proto.StateProofVotersLookback)
		stateProofRound := commitRound + basics.Round(tr.Proto.StateProofInterval)

		// we remove voters that are no longer needed (i.e StateProofNextRound is larger ) or older than the recover period
		if stateProofRound < lowestStateProofRound {
			delete(vt.votersForRoundCache, r)
		}
	}
}

// lowestRound() returns the lowest votersForRoundCache state (blocks and accounts) needed by
// the votersTracker in case of a restart.  The accountUpdates tracker will
// not delete account state before this round, so that after a restart, it's
// possible to reconstruct the votersTracker.  If votersTracker does
// not need any blocks, it returns base.
func (vt *votersTracker) lowestRound(base basics.Round) basics.Round {
	minRound := base

	vt.votersMu.RLock()
	defer vt.votersMu.RUnlock()

	for r := range vt.votersForRoundCache {
		if r < minRound {
			minRound = r
		}
	}

	return minRound
}

// LatestCompletedVotersUpTo returns the highest round <= r for which information about the top online
// participants has already been collected,  and the completed VotersForRound for that round.
// If none is found, it returns 0, nil. Unlike VotersForStateProof, this function does not wait.
func (vt *votersTracker) LatestCompletedVotersUpTo(r basics.Round) (basics.Round, *ledgercore.VotersForRound) {
	vt.votersMu.RLock()
	defer vt.votersMu.RUnlock()

	var latestRound basics.Round
	var latestVoters *ledgercore.VotersForRound

	for round, voters := range vt.votersForRoundCache {
		if round <= r && round > latestRound {
			if completed, err := voters.Completed(); completed && err == nil {
				latestRound = round
				latestVoters = voters
			}
		}
	}

	return latestRound, latestVoters
}

// VotersForStateProof returns the top online participants from round r. If this data is still being
// constructed in another goroutine, this function will wait until it is ready.
func (vt *votersTracker) VotersForStateProof(r basics.Round) (*ledgercore.VotersForRound, error) {
	tr, exists := vt.getVoters(r)
	if !exists {
		// Not tracked: stateproofs not enabled.
		return nil, nil
	}

	// Wait for the vc to be constructed.
	err := tr.Wait()
	if err != nil {
		return nil, err
	}

	return tr, nil
}

func (vt *votersTracker) registerPrepareCommitListener(commitListener ledgercore.VotersCommitListener) {
	vt.commitListenerMu.Lock()
	defer vt.commitListenerMu.Unlock()

	if vt.commitListener != nil {
		vt.l.trackerLog().Error("votersTracker.registerPrepareCommitListener: overriding existing listener.")
	}
	vt.commitListener = commitListener
}

func (vt *votersTracker) unregisterPrepareCommitListener() {
	vt.commitListenerMu.Lock()
	defer vt.commitListenerMu.Unlock()

	vt.commitListener = nil
}

func (vt *votersTracker) getVoters(round basics.Round) (*ledgercore.VotersForRound, bool) {
	vt.votersMu.RLock()
	defer vt.votersMu.RUnlock()

	tr, ok := vt.votersForRoundCache[round]
	return tr, ok
}

func (vt *votersTracker) setVoters(round basics.Round, voters *ledgercore.VotersForRound) {
	vt.votersMu.Lock()
	defer vt.votersMu.Unlock()

	vt.votersForRoundCache[round] = voters
}
