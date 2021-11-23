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

package ledger

import (
	"fmt"
	"sync"

	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/bookkeeping"
	"github.com/algorand/go-algorand/ledger/ledgercore"
	"github.com/algorand/go-algorand/protocol"
)

// The votersTracker maintains the Merkle tree for the most recent
// commitments to online accounts for compact certificates.
//
// We maintain multiple Merkle trees: we might commit to a new Merkle tree in
// block X, but we need the Merkle tree from block X-params.CompactCertBlocks
// to build the compact certificate for block X.
//
// votersTracker is kind-of like a tracker, but hangs off the acctupdates
// rather than a direct ledger tracker.  We don't have an explicit interface
// for such an "accounts tracker" yet, however.
type votersTracker struct {
	// round contains the top online accounts in a given round.
	//
	// To avoid increasing block latency, we include a Merkle commitment
	// to the top online accounts as of block X in the block header of
	// block X+CompactCertVotersLookback.  This gives each node some time
	// to construct this Merkle tree, before its root is needed in a block.
	//
	// This round map is indexed by the block X, using the terminology from
	// the above example, to be used in X+CompactCertVotersLookback.
	//
	// We maintain round entries for two reasons:
	//
	// The first is to maintain the tree for an upcoming block -- that is,
	// if X+Loookback<Latest.  The block evaluator can ask for the root of
	// the tree to propose and validate a block.
	//
	// The second is to construct compact certificates.  Compact certificates
	// are formed for blocks that are a multiple of CompactCertRounds, using
	// the Merkle commitment to online accounts from the previous such block.
	// Thus, we maintain X in the round map until we form a compact certificate
	// for round X+CompactCertVotersLookback+CompactCertRounds.
	round map[basics.Round]*ledgercore.VotersForRound

	l  ledgerForTracker
	au *accountUpdates

	// loadWaitGroup syncronizing the completion of the loadTree call so that we can
	// shutdown the tracker without leaving any running go-routines.
	loadWaitGroup sync.WaitGroup
}

// votersRoundForCertRound computes the round number whose voting participants
// will be used to sign the compact cert for certRnd.
func votersRoundForCertRound(certRnd basics.Round, proto config.ConsensusParams) basics.Round {
	// To form a compact certificate for round certRnd,
	// we need a commitment to the voters CompactCertRounds
	// before that, and the voters information from
	// CompactCertVotersLookback before that.
	return certRnd.SubSaturate(basics.Round(proto.CompactCertRounds)).SubSaturate(basics.Round(proto.CompactCertVotersLookback))
}

func (vt *votersTracker) loadFromDisk(l ledgerForTracker, au *accountUpdates) error {
	vt.l = l
	vt.au = au
	vt.round = make(map[basics.Round]*ledgercore.VotersForRound)

	latest := l.Latest()
	hdr, err := l.BlockHdr(latest)
	if err != nil {
		return err
	}
	proto := config.Consensus[hdr.CurrentProtocol]

	if proto.CompactCertRounds == 0 || hdr.CompactCert[protocol.CompactCertBasic].CompactCertNextRound == 0 {
		// Disabled, nothing to load.
		return nil
	}

	startR := votersRoundForCertRound(hdr.CompactCert[protocol.CompactCertBasic].CompactCertNextRound, proto)

	// Sanity check: we should never underflow or even reach 0.
	if startR == 0 {
		return fmt.Errorf("votersTracker: underflow: %d - %d - %d = %d",
			hdr.CompactCert[protocol.CompactCertBasic].CompactCertNextRound, proto.CompactCertRounds, proto.CompactCertVotersLookback, startR)
	}

	for r := startR; r <= latest; r += basics.Round(proto.CompactCertRounds) {
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

	_, ok := vt.round[r]
	if ok {
		// Already loaded.
		return
	}

	proto := config.Consensus[hdr.CurrentProtocol]
	if proto.CompactCertRounds == 0 {
		// No compact certs.
		return
	}

	tr := ledgercore.MakeVotersForRound()
	tr.Proto = proto

	vt.round[r] = tr

	vt.loadWaitGroup.Add(1)
	go func() {
		defer vt.loadWaitGroup.Done()
		onlineAccounts := ledgercore.TopOnlineAccounts(vt.au.onlineTop)
		err := tr.LoadTree(onlineAccounts, hdr)
		if err != nil {
			vt.l.trackerLog().Warnf("votersTracker.loadTree(%d): %v", hdr.Round, err)

			tr.BroadcastError(err)
		}
	}()
	return
}

// close waits until all the internal spawned go-rouines are done before returning, allowing clean
// shutdown.
func (vt *votersTracker) close() {
	vt.loadWaitGroup.Wait()
}

func (vt *votersTracker) newBlock(hdr bookkeeping.BlockHeader) {
	proto := config.Consensus[hdr.CurrentProtocol]
	if proto.CompactCertRounds == 0 {
		// No compact certs.
		return
	}

	// Check if any blocks can be forgotten because the compact cert is available.
	for r, tr := range vt.round {
		commitRound := r + basics.Round(tr.Proto.CompactCertVotersLookback)
		certRound := commitRound + basics.Round(tr.Proto.CompactCertRounds)
		if certRound < hdr.CompactCert[protocol.CompactCertBasic].CompactCertNextRound {
			delete(vt.round, r)
		}
	}

	// This might be a block where we snapshot the online participants,
	// to eventually construct a merkle tree for commitment in a later
	// block.
	r := uint64(hdr.Round)
	if (r+proto.CompactCertVotersLookback)%proto.CompactCertRounds == 0 {
		_, ok := vt.round[basics.Round(r)]
		if ok {
			vt.l.trackerLog().Errorf("votersTracker.newBlock: round %d already present", r)
		} else {
			vt.loadTree(hdr)
		}
	}
}

// lowestRound() returns the lowest round state (blocks and accounts) needed by
// the votersTracker in case of a restart.  The accountUpdates tracker will
// not delete account state before this round, so that after a restart, it's
// possible to reconstruct the votersTracker.  If votersTracker does
// not need any blocks, it returns base.
func (vt *votersTracker) lowestRound(base basics.Round) basics.Round {
	minRound := base
	for r := range vt.round {
		if r < minRound {
			minRound = r
		}
	}
	return minRound
}

// getVoters() returns the top online participants from round r.
func (vt *votersTracker) getVoters(r basics.Round) (*ledgercore.VotersForRound, error) {
	tr, ok := vt.round[r]
	if !ok {
		// Not tracked: compact certs not enabled.
		return nil, nil
	}

	// Wait for the Merkle tree to be constructed.
	err := tr.Wait()
	if err != nil {
		return nil, err
	}

	return tr, nil
}
