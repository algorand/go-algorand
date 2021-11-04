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

package ledgercore

import (
	"fmt"
	"sync"

	"github.com/algorand/go-deadlock"

	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/crypto/merklearray"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/bookkeeping"
)

// VotersForRound tracks the top online voting accounts as of a particular
// round, along with a Merkle tree commitment to those voting accounts.
type VotersForRound struct {
	// Because it can take some time to compute the top participants and the
	// corresponding Merkle tree, the votersForRound is constructed in
	// the background.  This means that fields (participants, adddToPos,
	// tree, and totalWeight) could be nil/zero while a background thread
	// is computing them.  Once the fields are set, however, they are
	// immutable, and it is no longer necessary to acquire the lock.
	//
	// If an error occurs while computing the tree in the background,
	// loadTreeError might be set to non-nil instead.  That also finalizes
	// the state of this VotersForRound.
	mu            deadlock.Mutex
	cond          *sync.Cond
	loadTreeError error

	// Proto is the ConsensusParams for the round whose balances are reflected
	// in participants.
	Proto config.ConsensusParams

	// Participants is the array of top #CompactCertVoters online accounts
	// in this round, sorted by normalized balance (to make sure heavyweight
	// accounts are biased to the front).
	Participants ParticipantsArray

	// AddrToPos specifies the position of a given account address (if present)
	// in the Participants array.  This allows adding a vote from a given account
	// to the certificate builder.
	AddrToPos map[basics.Address]uint64

	// Tree is a constructed Merkle tree of the Participants array.
	Tree *merklearray.Tree

	// TotalWeight is the sum of the weights from the Participants array.
	TotalWeight basics.MicroAlgos
}

// TopOnlineAccounts is the function signature for a method that would return the top online accounts.
type TopOnlineAccounts func(rnd basics.Round, voteRnd basics.Round, n uint64) ([]*OnlineAccount, error)

// MakeVotersForRound create a new VotersForRound object and initialize it's cond.
func MakeVotersForRound() *VotersForRound {
	vr := &VotersForRound{}
	vr.cond = sync.NewCond(&vr.mu)
	return vr
}

// LoadTree todo
func (tr *VotersForRound) LoadTree(onlineTop TopOnlineAccounts, hdr bookkeeping.BlockHeader) error {
	r := hdr.Round

	// certRound is the block that we expect to form a compact certificate for,
	// using the balances from round r.
	certRound := r + basics.Round(tr.Proto.CompactCertVotersLookback+tr.Proto.CompactCertRounds)

	// sigKeyRound is the ephemeral key ID that we expect to be used for signing
	// the block from certRound.  It is one higher because the keys for certRound
	// might be deleted by the time consensus is reached on the block and we try
	// to sign the compact cert for block certRound.
	sigKeyRound := certRound + 1

	top, err := onlineTop(r, sigKeyRound, tr.Proto.CompactCertTopVoters)
	if err != nil {
		return err
	}

	participants := make(ParticipantsArray, len(top))
	addrToPos := make(map[basics.Address]uint64)
	var totalWeight basics.MicroAlgos

	for i, acct := range top {
		var ot basics.OverflowTracker
		rewards := basics.PendingRewards(&ot, tr.Proto, acct.MicroAlgos, acct.RewardsBase, hdr.RewardsLevel)
		money := ot.AddA(acct.MicroAlgos, rewards)
		if ot.Overflowed {
			return fmt.Errorf("votersTracker.LoadTree: overflow adding rewards %d + %d", acct.MicroAlgos, rewards)
		}

		totalWeight = ot.AddA(totalWeight, money)
		if ot.Overflowed {
			return fmt.Errorf("votersTracker.LoadTree: overflow computing totalWeight %d + %d", totalWeight.ToUint64(), money.ToUint64())
		}

		keyDilution := acct.VoteKeyDilution
		if keyDilution == 0 {
			keyDilution = tr.Proto.DefaultKeyDilution
		}

		participants[i] = basics.Participant{
			PK:          acct.VoteID,
			Weight:      money.ToUint64(),
			KeyDilution: keyDilution,
		}
		addrToPos[acct.Address] = uint64(i)
	}

	tree, err := merklearray.Build(participants)
	if err != nil {
		return err
	}

	tr.mu.Lock()
	tr.AddrToPos = addrToPos
	tr.Participants = participants
	tr.TotalWeight = totalWeight
	tr.Tree = tree
	tr.cond.Broadcast()
	tr.mu.Unlock()

	return nil
}

// BroadcastError broadcasts the error
func (tr *VotersForRound) BroadcastError(err error) {
	tr.mu.Lock()
	tr.loadTreeError = err
	tr.cond.Broadcast()
	tr.mu.Unlock()
}

//Wait waits for the tree to get constructed.
func (tr *VotersForRound) Wait() error {
	tr.mu.Lock()
	defer tr.mu.Unlock()
	for tr.Tree == nil {
		if tr.loadTreeError != nil {
			return tr.loadTreeError
		}

		tr.cond.Wait()
	}
	return nil
}
