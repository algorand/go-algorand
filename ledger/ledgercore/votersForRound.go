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

package ledgercore

import (
	"fmt"
	"sync"

	"github.com/algorand/go-deadlock"

	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/crypto/merklearray"
	"github.com/algorand/go-algorand/crypto/merklesignature"
	"github.com/algorand/go-algorand/crypto/stateproof"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/bookkeeping"
)

// OnlineAccountsFetcher captures the functionality of querying online accounts status
type OnlineAccountsFetcher interface {
	// TopOnlineAccounts returns the top n online accounts, sorted by their normalized
	// balance and address, whose voting keys are valid in voteRnd.  See the
	// normalization description in AccountData.NormalizedOnlineBalance().
	TopOnlineAccounts(rnd basics.Round, voteRnd basics.Round, n uint64, params *config.ConsensusParams, rewardsLevel uint64) (topOnlineAccounts []*OnlineAccount, totalOnlineStake basics.MicroAlgos, err error)
}

// LedgerForSPBuilder captures the functionality needed for the creation of the cryptographic state proof builder.
type LedgerForSPBuilder interface {
	VotersForStateProof(rnd basics.Round) (*VotersForRound, error)
	BlockHdr(basics.Round) (bookkeeping.BlockHeader, error)
}

// VotersCommitListener represents an object that needs to get notified on commit stages in the voters tracker.
type VotersCommitListener interface {
	// OnPrepareVoterCommit gives the listener the opportunity to backup VotersForRound data related to rounds  (oldBase, newBase] before it is being removed.
	// The implementation should log any errors that might occur.
	OnPrepareVoterCommit(oldBase basics.Round, newBase basics.Round, voters LedgerForSPBuilder)
}

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

	// Participants is the array of top StateProofTopVoters online accounts
	// in this round, sorted by normalized balance (to make sure heavyweight
	// accounts are biased to the front).
	Participants basics.ParticipantsArray

	// AddrToPos specifies the position of a given account address (if present)
	// in the Participants array.  This allows adding a vote from a given account
	// to the certificate builder.
	AddrToPos map[basics.Address]uint64

	// Tree is a constructed Merkle tree of the Participants array.
	Tree *merklearray.Tree

	// TotalWeight is the sum of the weights from the Participants array.
	TotalWeight basics.MicroAlgos
}

// MakeVotersForRound create a new VotersForRound object and initialize it's cond.
func MakeVotersForRound() *VotersForRound {
	vr := &VotersForRound{}
	vr.cond = sync.NewCond(&vr.mu)
	return vr
}

func createStateProofParticipant(stateProofID *merklesignature.Commitment, money basics.MicroAlgos) basics.Participant {
	var retPart basics.Participant
	retPart.Weight = money.ToUint64()
	// Some accounts might not have StateProof keys commitment. As a result,
	// the commitment would be an array filled with zeroes: [0x0...0x0].
	// Since the commitment is created using the subset-sum hash function, for which the
	// value [0x0..0x0] might be known, we avoid using such empty commitments.
	// We replace it with a commitment for zero keys..
	if stateProofID.IsEmpty() {
		copy(retPart.PK.Commitment[:], merklesignature.NoKeysCommitment[:])
	} else {
		copy(retPart.PK.Commitment[:], stateProofID[:])

	}
	// KeyLifetime is set as a default value here (256) as the currently registered StateProof keys do not have a KeyLifetime value associated with them.
	// In order to support changing the KeyLifetime in the future, we would need to update the Keyreg transaction and replace the value here with the one
	// registered by the Account.
	retPart.PK.KeyLifetime = merklesignature.KeyLifetimeDefault
	return retPart
}

// LoadTree loads the participation tree and other required fields, using the provided OnlineAccountsFetcher.
func (tr *VotersForRound) LoadTree(onlineAccountsFetcher OnlineAccountsFetcher, hdr bookkeeping.BlockHeader) error {
	r := hdr.Round

	// stateProofRound is the block that we expect to form a state proof for,
	// using the balances from round r.
	stateProofRound := r + basics.Round(tr.Proto.StateProofVotersLookback+tr.Proto.StateProofInterval)

	top, totalOnlineWeight, err := onlineAccountsFetcher.TopOnlineAccounts(r, stateProofRound, tr.Proto.StateProofTopVoters, &tr.Proto, hdr.RewardsLevel)
	if err != nil {
		return err
	}

	participants := make(basics.ParticipantsArray, len(top))
	addrToPos := make(map[basics.Address]uint64)

	for i, acct := range top {
		var ot basics.OverflowTracker
		rewards := basics.PendingRewards(&ot, tr.Proto, acct.MicroAlgos, acct.RewardsBase, hdr.RewardsLevel)
		money := ot.AddA(acct.MicroAlgos, rewards)
		if ot.Overflowed {
			return fmt.Errorf("votersTracker.LoadTree: overflow adding rewards %d + %d", acct.MicroAlgos, rewards)
		}

		participants[i] = createStateProofParticipant(&acct.StateProofID, money)
		addrToPos[acct.Address] = uint64(i)
	}

	tree, err := merklearray.BuildVectorCommitmentTree(participants, crypto.HashFactory{HashType: stateproof.HashType})
	if err != nil {
		return err
	}

	tr.mu.Lock()
	tr.AddrToPos = addrToPos
	tr.Participants = participants
	tr.TotalWeight = totalOnlineWeight
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

// Wait waits for the tree to get constructed.
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

// Completed returns true if the tree has finished being constructed.
// If there was an error constructing the tree, the error is also returned.
func (tr *VotersForRound) Completed() (bool, error) {
	tr.mu.Lock()
	defer tr.mu.Unlock()
	return tr.Tree != nil || tr.loadTreeError != nil, tr.loadTreeError
}
