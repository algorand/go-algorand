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

package stateproof

import (
	"context"
	"database/sql"
	"encoding/binary"
	"errors"
	"fmt"
	"maps"
	"slices"

	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/crypto/stateproof"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/bookkeeping"
	"github.com/algorand/go-algorand/data/stateproofmsg"
	"github.com/algorand/go-algorand/data/transactions"
	"github.com/algorand/go-algorand/ledger/ledgercore"
	"github.com/algorand/go-algorand/logging"
	"github.com/algorand/go-algorand/network"
	"github.com/algorand/go-algorand/protocol"
	"github.com/algorand/go-algorand/stateproof/verify"
)

var errVotersNotTracked = errors.New("voters not tracked for the given lookback round")

// spProver captures the state proof cryptographic prover in addition to data needed for
// signatures aggregation.
type spProver struct {
	_struct struct{} `codec:",omitempty,omitemptyarray"`

	*stateproof.Prover `codec:"prv"`

	AddrToPos map[Address]uint64      `codec:"addr,allocbound=stateproof.VotersAllocBound"`
	VotersHdr bookkeeping.BlockHeader `codec:"hdr"`
	Message   stateproofmsg.Message   `codec:"msg"`
}

// OnPrepareVoterCommit is a function called by the voters tracker when it's preparing to commit rnd. It gives the builder
// the chance to persist the data it needs.
func (spw *Worker) OnPrepareVoterCommit(oldBase basics.Round, newBase basics.Round, votersFetcher ledgercore.LedgerForSPBuilder) {
	for rnd := oldBase + 1; rnd <= newBase; rnd++ {
		header, err := votersFetcher.BlockHdr(rnd)
		if err != nil {
			spw.log.Errorf("OnPrepareVoterCommit(%d): could not fetch round header: %v", rnd, err)
			continue
		}

		proto := config.Consensus[header.CurrentProtocol]
		if proto.StateProofInterval == 0 || uint64(rnd)%proto.StateProofInterval != 0 {
			continue
		}

		var proverExists bool
		err = spw.db.Atomic(func(ctx context.Context, tx *sql.Tx) (err error) {
			proverExists, err = proverExistInDB(tx, rnd)
			return err
		})
		if err != nil {
			spw.log.Warnf("OnPrepareVoterCommit(%d): could not check prover existence, assuming it doesn't exist: %v\n", rnd, err)
		} else if proverExists {
			continue
		}

		provr, err := createProver(rnd, votersFetcher)
		if err != nil {
			if errors.Is(err, errVotersNotTracked) {
				// There are few reasons why we might encounter a situation where we don't
				// have voters for a state proof round.
				//
				// 1 - When state proof chain starts, the first round s.t round  % proto.stateproofInterval == 0  will not
				// have voters (since they are not enable). For this round we will not create a state proof.
				// e.g if  proto.stateproofInterval == 10, and round = 10. We skip the state proof for that round
				// (since there are not voters on round 0)
				//
				// 2 - When a node uses fastcatchup to some round, and immediately tries to create a builder.
				// Node might fail to create the builder since MaxBalLookback (in catchpoint) might not be large enough
				spw.log.Warnf("OnPrepareVoterCommit(%d): %v", rnd, err)
				continue
			}

			spw.log.Errorf("OnPrepareVoterCommit(%d): could not create prover: %v", rnd, err)
			continue
		}

		// At this point, there is a possibility that the signer has already created this specific builder
		// (signer created  the builder after proverExistInDB was called and was fast enough to persist it).
		// In this case we will rewrite the new builder
		err = spw.db.Atomic(func(_ context.Context, tx *sql.Tx) error {
			return persistProver(tx, rnd, &provr)
		})
		if err != nil {
			spw.log.Errorf("OnPrepareVoterCommit(%d): could not persist prover: %v", rnd, err)
		}
	}
}

// loadOrCreateProverWithSignatures either loads a state proof prover from the DB or creates a new prover.
// this function fills the prover with all the available signatures
func (spw *Worker) loadOrCreateProverWithSignatures(rnd basics.Round) (spProver, error) {
	b, err := spw.loadOrCreateProver(rnd)
	if err != nil {
		return spProver{}, err
	}

	if err := spw.loadSignaturesIntoProver(&b); err != nil {
		return spProver{}, err
	}
	return b, nil
}

func (spw *Worker) loadOrCreateProver(rnd basics.Round) (spProver, error) {
	var prover spProver
	err := spw.db.Atomic(func(ctx context.Context, tx *sql.Tx) (err error) {
		prover, err = getProver(tx, rnd)
		return err
	})

	if err == nil {
		return prover, nil
	}

	if !errors.Is(err, sql.ErrNoRows) {
		spw.log.Errorf("loadOrCreateProver: error while fetching builder from DB: %v", err)
	}

	prover, err = createProver(rnd, spw.ledger)
	if err != nil {
		return spProver{}, err
	}

	err = spw.db.Atomic(func(_ context.Context, tx *sql.Tx) error {
		return persistProver(tx, rnd, &prover)
	})

	// We ignore persisting errors because we still want to try and use our successfully generated builder,
	// even if, for some reason, persisting it failed.
	if err != nil {
		spw.log.Errorf("loadOrCreateProver(%d): failed to insert prover into database: %v", rnd, err)
	}

	return prover, nil
}

func (spw *Worker) loadSignaturesIntoProver(prover *spProver) error {
	var sigs []pendingSig
	err := spw.db.Atomic(func(ctx context.Context, tx *sql.Tx) error {
		var err2 error
		sigs, err2 = getPendingSigsForRound(tx, basics.Round(prover.Round))
		return err2
	})
	if err != nil {
		return err
	}

	for i := range sigs {
		err = prover.insertSig(&sigs[i], false)
		if err != nil {
			spw.log.Warn(err)
		}
	}
	return nil
}

func createProver(rnd basics.Round, votersFetcher ledgercore.LedgerForSPBuilder) (spProver, error) {
	// since this function might be invoked under tracker commit context (i.e invoked from the ledger code ),
	// it is important that we do not use the ledger directly.

	hdr, err := votersFetcher.BlockHdr(rnd)
	if err != nil {
		return spProver{}, err
	}

	hdrProto := config.Consensus[hdr.CurrentProtocol]
	votersRnd := rnd.SubSaturate(basics.Round(hdrProto.StateProofInterval))
	lookback := votersRnd.SubSaturate(basics.Round(hdrProto.StateProofVotersLookback))
	voters, err := votersFetcher.VotersForStateProof(lookback)
	if err != nil {
		return spProver{}, err
	}
	if voters == nil {
		return spProver{}, fmt.Errorf("lookback round %d: %w", lookback, errVotersNotTracked)
	}

	votersHdr, err := votersFetcher.BlockHdr(votersRnd)
	if err != nil {
		return spProver{}, err
	}

	msg, err := GenerateStateProofMessage(votersFetcher, rnd)
	if err != nil {
		return spProver{}, err
	}

	provenWeight, err := verify.GetProvenWeight(&votersHdr, &hdr)
	if err != nil {
		return spProver{}, err
	}

	var res spProver
	res.VotersHdr = votersHdr
	res.AddrToPos = voters.AddrToPos
	res.Message = msg
	res.Prover, err = stateproof.MakeProver(msg.Hash(),
		uint64(rnd),
		provenWeight,
		voters.Participants,
		voters.Tree,
		config.Consensus[votersHdr.CurrentProtocol].StateProofStrengthTarget)
	if err != nil {
		return spProver{}, err
	}

	return res, nil
}

func (spw *Worker) initProvers() {
	spw.provers = make(map[basics.Round]spProver)
	rnds, err := spw.getAllOnlineProverRounds()
	if err != nil {
		spw.log.Errorf("initProvers: failed to load rounds: %v", err)
		return
	}

	for _, rnd := range rnds {
		if _, ok := spw.provers[rnd]; ok {
			spw.log.Warnf("initProvers: round %d already present", rnd)
			continue
		}

		prover, err := spw.loadOrCreateProverWithSignatures(rnd)
		if err != nil {
			spw.log.Warnf("initProvers: failed to load prover for round %d", rnd)
			continue
		}
		spw.provers[rnd] = prover
	}
}

func (spw *Worker) getAllOnlineProverRounds() ([]basics.Round, error) {
	// Some state proof databases might only contain a signature table. For that reason, when trying to create provers for possible state proof
	// rounds we search the signature table and not the prover table
	latest := spw.ledger.Latest()
	latestHdr, err := spw.ledger.BlockHdr(latest)
	if err != nil {
		return nil, err
	}
	proto := config.Consensus[latestHdr.CurrentProtocol]
	if proto.StateProofInterval == 0 { // StateProofs are not enabled yet
		return nil, err
	}

	latestStateProofRound := latest.RoundDownToMultipleOf(basics.Round(proto.StateProofInterval))
	threshold := onlineProversThreshold(&proto, latestHdr.StateProofTracking[protocol.StateProofBasic].StateProofNextRound)

	var rnds []basics.Round
	err = spw.db.Atomic(func(_ context.Context, tx *sql.Tx) error {
		var err2 error
		rnds, err2 = getSignatureRounds(tx, threshold, latestStateProofRound)
		return err2
	})

	return rnds, err
}

var errAddressNotInVoters = errors.New("cannot find address in builder")                 // Address was not a part of the voters for this StateProof (top N accounts)
var errFailedToAddSigAtPos = errors.New("could not add signature to builder")            // Position was out of array bounds or signature already present
var errSigAlreadyPresentAtPos = errors.New("signature already present at this position") // Signature already present at this position
var errSignatureVerification = errors.New("error while verifying signature")             // Signature failed cryptographic verification

func (b *spProver) insertSig(s *pendingSig, verify bool) error {
	rnd := b.Round
	pos, ok := b.AddrToPos[s.signer]
	if !ok {
		return fmt.Errorf("insertSig: %w (%v not in participants for round %d)", errAddressNotInVoters, s.signer, rnd)
	}

	isPresent, err := b.Present(pos)
	if err != nil {
		return fmt.Errorf("insertSig: %w (failed to invoke builderForRound.Present on pos %d - %v)", errFailedToAddSigAtPos, pos, err)
	}
	if isPresent {
		return errSigAlreadyPresentAtPos
	}

	if err = b.IsValid(pos, &s.sig, verify); err != nil {
		return fmt.Errorf("insertSig: %w (cannot add %v in round %d: %v)", errSignatureVerification, s.signer, rnd, err)
	}
	if err = b.Add(pos, s.sig); err != nil {
		return fmt.Errorf("insertSig: %w (%v)", errFailedToAddSigAtPos, err)
	}

	return nil
}

func (spw *Worker) handleSigMessage(msg network.IncomingMessage) network.OutgoingMessage {
	var ssig sigFromAddr
	err := protocol.Decode(msg.Data, &ssig)
	if err != nil {
		spw.log.Warnf("spw.handleSigMessage(): decode: %v", err)
		return network.OutgoingMessage{Action: network.Disconnect}
	}

	fwd, err := spw.handleSig(ssig, msg.Sender)
	if err != nil {
		spw.log.Warnf("spw.handleSigMessage(): %v", err)
	}

	return network.OutgoingMessage{Action: fwd}
}

// meetsBroadcastPolicy verifies that the signature's round is either under the threshold round or equal to the
// latest StateProof round.
// This signature filtering is only relevant when the StateProof chain is stalled and many signatures may be spammed.
func (spw *Worker) meetsBroadcastPolicy(sfa sigFromAddr, latestRound basics.Round, proto *config.ConsensusParams, stateProofNextRound basics.Round) bool {
	if sfa.Round <= onlineProversThreshold(proto, stateProofNextRound) {
		return true
	}

	latestStateProofRound := latestRound.RoundDownToMultipleOf(basics.Round(proto.StateProofInterval))
	return sfa.Round == latestStateProofRound
}

// handleSig adds a signature to the pending in-memory state proof provers (provers). This function is
// also responsible for making sure that the signature is valid, and not duplicated.
// if a signature passes all verification it is written into the database.
func (spw *Worker) handleSig(sfa sigFromAddr, sender network.Peer) (network.ForwardingPolicy, error) {
	spw.mu.Lock()
	defer spw.mu.Unlock()

	// might happen if the state proof worker is stopping
	if spw.provers == nil {
		return network.Ignore, fmt.Errorf("handleSig: no provers loaded")
	}

	proverForRound, ok := spw.provers[sfa.Round]
	if !ok {
		latest := spw.ledger.Latest()
		latestHdr, err := spw.ledger.BlockHdr(latest)
		if err != nil {
			return network.Ignore, err
		}

		stateProofNextRound := latestHdr.StateProofTracking[protocol.StateProofBasic].StateProofNextRound

		if sfa.Round < stateProofNextRound {
			// Already have a complete state proof in ledger.
			// Ignore this sig.
			return network.Ignore, nil
		}

		proto := config.Consensus[latestHdr.CurrentProtocol]
		// proto.StateProofInterval is not expected to be 0 after passing StateProofNextRound
		// checking anyway, otherwise will panic
		if proto.StateProofInterval == 0 {
			return network.Disconnect, fmt.Errorf("handleSig: StateProofInterval is 0 for round %d", latest)
		}

		if uint64(sfa.Round)%proto.StateProofInterval != 0 {
			// reject the sig for the round which is not a multiple of the interval
			// Disconnect: should not be sending a sig for this round
			return network.Disconnect, fmt.Errorf("handleSig: round %d is not a multiple of SP interval %d",
				sfa.Round, proto.StateProofInterval)
		}

		if sfa.Round > latest {
			// avoiding an inspection in DB in case we haven't reached the round.
			// Avoiding disconnecting the peer, since it might've been sent to this node while it recovers.
			return network.Ignore, fmt.Errorf("handleSig: latest round is smaller than given round %d", sfa.Round)
		}

		// We want to save the signature in the DB if we know we generated it. However, if the signature's source is
		// external, we only want to process it if we know for sure it meets our broadcast policy.
		if sender != nil && !spw.meetsBroadcastPolicy(sfa, latestHdr.Round, &proto, stateProofNextRound) {
			return network.Ignore, nil
		}

		proverForRound, err = spw.loadOrCreateProverWithSignatures(sfa.Round)
		if err != nil {
			// Should not disconnect this peer, since this is a fault of the relay
			// The peer could have other signatures what the relay is interested in
			return network.Ignore, err
		}
		spw.provers[sfa.Round] = proverForRound
		spw.log.Infof("spw.handleSig: starts gathering signatures for round %d", sfa.Round)
	}

	sig := pendingSig{
		signer:       sfa.SignerAddress,
		sig:          sfa.Sig,
		fromThisNode: sender == nil,
	}
	err := proverForRound.insertSig(&sig, true)
	if errors.Is(err, errSigAlreadyPresentAtPos) {
		// Safe to ignore this error as it means we already have a valid signature for this address
		return network.Ignore, nil
	}
	if errors.Is(err, errAddressNotInVoters) || errors.Is(err, errSignatureVerification) {
		return network.Disconnect, err
	}
	if err != nil { // errFailedToAddSigAtPos and fallback in case of unknown error
		return network.Ignore, err
	}

	err = spw.db.Atomic(func(ctx context.Context, tx *sql.Tx) error {
		return addPendingSig(tx, sfa.Round, sig)
	})
	if err != nil {
		return network.Ignore, err
	}

	return network.Broadcast, nil
}

func (spw *Worker) builder(latest basics.Round) {
	// We clock the building of state proofs based on new
	// blocks.  This is because the acceptable state proof
	// size grows over time, so that we aim to construct an extremely
	// small state proof upfront, but if that doesn't work out, we
	// will settle for a larger proof.  New blocks also tell us
	// if a state proof has been committed, so that we can stop trying
	// to build it.

	nextBroadcastRnd := latest
	for {
		spw.tryBroadcast()

		select {
		case <-spw.ctx.Done():
			spw.wg.Done()
			return

		case <-spw.ledger.Wait(nextBroadcastRnd + 1):
			// Continue on
		}

		newLatest := spw.ledger.Latest()
		newLatestHdr, err := spw.ledger.BlockHdr(newLatest)

		if err != nil {
			spw.log.Warnf("spw.builder: BlockHdr(%d): %v", newLatest, err)
			continue
		}

		proto := config.Consensus[newLatestHdr.CurrentProtocol]
		stateProofNextRound := newLatestHdr.StateProofTracking[protocol.StateProofBasic].StateProofNextRound

		spw.deleteProverData(&proto, stateProofNextRound)

		// Broadcast signatures based on the previous block(s) that
		// were agreed upon.  This ensures that, if we send a signature
		// for block R, nodes will have already verified block R, because
		// block R+1 has been formed.
		for r := nextBroadcastRnd; r < newLatest; r++ {
			// Wait for the signer to catch up; mostly relevant in tests.
			spw.waitForSignature(r)
			spw.broadcastSigs(r, stateProofNextRound, proto)
		}
		nextBroadcastRnd = newLatest
	}
}

// broadcastSigs periodically broadcasts pending signatures for rounds
// that have not been able to form a state proof, with correlation to builderCacheLength.
//
// Signature re-broadcasting happens in periods of proto.StateProofInterval
// rounds.
//
// In the first half of each such period, signers of a block broadcast their
// own signatures; this is the expected common path.
//
// In the second half of each such period, any signatures seen by this node
// are broadcast.
//
// The broadcast schedule is randomized by the address of the block signer,
// for load-balancing over time.
func (spw *Worker) broadcastSigs(brnd basics.Round, stateProofNextRound basics.Round, proto config.ConsensusParams) {
	if proto.StateProofInterval == 0 {
		return
	}

	spw.mu.Lock()
	defer spw.mu.Unlock()

	latestStateProofRound := brnd.RoundDownToMultipleOf(basics.Round(proto.StateProofInterval))
	threshold := onlineProversThreshold(&proto, stateProofNextRound)
	var roundSigs map[basics.Round][]pendingSig
	err := spw.db.Atomic(func(ctx context.Context, tx *sql.Tx) (err error) {
		if brnd%basics.Round(proto.StateProofInterval) < basics.Round(proto.StateProofInterval/2) {
			roundSigs, err = getPendingSigs(tx, threshold, latestStateProofRound, true)
		} else {
			roundSigs, err = getPendingSigs(tx, threshold, latestStateProofRound, false)
		}
		return
	})
	if err != nil {
		spw.log.Warnf("broadcastSigs: getPendingSigs: %v", err)
		return
	}

	for rnd, sigs := range roundSigs {
		if rnd > brnd {
			// Signature is for later block than brnd.  This could happen
			// during catchup or testing.  The caller's loop will eventually
			// invoke this function with a suitably high brnd.
			continue
		}

		for _, sig := range sigs {
			// Randomize which sigs get broadcast over time.
			addr64 := binary.LittleEndian.Uint64(sig.signer[:])
			if addr64%(proto.StateProofInterval/2) != uint64(brnd)%(proto.StateProofInterval/2) {
				continue
			}

			sfa := sigFromAddr{
				SignerAddress: sig.signer,
				Round:         rnd,
				Sig:           sig.sig,
			}
			err = spw.net.Broadcast(context.Background(), protocol.StateProofSigTag,
				protocol.Encode(&sfa), false, nil)
			if err != nil {
				spw.log.Warnf("broadcastSigs: Broadcast for %d: %v", rnd, err)
			}
		}
	}
}

func (spw *Worker) deleteProverData(proto *config.ConsensusParams, stateProofNextRound basics.Round) {
	if proto.StateProofInterval == 0 || stateProofNextRound == 0 {
		return
	}

	// Delete from memory (already stored on disk). Practically, There are two scenarios where provers gets removed from memory
	// 1. When a state proof is committed, the earliest will get removed and later on will be removed from disk.
	//	(when calling deleteStaleProver)
	// 2. If state proofs are stalled, and consensus is moving forward, a new latest prover will be created and
	// the older provers will be swapped out from memory. (i.e will be removed from memory but stays on disk).
	spw.trimProversCache(proto, stateProofNextRound)

	if spw.lastCleanupRound == stateProofNextRound {
		return
	}

	// Delete from disk (database)
	spw.deleteStaleSigs(stateProofNextRound)
	spw.deleteStaleKeys(stateProofNextRound)
	spw.deleteStaleProver(stateProofNextRound)
	spw.lastCleanupRound = stateProofNextRound
}

func (spw *Worker) deleteStaleSigs(retainRound basics.Round) {
	err := spw.db.Atomic(func(ctx context.Context, tx *sql.Tx) error {
		return deletePendingSigsBeforeRound(tx, retainRound)
	})
	if err != nil {
		spw.log.Warnf("deleteStaleSigs(%d): %v", retainRound, err)
	}
}

func (spw *Worker) deleteStaleKeys(retainRound basics.Round) {
	keys := spw.accts.StateProofKeys(retainRound)
	for _, key := range keys {
		firstRoundAtKeyLifeTime, err := key.StateProofSecrets.FirstRoundInKeyLifetime()
		if err != nil {
			spw.log.Errorf("deleteStaleKeys: could not calculate keylifetime for account %v on round %d:  %v", key.ParticipationID, firstRoundAtKeyLifeTime, err)
			continue
		}
		err = spw.accts.DeleteStateProofKey(key.ParticipationID, basics.Round(firstRoundAtKeyLifeTime))
		if err != nil {
			spw.log.Warnf("deleteStaleKeys: could not remove key for account %v on round %d: %v", key.ParticipationID, firstRoundAtKeyLifeTime, err)
		}
	}
}

func (spw *Worker) deleteStaleProver(retainRound basics.Round) {
	err := spw.db.Atomic(func(ctx context.Context, tx *sql.Tx) error {
		return deleteProvers(tx, retainRound)
	})
	if err != nil {
		spw.log.Warnf("deleteStaleProver: failed to delete provers from database: %v", err)
	}
}

// onlineProversThreshold returns the highest round for which the prover should be stored in memory (cache).
// This is mostly relevant in case the StateProof chain is stalled.
// The threshold is also used to limit the StateProof signatures broadcasted over the network.
func onlineProversThreshold(proto *config.ConsensusParams, stateProofNextRound basics.Round) basics.Round {
	/*
		proverCacheLength - 2:
			let proversCacheLength <- 5, StateProofNextRound <- 1024, LatestRound <- 4096
			threshold = StateProofNextRound + 3 * StateProofInterval (for a total of 4 early StateProofs)
			the 5th prover in the cache is reserved for the LatestRound stateproof.
	*/
	threshold := stateProofNextRound + basics.Round((proversCacheLength-2)*proto.StateProofInterval)
	return threshold
}

// trimProversCache reduces the number of provers stored in memory to X earliest as well as 1 latest, to an overall amount of X+1 provers
func (spw *Worker) trimProversCache(proto *config.ConsensusParams, stateProofNextRound basics.Round) {
	spw.mu.Lock()
	defer spw.mu.Unlock()

	var maxProverRound basics.Round
	for rnd := range spw.provers {
		if rnd > maxProverRound {
			maxProverRound = rnd
		}
	}

	threshold := onlineProversThreshold(proto, stateProofNextRound)
	/*
		For example, provers currently stored in memory are for these rounds:
		[..., StateProofNextRound-256, StateProofNextRound, StateProofNextRound+256, ..., Threshold, ..., maxProverRound]
		[StateProofNextRound, ..., Threshold, maxProverRound] <- Only provers that should be stored in memory after trim
	*/
	for rnd := range spw.provers {
		if rnd < stateProofNextRound || (threshold < rnd && rnd < maxProverRound) {
			delete(spw.provers, rnd)
		}
	}
}

func (spw *Worker) tryBroadcast() {
	spw.mu.Lock()
	defer spw.mu.Unlock()

	sortedRounds := slices.Sorted(maps.Keys(spw.provers))

	for _, rnd := range sortedRounds {
		// Iterate over the provers in a sequential manner. If the earlist state proof is not ready/rejected
		// it won't be possible to add a later one. For that reason, we break the loop
		b := spw.provers[rnd]
		firstValid := spw.ledger.Latest()
		acceptableWeight := verify.AcceptableStateProofWeight(&b.VotersHdr, firstValid, logging.Base())
		if b.SignedWeight() < acceptableWeight {
			// Haven't signed enough to build the state proof at this time..
			break
		}

		if !b.Ready() {
			// Haven't gotten enough signatures to get past ProvenWeight
			break
		}

		sp, err := b.CreateProof()
		if err != nil {
			spw.log.Warnf("spw.tryBroadcast: building state proof for %d failed: %v", rnd, err)
			break
		}

		latestHeader, err := spw.ledger.BlockHdr(firstValid)
		if err != nil {
			spw.log.Warnf("spw.tryBroadcast: could not fetch block header for round %d: %v", firstValid, err)
			break
		}

		spw.log.Infof("spw.tryBroadcast: building state proof transaction for round %d", rnd)
		var stxn transactions.SignedTxn
		stxn.Txn.Type = protocol.StateProofTx
		stxn.Txn.Sender = transactions.StateProofSender
		stxn.Txn.FirstValid = firstValid
		stxn.Txn.LastValid = firstValid + basics.Round(config.Consensus[latestHeader.CurrentProtocol].MaxTxnLife)
		stxn.Txn.GenesisHash = spw.ledger.GenesisHash()
		stxn.Txn.StateProofTxnFields.StateProofType = protocol.StateProofBasic
		stxn.Txn.StateProofTxnFields.StateProof = *sp
		stxn.Txn.StateProofTxnFields.Message = b.Message
		err = spw.txnSender.BroadcastInternalSignedTxGroup([]transactions.SignedTxn{stxn})
		if err != nil {
			spw.log.Warnf("spw.tryBroadcast: broadcasting state proof txn for %d: %v", rnd, err)
			// if this StateProofTxn was rejected, the next one would be rejected as well since state proof should be added in
			// a sequential order
			break
		}
	}
}

func (spw *Worker) invokeBuilder(r basics.Round) {
	spw.signedMu.Lock()
	spw.signed = r
	spw.signedMu.Unlock()

	select {
	case spw.signedCh <- struct{}{}:
	default:
	}
}

func (spw *Worker) lastSignedBlock() basics.Round {
	spw.signedMu.RLock()
	defer spw.signedMu.RUnlock()
	return spw.signed
}

func (spw *Worker) waitForSignature(r basics.Round) {
	for {
		if r <= spw.lastSignedBlock() {
			return
		}

		select {
		case <-spw.ctx.Done():
			return
		case <-spw.signedCh:
		}
	}
}
