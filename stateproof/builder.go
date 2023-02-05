// Copyright (C) 2019-2023 Algorand, Inc.
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
	"sort"

	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/crypto/stateproof"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/transactions"
	"github.com/algorand/go-algorand/ledger/ledgercore"
	"github.com/algorand/go-algorand/logging"
	"github.com/algorand/go-algorand/network"
	"github.com/algorand/go-algorand/protocol"
	"github.com/algorand/go-algorand/stateproof/verify"
)

var errVotersNotTracked = errors.New("voters not tracked for the given lookback round")

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

		builderExists, err := spw.builderExists(rnd)
		if err != nil {
			spw.log.Warnf("OnPrepareVoterCommit(%d): could not check builder existence, assuming it doesn't exist: %v\n", rnd, err)
		} else if builderExists {
			continue
		}

		buildr, err := createBuilder(rnd, votersFetcher)
		if err != nil {
			if errors.Is(err, errVotersNotTracked) {
				// Voters not tracked for that round.  Might not be a valid
				// state proof round; state proofs might not be enabled; etc.
				spw.log.Warnf("OnPrepareVoterCommit(%d): %v", rnd, err)
				continue
			}

			spw.log.Errorf("OnPrepareVoterCommit(%d): could not create builder: %v", rnd, err)
			continue
		}

		err = spw.db.Atomic(func(_ context.Context, tx *sql.Tx) error {
			return persistBuilder(tx, rnd, &buildr)
		})
		if err != nil {
			spw.log.Errorf("OnPrepareVoterCommit(%d): could not persist builder: %v", rnd, err)
		}
	}
}

// loadOrCreateBuilderWithSignatures either loads a builder from the DB or creates a new builder.
// this function fills the builder with all the available signatures
func (spw *Worker) loadOrCreateBuilderWithSignatures(rnd basics.Round) (builder, error) {
	b, err := spw.loadOrCreateBuilder(rnd)
	if err != nil {
		return builder{}, err
	}

	if err := spw.loadSignaturesIntoBuilder(&b); err != nil {
		return builder{}, err
	}
	return b, nil
}

func (spw *Worker) loadOrCreateBuilder(rnd basics.Round) (builder, error) {
	var buildr builder
	err := spw.db.Atomic(func(ctx context.Context, tx *sql.Tx) (err error) {
		buildr, err = getBuilder(tx, rnd)
		return err
	})

	if err == nil {
		return buildr, nil
	}

	if !errors.Is(err, sql.ErrNoRows) {
		spw.log.Errorf("loadOrCreateBuilder: error while fetching builder from DB: %v", err)
	}

	buildr, err = createBuilder(rnd, spw.ledger)
	if err != nil {
		return builder{}, err
	}

	err = spw.db.Atomic(func(_ context.Context, tx *sql.Tx) error {
		return persistBuilder(tx, rnd, &buildr)
	})

	// We ignore persisting errors because we still want to try and use our successfully generated builder,
	// even if, for some reason, persisting it failed.
	if err != nil {
		spw.log.Errorf("loadOrCreateBuilder(%d): failed to insert builder into database: %v", rnd, err)
	}

	return buildr, nil
}

func (spw *Worker) loadSignaturesIntoBuilder(buildr *builder) error {
	var sigs []pendingSig
	err := spw.db.Atomic(func(ctx context.Context, tx *sql.Tx) error {
		var err2 error
		sigs, err2 = getPendingSigsForRound(tx, basics.Round(buildr.Round))
		return err2
	})
	if err != nil {
		return err
	}

	for _, sig := range sigs {
		err = buildr.insertSig(&sig, false)
		if err != nil {
			spw.log.Warn(err)
		}
	}
	return nil
}

func createBuilder(rnd basics.Round, votersFetcher ledgercore.LedgerForSPBuilder) (builder, error) {
	// since this function might be invoked under tracker commit context (i.e invoked from the ledger code ),
	// it is important that we do not use the ledger directly.

	hdr, err := votersFetcher.BlockHdr(rnd)
	if err != nil {
		return builder{}, err
	}

	hdrProto := config.Consensus[hdr.CurrentProtocol]
	votersRnd := rnd.SubSaturate(basics.Round(hdrProto.StateProofInterval))
	votersHdr, err := votersFetcher.BlockHdr(votersRnd)
	if err != nil {
		return builder{}, err
	}

	lookback := votersRnd.SubSaturate(basics.Round(hdrProto.StateProofVotersLookback))
	voters, err := votersFetcher.VotersForStateProof(lookback)
	if err != nil {
		return builder{}, err
	}

	if voters == nil {
		// Voters not tracked for that round.  Might not be a valid
		// state proof round; state proofs might not be enabled; etc.
		return builder{}, fmt.Errorf("lookback round %d: %w", lookback, errVotersNotTracked)
	}

	msg, err := GenerateStateProofMessage(votersFetcher, rnd)
	if err != nil {
		return builder{}, err
	}

	provenWeight, err := verify.GetProvenWeight(&votersHdr, &hdr)
	if err != nil {
		return builder{}, err
	}

	var res builder
	res.VotersHdr = votersHdr
	res.AddrToPos = voters.AddrToPos
	res.Message = msg
	res.Builder, err = stateproof.MakeBuilder(msg.Hash(),
		uint64(rnd),
		provenWeight,
		voters.Participants,
		voters.Tree,
		config.Consensus[votersHdr.CurrentProtocol].StateProofStrengthTarget)
	if err != nil {
		return builder{}, err
	}

	return res, nil
}

func (spw *Worker) initBuilders() {
	spw.mu.Lock()
	defer spw.mu.Unlock()

	rnds, err := spw.getAllOnlineBuilderRounds()
	if err != nil {
		spw.log.Errorf("initBuilders: failed to load rounds: %v", err)
		return
	}

	for _, rnd := range rnds {
		if _, ok := spw.builders[rnd]; ok {
			spw.log.Warnf("initBuilders: round %d already present", rnd)
			continue
		}

		buildr, err := spw.loadOrCreateBuilderWithSignatures(rnd)
		if err != nil {
			spw.log.Warnf("initBuilders: failed to load builder for round %d", rnd)
			continue
		}
		spw.builders[rnd] = buildr
	}

	spw.ledger.RegisterVotersCommitListener(spw)
}

func (spw *Worker) getAllOnlineBuilderRounds() ([]basics.Round, error) {
	// Some state proof databases might only contain a signature table. For that reason, when trying to create builders for possible state proof
	// rounds we search the signature table and not the builder table
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
	threshold := onlineBuildersThreshold(&proto, latestHdr.StateProofTracking[protocol.StateProofBasic].StateProofNextRound)

	var rnds []basics.Round
	err = spw.db.Atomic(func(_ context.Context, tx *sql.Tx) error {
		var err error
		rnds, err = getSignatureRounds(tx, threshold, latestStateProofRound)
		return err
	})

	return rnds, err
}

var errAddressNotInVoters = errors.New("cannot find address in builder")                 // Address was not a part of the voters for this StateProof (top N accounts)
var errFailedToAddSigAtPos = errors.New("could not add signature to builder")            // Position was out of array bounds or signature already present
var errSigAlreadyPresentAtPos = errors.New("signature already present at this position") // Signature already present at this position
var errSignatureVerification = errors.New("error while verifying signature")             // Signature failed cryptographic verification

func (b *builder) insertSig(s *pendingSig, verify bool) error {
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
	if sfa.Round <= onlineBuildersThreshold(proto, stateProofNextRound) {
		return true
	}

	latestStateProofRound := latestRound.RoundDownToMultipleOf(basics.Round(proto.StateProofInterval))
	return sfa.Round == latestStateProofRound
}

// handleSig adds a signature to the pending in-memory state proof provers (builders). This function is
// also responsible for making sure that the signature is valid, and not duplicated.
// if a signature passes all verification it is written into the database.
func (spw *Worker) handleSig(sfa sigFromAddr, sender network.Peer) (network.ForwardingPolicy, error) {
	spw.mu.Lock()
	defer spw.mu.Unlock()

	builderForRound, ok := spw.builders[sfa.Round]
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

		builderForRound, err = spw.loadOrCreateBuilderWithSignatures(sfa.Round)
		if err != nil {
			// Should not disconnect this peer, since this is a fault of the relay
			// The peer could have other signatures what the relay is interested in
			return network.Ignore, err
		}
		spw.builders[sfa.Round] = builderForRound
		spw.log.Infof("spw.handleSig: starts gathering signatures for round %d", sfa.Round)
	}

	sig := pendingSig{
		signer:       sfa.SignerAddress,
		sig:          sfa.Sig,
		fromThisNode: sender == nil,
	}
	err := builderForRound.insertSig(&sig, true)
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

func (spw *Worker) sigExists(round basics.Round, account basics.Address) (bool, error) {
	var exists bool
	err := spw.db.Atomic(func(ctx context.Context, tx *sql.Tx) error {
		res, err := sigExistsInDB(tx, round, account)
		exists = res
		return err
	})
	return exists, err
}

func (spw *Worker) builderExists(rnd basics.Round) (bool, error) {
	var exist bool
	err := spw.db.Atomic(func(ctx context.Context, tx *sql.Tx) error {
		var err2 error
		exist, err2 = builderExistInDB(tx, rnd)
		return err2
	})

	return exist, err
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

		spw.deleteBuildData(&proto, stateProofNextRound)

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
	threshold := onlineBuildersThreshold(&proto, stateProofNextRound)
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

func (spw *Worker) deleteBuildData(proto *config.ConsensusParams, stateProofNextRound basics.Round) {
	if proto.StateProofInterval == 0 || stateProofNextRound == 0 {
		return
	}

	// Delete from memory (already stored on disk)
	spw.trimBuildersCache(proto, stateProofNextRound)

	if spw.lastCleanupRound == stateProofNextRound {
		return
	}

	// Delete from disk (database)
	spw.deleteStaleSigs(stateProofNextRound)
	spw.deleteStaleKeys(stateProofNextRound)
	spw.deleteStaleBuilders(stateProofNextRound)
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
	spw.accts.DeleteStateProofKeysForExpiredAccounts(retainRound)
}

func (spw *Worker) deleteStaleBuilders(retainRound basics.Round) {
	err := spw.db.Atomic(func(ctx context.Context, tx *sql.Tx) error {
		return deleteBuilders(tx, retainRound)
	})
	if err != nil {
		spw.log.Warnf("deleteOldBuilders: failed to delete builders from database: %v", err)
	}
}

// onlineBuildersThreshold returns the highest round for which the builder should be stored in memory (cache).
// This is mostly relevant in case the StateProof chain is stalled.
// The threshold is also used to limit the StateProof signatures broadcasted over the network.
func onlineBuildersThreshold(proto *config.ConsensusParams, stateProofNextRound basics.Round) basics.Round {
	/*
		builderCacheLength - 2:
			let buildersCacheLength <- 5, StateProofNextRound <- 1024, LatestRound <- 4096
			threshold = StateProofNextRound + 3 * StateProofInterval (for a total of 4 early StateProofs)
			the 5th builder in the cache is reserved for the LatestRound stateproof.
	*/
	threshold := stateProofNextRound + basics.Round((buildersCacheLength-2)*proto.StateProofInterval)
	return threshold
}

// trimBuildersCache reduces the number of builders stored in memory to X earliest as well as 1 latest, to an overall amount of X+1 builders
func (spw *Worker) trimBuildersCache(proto *config.ConsensusParams, stateProofNextRound basics.Round) {
	spw.mu.Lock()
	defer spw.mu.Unlock()

	var maxBuilderRound basics.Round
	for rnd := range spw.builders {
		if rnd > maxBuilderRound {
			maxBuilderRound = rnd
		}
	}

	threshold := onlineBuildersThreshold(proto, stateProofNextRound)
	/*
		For example, builders currently stored in memory are for these rounds:
		[..., StateProofNextRound-256, StateProofNextRound, StateProofNextRound+256, ..., Threshold, ..., MaxBuilderRound]
		[StateProofNextRound, ..., Threshold, MaxBuilderRound] <- Only builders that should be stored in memory after trim
	*/
	for rnd := range spw.builders {
		if rnd < stateProofNextRound || (threshold < rnd && rnd < maxBuilderRound) {
			delete(spw.builders, rnd)
		}
	}
}

func (spw *Worker) tryBroadcast() {
	spw.mu.Lock()
	defer spw.mu.Unlock()

	sortedRounds := make([]basics.Round, 0, len(spw.builders))
	for rnd := range spw.builders {
		sortedRounds = append(sortedRounds, rnd)
	}
	sort.Slice(sortedRounds, func(i, j int) bool { return sortedRounds[i] < sortedRounds[j] })

	for _, rnd := range sortedRounds { // Iterate over the builders in a sequential manner
		b := spw.builders[rnd]
		firstValid := spw.ledger.Latest()
		acceptableWeight := verify.AcceptableStateProofWeight(&b.VotersHdr, firstValid, logging.Base())
		if b.SignedWeight() < acceptableWeight {
			// Haven't signed enough to build the state proof at this time..
			continue
		}

		if !b.Ready() {
			// Haven't gotten enough signatures to get past ProvenWeight
			continue
		}

		sp, err := b.Build()
		if err != nil {
			spw.log.Warnf("spw.tryBroadcast: building state proof for %d failed: %v", rnd, err)
			continue
		}

		latestHeader, err := spw.ledger.BlockHdr(firstValid)
		if err != nil {
			spw.log.Warnf("spw.tryBroadcast: could not fetch block header for round %d failed: %v", firstValid, err)
			continue
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
	spw.mu.Lock()
	spw.signed = r
	spw.mu.Unlock()

	select {
	case spw.signedCh <- struct{}{}:
	default:
	}
}

func (spw *Worker) lastSignedBlock() basics.Round {
	spw.mu.Lock()
	defer spw.mu.Unlock()
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
