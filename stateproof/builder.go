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

package stateproof

import (
	"context"
	"database/sql"
	"encoding/binary"
	"fmt"

	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/crypto/stateproof"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/transactions"
	"github.com/algorand/go-algorand/ledger"
	"github.com/algorand/go-algorand/logging"
	"github.com/algorand/go-algorand/network"
	"github.com/algorand/go-algorand/protocol"
)

// builderForRound not threadsafe, should be called in a lock environment
func (spw *Worker) builderForRound(rnd basics.Round) (builder, error) {
	hdr, err := spw.ledger.BlockHdr(rnd)
	if err != nil {
		return builder{}, err
	}

	hdrProto := config.Consensus[hdr.CurrentProtocol]
	votersRnd := rnd.SubSaturate(basics.Round(hdrProto.StateProofInterval))
	votersHdr, err := spw.ledger.BlockHdr(votersRnd)
	if err != nil {
		return builder{}, err
	}

	lookback := votersRnd.SubSaturate(basics.Round(hdrProto.StateProofVotersLookback))
	voters, err := spw.ledger.VotersForStateProof(lookback)
	if err != nil {
		return builder{}, err
	}

	if voters == nil {
		// Voters not tracked for that round.  Might not be a valid
		// state proof round; state proofs might not be enabled; etc.
		return builder{}, fmt.Errorf("voters not tracked for lookback round %d", lookback)
	}

	msg, err := GenerateStateProofMessage(spw.ledger, uint64(votersHdr.Round), hdr)
	if err != nil {
		return builder{}, err
	}
	spw.Message = msg

	provenWeight, err := ledger.GetProvenWeight(votersHdr, hdr)
	if err != nil {
		return builder{}, err
	}

	var res builder
	res.votersHdr = votersHdr
	res.voters = voters
	res.Builder, err = stateproof.MkBuilder(msg.IntoStateProofMessageHash(),
		uint64(hdr.Round),
		provenWeight,
		voters.Participants,
		voters.Tree,
		config.Consensus[votersHdr.CurrentProtocol].StateProofStrengthTarget)
	if err != nil {
		return builder{}, err
	}

	spw.builders[rnd] = res
	return res, nil
}

func (spw *Worker) initBuilders() {
	spw.mu.Lock()
	defer spw.mu.Unlock()

	var roundSigs map[basics.Round][]pendingSig
	err := spw.db.Atomic(func(ctx context.Context, tx *sql.Tx) (err error) {
		roundSigs, err = getPendingSigs(tx)
		return
	})
	if err != nil {
		spw.log.Warnf("initBuilders: getPendingSigs: %w", err)
		return
	}

	for rnd, sigs := range roundSigs {
		if _, ok := spw.builders[rnd]; ok {
			spw.log.Warnf("initBuilders: round %d already present", rnd)
			continue
		}
		spw.addSigsToBuilder(sigs, rnd)
	}
}

func (spw *Worker) addSigsToBuilder(sigs []pendingSig, rnd basics.Round) {
	builderForRound, err := spw.builderForRound(rnd)
	if err != nil {
		spw.log.Warnf("addSigsToBuilder: builderForRound(%d): %v", rnd, err)
		return
	}

	for _, sig := range sigs {
		pos, ok := builderForRound.voters.AddrToPos[sig.signer]
		if !ok {
			spw.log.Warnf("addSigsToBuilder: cannot find %v in round %d", sig.signer, rnd)
			continue
		}

		isPresent, err := builderForRound.Present(pos)
		if err != nil {
			spw.log.Warnf("addSigsToBuilder: failed to invoke builderForRound.Present on pos %d - %w ", pos, err)
			continue
		}
		if isPresent {
			spw.log.Warnf("addSigsToBuilder: cannot add %v in round %d: position %d already added", sig.signer, rnd, pos)
			continue
		}

		if err := builderForRound.IsValid(pos, sig.sig, false); err != nil {
			spw.log.Warnf("addSigsToBuilder: cannot add %v in round %d: %v", sig.signer, rnd, err)
			continue
		}
		if err := builderForRound.Add(pos, sig.sig); err != nil {
			spw.log.Warnf("addSigsToBuilder: error while adding sig. inner error: %w", err)
			continue
		}
	}
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

func (spw *Worker) handleSig(sfa sigFromAddr, sender network.Peer) (network.ForwardingPolicy, error) {
	spw.mu.Lock()
	defer spw.mu.Unlock()

	builderForRound, ok := spw.builders[sfa.Round]
	if !ok {
		latest := spw.ledger.Latest()
		latestHdr, err := spw.ledger.BlockHdr(latest)
		if err != nil {
			return network.Disconnect, err
		}

		if sfa.Round < latestHdr.StateProofTracking[protocol.StateProofBasic].StateProofNextRound {
			// Already have a complete state proof in ledger.
			// Ignore this sig.
			return network.Ignore, nil
		}

		builderForRound, err = spw.builderForRound(sfa.Round)
		if err != nil {
			return network.Disconnect, err
		}
	}

	pos, ok := builderForRound.voters.AddrToPos[sfa.Signer]
	if !ok {
		return network.Disconnect, fmt.Errorf("handleSig: %v not in participants for %d", sfa.Signer, sfa.Round)
	}

	if isPresent, err := builderForRound.Present(pos); err != nil || isPresent {
		// Signature already part of the builderForRound, ignore.
		return network.Ignore, nil
	}

	if err := builderForRound.IsValid(pos, sfa.Sig, true); err != nil {
		return network.Disconnect, err
	}

	err := spw.db.Atomic(func(ctx context.Context, tx *sql.Tx) error {
		return addPendingSig(tx, sfa.Round, pendingSig{
			signer:       sfa.Signer,
			sig:          sfa.Sig,
			fromThisNode: sender == nil,
		})
	})
	if err != nil {
		return network.Ignore, err
	}
	// validated that we can add the sig previously.
	if err := builderForRound.Add(pos, sfa.Sig); err != nil {
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
	for {
		spw.tryBuilding()

		nextrnd := latest + 1
		select {
		case <-spw.ctx.Done():
			spw.wg.Done()
			return

		case <-spw.ledger.Wait(nextrnd):
			// Continue on
		}

		// See if any new state proofs were formed, according to
		// the new block, which would mean we can clean up some builders.
		hdr, err := spw.ledger.BlockHdr(nextrnd)
		if err != nil {
			spw.log.Warnf("spw.builder: BlockHdr(%d): %v", nextrnd, err)
			continue
		} else {
			spw.deleteOldSigs(hdr.StateProofTracking[protocol.StateProofBasic].StateProofNextRound)
		}

		// Broadcast signatures based on the previous block(s) that
		// were agreed upon.  This ensures that, if we send a signature
		// for block R, nodes will have already verified block R, because
		// block R+1 has been formed.
		proto := config.Consensus[hdr.CurrentProtocol]
		newLatest := spw.ledger.Latest()
		for r := latest; r < newLatest; r++ {
			// Wait for the signer to catch up; mostly relevant in tests.
			spw.waitForSignedBlock(r)

			spw.broadcastSigs(r, proto)
		}
		latest = newLatest
	}
}

// broadcastSigs periodically broadcasts pending signatures for rounds
// that have not been able to form a state proof.
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
func (spw *Worker) broadcastSigs(brnd basics.Round, proto config.ConsensusParams) {
	if proto.StateProofInterval == 0 {
		return
	}

	spw.mu.Lock()
	defer spw.mu.Unlock()

	var roundSigs map[basics.Round][]pendingSig
	err := spw.db.Atomic(func(ctx context.Context, tx *sql.Tx) (err error) {
		if brnd%basics.Round(proto.StateProofInterval) < basics.Round(proto.StateProofInterval/2) {
			roundSigs, err = getPendingSigsFromThisNode(tx)
		} else {
			roundSigs, err = getPendingSigs(tx)
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
				Signer: sig.signer,
				Round:  rnd,
				Sig:    sig.sig,
			}
			err = spw.net.Broadcast(context.Background(), protocol.StateProofSigTag,
				protocol.Encode(&sfa), false, nil)
			if err != nil {
				spw.log.Warnf("broadcastSigs: Broadcast for %d: %v", rnd, err)
			}
		}
	}
}

func (spw *Worker) deleteOldSigs(nextStateProof basics.Round) {
	spw.mu.Lock()
	defer spw.mu.Unlock()

	err := spw.db.Atomic(func(ctx context.Context, tx *sql.Tx) error {
		return deletePendingSigsBeforeRound(tx, nextStateProof)
	})
	if err != nil {
		spw.log.Warnf("deletePendingSigsBeforeRound(%d): %v", nextStateProof, err)
	}

	for rnd := range spw.builders {
		if rnd < nextStateProof {
			delete(spw.builders, rnd)
		}
	}
}

func (spw *Worker) tryBuilding() {
	spw.mu.Lock()
	defer spw.mu.Unlock()

	for rnd, b := range spw.builders {
		firstValid := spw.ledger.Latest()
		acceptableWeight := ledger.AcceptableStateProofWeight(b.votersHdr, firstValid, logging.Base())
		if b.SignedWeight() < acceptableWeight {
			// Haven't signed enough to build the cert at this time..
			continue
		}

		if !b.Ready() {
			// Haven't gotten enough signatures to get past ProvenWeight
			continue
		}

		cert, err := b.Build()
		if err != nil {
			spw.log.Warnf("spw.tryBuilding: building state proof for %d: %v", rnd, err)
			continue
		}

		var stxn transactions.SignedTxn
		stxn.Txn.Type = protocol.StateProofTx
		stxn.Txn.Sender = transactions.StateProofSender
		stxn.Txn.FirstValid = firstValid
		stxn.Txn.LastValid = firstValid + basics.Round(b.voters.Proto.MaxTxnLife)
		stxn.Txn.GenesisHash = spw.ledger.GenesisHash()
		stxn.Txn.StateProofType = protocol.StateProofBasic
		stxn.Txn.StateProofIntervalLatestRound = rnd
		stxn.Txn.StateProof = *cert
		stxn.Txn.StateProofMessage = spw.Message
		err = spw.txnSender.BroadcastInternalSignedTxGroup([]transactions.SignedTxn{stxn})
		if err != nil {
			spw.log.Warnf("spw.tryBuilding: broadcasting state proof txn for %d: %v", rnd, err)
		}
	}
}

func (spw *Worker) signedBlock(r basics.Round) {
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

func (spw *Worker) waitForSignedBlock(r basics.Round) {
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
