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
	"time"

	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/crypto/merklesignature"
	"github.com/algorand/go-algorand/data/account"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/bookkeeping"
	"github.com/algorand/go-algorand/protocol"
)

// sigFromAddr encapsulates a signature on a block header, which
// will eventually be used to form a state proof for that
// block.
type sigFromAddr struct {
	_struct struct{} `codec:",omitempty,omitemptyarray"`

	SignerAddress basics.Address            `codec:"a"`
	Round         basics.Round              `codec:"r"`
	Sig           merklesignature.Signature `codec:"s"`
}

func (spw *Worker) signer(latest basics.Round) {
	nextRnd := spw.nextStateProofRound(latest)
	for { // Start signing StateProofs from nextRnd onwards
		select {
		case <-spw.ledger.Wait(nextRnd):
			hdr, err := spw.ledger.BlockHdr(nextRnd)
			if err != nil {
				spw.log.Warnf("spw.signer(): BlockHdr(next %d): %v", nextRnd, err)
				time.Sleep(1 * time.Second)
				nextRnd = spw.nextStateProofRound(spw.ledger.Latest())
				continue
			}
			spw.signStateProof(hdr)
			spw.invokeBuilder(nextRnd)
			nextRnd++

		case <-spw.ctx.Done():
			spw.wg.Done()
			return
		}
	}
}

func (spw *Worker) nextStateProofRound(latest basics.Round) basics.Round {
	var nextrnd basics.Round

	for {
		latestHdr, err := spw.ledger.BlockHdr(latest)
		if err != nil {
			spw.log.Warnf("spw.signer(): BlockHdr(latest %d): %v", latest, err)
			time.Sleep(1 * time.Second)
			latest = spw.ledger.Latest()
			continue
		}

		nextrnd = latestHdr.StateProofTracking[protocol.StateProofBasic].StateProofNextRound
		if nextrnd == 0 {
			// State proofs are not enabled yet.  Keep monitoring new blocks.
			nextrnd = latest + 1
		}
		break
	}

	return nextrnd
}

func (spw *Worker) signStateProof(hdr bookkeeping.BlockHeader) {
	proto := config.Consensus[hdr.CurrentProtocol]
	if proto.StateProofInterval == 0 {
		return
	}

	// Only sign blocks that are a multiple of StateProofInterval.
	if hdr.Round%basics.Round(proto.StateProofInterval) != 0 {
		return
	}

	keys := spw.accts.StateProofKeys(hdr.Round)
	if len(keys) == 0 {
		// No keys, nothing to do.
		return
	}

	// votersRound is the round containing the merkle root commitment
	// for the voters that are going to sign this block.
	votersRound := hdr.Round.SubSaturate(basics.Round(proto.StateProofInterval))
	votersHdr, err := spw.ledger.BlockHdr(votersRound)
	if err != nil {
		spw.log.Warnf("spw.signBlock(%d): BlockHdr(%d): %v", hdr.Round, votersRound, err)
		return
	}

	if votersHdr.StateProofTracking[protocol.StateProofBasic].StateProofVotersCommitment.IsEmpty() {
		// No voter commitment, perhaps because state proofs were
		// just enabled.
		return
	}

	sigs := make([]sigFromAddr, 0, len(keys))
	ids := make([]account.ParticipationID, 0, len(keys))
	usedSigners := make([]*merklesignature.Signer, 0, len(keys))

	stateproofMessage, err := GenerateStateProofMessage(spw.ledger, uint64(votersHdr.Round), hdr)
	if err != nil {
		spw.log.Warnf("spw.signBlock(%d): GenerateStateProofMessage: %v", hdr.Round, err)
		return
	}
	hashedStateproofMessage := stateproofMessage.Hash()

	for _, key := range keys {
		if key.FirstValid > hdr.Round || hdr.Round > key.LastValid {
			continue
		}

		if key.StateProofSecrets == nil {
			spw.log.Warnf("spw.signBlock(%d): empty state proof secrets for round", hdr.Round)
			continue
		}

		sig, err := key.StateProofSecrets.SignBytes(hashedStateproofMessage[:])
		if err != nil {
			spw.log.Warnf("spw.signBlock(%d): StateProofSecrets.Sign: %v", hdr.Round, err)
			continue
		}

		sigs = append(sigs, sigFromAddr{
			SignerAddress: key.Account,
			Round:         hdr.Round,
			Sig:           sig,
		})
		ids = append(ids, key.ParticipationID)
		usedSigners = append(usedSigners, key.StateProofSecrets)
	}

	// any error in handle sig indicates the signature wasn't stored in disk, thus we cannot delete the key.
	for i, sfa := range sigs {
		if _, err := spw.handleSig(sfa, nil); err != nil {
			spw.log.Warnf("spw.signBlock(%d): handleSig: %v", hdr.Round, err)
			continue
		}

		firstRoundInKeyLifetime, err := usedSigners[i].FirstRoundInKeyLifetime() // Calculate first round of the key in order to delete all previous keys (and keep the current one for now)
		if err != nil {
			spw.log.Warnf("spw.signBlock(%d): Signer.FirstRoundInKeyLifetime: %v", hdr.Round, err)
			continue
		}
		if firstRoundInKeyLifetime == 0 {
			continue // No previous keys to delete (also underflows when subtracting 1)
		}

		// Safe to delete key for sfa.Round because the signature is now stored in the disk.
		if err := spw.accts.DeleteStateProofKey(ids[i], basics.Round(firstRoundInKeyLifetime-1)); err != nil { // Subtract 1 to delete all keys up to this one
			spw.log.Warnf("spw.signBlock(%d): DeleteStateProofKey: %v", hdr.Round, err)
		}
	}
}
