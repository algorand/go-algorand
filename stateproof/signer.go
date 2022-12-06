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
	"github.com/algorand/go-algorand/data/stateproofmsg"
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
			spw.signStateProof(nextRnd)
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

func (spw *Worker) signStateProof(round basics.Round) {
	// TODO: What happens right after upgrade when the tracker doesn't contain the context?
	// TODO: Perhaps we should add a fallback for the voters
	verificationContext, err := spw.ledger.StateProofVerificationContext(round)
	if err != nil {
		// TODO: Should this really be the error handling here? This really shouldn't happen
		spw.log.Warnf("spw.signBlock(%d): StateProofVerificationContext(%d): %v", round, round, err)
		return
	}

	proto := config.Consensus[verificationContext.Version]
	if proto.StateProofInterval == 0 {
		return
	}

	// Only sign blocks that are a multiple of StateProofInterval.
	if round%basics.Round(proto.StateProofInterval) != 0 {
		return
	}

	if verificationContext.VotersCommitment.IsEmpty() {
		// No voter commitment, perhaps because state proofs were
		// just enabled.
		return
	}

	keys := spw.accts.StateProofKeys(round)
	if len(keys) == 0 {
		// No keys, nothing to do.
		return
	}

	// votersRound is the round containing the merkle root commitment
	// for the voters that are going to sign this block.
	votersRound := round.SubSaturate(basics.Round(proto.StateProofInterval))

	stateProofMessage, err := spw.getStateProofMessage(round, votersRound)
	if err != nil {
		// TODO: Warn? Or something else?
		spw.log.Warnf("spw.signBlock(%d): getStateProofMessage: %v", round, err)
		return
	}

	spw.signStateProofMessage(stateProofMessage, round, keys)
}

func (spw *Worker) getStateProofMessage(round basics.Round, votersRound basics.Round) (*stateproofmsg.Message, error) {
	// TODO: Do we maybe want to save information indicating whether I've signed the builder
	dbBuilder, err := spw.loadBuilderFromDB(round)
	if err == nil {
		return &dbBuilder.Message, nil
	}

	// TODO: Do we really want this fall back on every error?
	// TODO: Add a comment here

	hdr, err := spw.ledger.BlockHdr(round)
	if err != nil {
		return nil, err
	}

	stateproofMessage, err := GenerateStateProofMessage(spw.ledger, uint64(votersRound), hdr)
	if err != nil {
		return nil, err
	}

	return &stateproofMessage, nil
}

func (spw *Worker) signStateProofMessage(message *stateproofmsg.Message, round basics.Round, keys []account.StateProofSecretsForRound) {
	hashedStateproofMessage := message.Hash()

	sigs := make([]sigFromAddr, 0, len(keys))

	for _, key := range keys {
		if key.FirstValid > round || round > key.LastValid {
			continue
		}

		if key.StateProofSecrets == nil {
			spw.log.Warnf("spw.signBlock(%d): empty state proof secrets for round", round)
			continue
		}

		exists, err := spw.sigExistsInDB(round, key.Account)
		if err != nil {
			spw.log.Warnf("spw.signBlock(%d): couldn't figure if sig exists in DB: %v", round, err)
		} else if exists {
			continue
		}

		sig, err := key.StateProofSecrets.SignBytes(hashedStateproofMessage[:])
		if err != nil {
			spw.log.Warnf("spw.signBlock(%d): StateProofSecrets.Sign: %v", round, err)
			continue
		}

		sigs = append(sigs, sigFromAddr{
			SignerAddress: key.Account,
			Round:         round,
			Sig:           sig,
		})
	}

	// any error in handle sig indicates the signature wasn't stored in disk, thus we cannot delete the key.
	for _, sfa := range sigs {
		if _, err := spw.handleSig(sfa, nil); err != nil {
			spw.log.Warnf("spw.signBlock(%d): handleSig: %v", round, err)
			continue
		}
		spw.log.Infof("spw.signBlock(%d): sp message was signed with address %v", round, sfa.SignerAddress)
	}
}
