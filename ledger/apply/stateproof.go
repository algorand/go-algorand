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

package apply

import (
	"errors"
	"fmt"

	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/transactions"
	"github.com/algorand/go-algorand/ledger/ledgercore"
	"github.com/algorand/go-algorand/protocol"
	"github.com/algorand/go-algorand/stateproof/verify"
)

// Errors for apply stateproof
var (
	ErrStateProofTypeNotSupported       = errors.New("state proof type not supported")
	ErrExpectedDifferentStateProofRound = errors.New("expected different state proof round")
)

// StateProof applies the StateProof transaction and setting the next StateProof round
func StateProof(tx transactions.StateProofTxnFields, atRound basics.Round, sp StateProofsApplier, validate bool) error {
	spType := tx.StateProofType
	if spType != protocol.StateProofBasic {
		return fmt.Errorf("applyStateProof: %w - type %d ", ErrStateProofTypeNotSupported, spType)
	}

	lastRoundInInterval := basics.Round(tx.Message.LastAttestedRound)
	nextStateProofRnd := sp.GetStateProofNextRound()
	if nextStateProofRnd == 0 || nextStateProofRnd != lastRoundInInterval {
		return fmt.Errorf("applyStateProof: %w - expecting state proof for %d, but new state proof is for %d",
			ErrExpectedDifferentStateProofRound, nextStateProofRnd, lastRoundInInterval)
	}

	if validate {
		var verificationContext *ledgercore.StateProofVerificationContext
		var err error
		if sp.ConsensusParams().StateProofUseTrackerVerification {
			verificationContext, err = sp.GetStateProofVerificationContext(lastRoundInInterval)
		} else {
			verificationContext, err = gatherVerificationContextUsingBlockHeaders(sp, lastRoundInInterval)
		}
		if err != nil {
			return err
		}

		if err = verify.ValidateStateProof(verificationContext, &tx.StateProof, atRound, &tx.Message); err != nil {
			return err
		}
	}

	// IMPORTANT: this line does not support changing the StateProofInterval consensus param;
	// Ideally the protocol version should be taken from the votersHeader (or even the lastRoundInInterval header).
	// However, when replaying the past 320 blocks we might not be able to fetch this header (only X+320+1000 past headers are available).
	// So for now we will use the current protocol version parameter, and when support for changing StateProofInterval arises
	// we shall revisit this decision.
	sp.SetStateProofNextRound(lastRoundInInterval + basics.Round(sp.ConsensusParams().StateProofInterval))
	return nil
}

func gatherVerificationContextUsingBlockHeaders(sp StateProofsApplier, lastRoundInInterval basics.Round) (*ledgercore.StateProofVerificationContext, error) {
	lastRoundHdr, err := sp.BlockHdr(lastRoundInInterval)
	if err != nil {
		return nil, err
	}
	proto := config.Consensus[lastRoundHdr.CurrentProtocol]
	votersRnd := lastRoundInInterval.SubSaturate(basics.Round(proto.StateProofInterval))
	votersHdr, err := sp.BlockHdr(votersRnd)
	if err != nil {
		return nil, err
	}

	verificationContext := ledgercore.MakeStateProofVerificationContext(&votersHdr, lastRoundInInterval)

	return verificationContext, nil
}
