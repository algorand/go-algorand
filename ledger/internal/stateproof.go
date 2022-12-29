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

package internal

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
	errStateProofTypeNotSupported       = errors.New("state proof type not supported")
	errExpectedDifferentStateProofRound = errors.New("expected different state proof round")
)

// applyStateProof applies the StateProof transaction and setting the next StateProof round
func applyStateProof(tx transactions.StateProofTxnFields, atRound basics.Round, sp *roundCowState, spVCgetter ledgercore.StateProofTrackerGetter, validate bool) error {
	spType := tx.StateProofType
	if spType != protocol.StateProofBasic {
		return fmt.Errorf("applyStateProof: %w - type %d ", errStateProofTypeNotSupported, spType)
	}

	lastRoundInInterval := basics.Round(tx.Message.LastAttestedRound)
	nextStateProofRnd := sp.GetStateProofNextRound()
	if nextStateProofRnd == 0 || nextStateProofRnd != lastRoundInInterval {
		return fmt.Errorf("applyStateProof: %w - expecting state proof for %d, but new state proof is for %d",
			errExpectedDifferentStateProofRound, nextStateProofRnd, lastRoundInInterval)
	}

	atRoundHdr, err := sp.BlockHdr(atRound)
	if err != nil {
		return err
	}

	var verificationContext *ledgercore.StateProofVerificationContext
	if config.Consensus[atRoundHdr.CurrentProtocol].StateProofUseTrackerVerification {
		verificationContext, err = spVCgetter.GetStateProofVerificationContext__(lastRoundInInterval)
	} else {
		verificationContext, err = gatherVerificationContextUsingBlockHeaders(sp, lastRoundInInterval)
	}
	if err != nil {
		return err
	}

	if validate {
		if err = verify.ValidateStateProof(verificationContext, &tx.StateProof, atRound, &tx.Message); err != nil {
			return err
		}
	}

	sp.SetStateProofNextRound(lastRoundInInterval + basics.Round(config.Consensus[verificationContext.Version].StateProofInterval))
	return nil
}

func gatherVerificationContextUsingBlockHeaders(sp *roundCowState, lastRoundInInterval basics.Round) (*ledgercore.StateProofVerificationContext, error) {
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

	verificationContext := ledgercore.StateProofVerificationContext{
		LastAttestedRound: lastRoundInInterval,
		VotersCommitment:  votersHdr.StateProofTracking[protocol.StateProofBasic].StateProofVotersCommitment,
		OnlineTotalWeight: votersHdr.StateProofTracking[protocol.StateProofBasic].StateProofOnlineTotalWeight,
		Version:           votersHdr.CurrentProtocol,
	}
	return &verificationContext, nil
}
