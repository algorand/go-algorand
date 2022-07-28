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

package apply

import (
	"errors"
	"fmt"
	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/transactions"
	"github.com/algorand/go-algorand/logging"
	"github.com/algorand/go-algorand/protocol"
	"github.com/algorand/go-algorand/stateproof/verify"
)

var (
	errStateProofNotEnabled             = errors.New("state proofs are not enabled")
	errNotAtRightMultiple               = errors.New("state proof is not in a valid round multiple")
	errInvalidVotersRound               = errors.New("invalid voters round")
	errExpectedDifferentStateProofRound = errors.New("expected different state proof round")
	errInsufficientWeight               = errors.New("insufficient state proof weight")
	errStateProofTypeNotSupported       = errors.New("state proof type is not supported")
)

// StateProof applies the StateProof transaction and setting the next StateProof round
func StateProof(tx transactions.StateProofTxnFields, atRound basics.Round, sp StateProofs, validate bool) error {
	spType := tx.StateProofType
	if spType != protocol.StateProofBasic {
		return fmt.Errorf("%w %d", errStateProofTypeNotSupported, spType)
	}

	lastRoundInInterval := tx.StateProofIntervalLastRound
	lastRoundInIntervalHdr, err := sp.BlockHdr(lastRoundInInterval)
	if err != nil {
		return err
	}

	proto := config.Consensus[lastRoundInIntervalHdr.CurrentProtocol]

	if validate {
		if proto.StateProofInterval == 0 {
			return fmt.Errorf("rounds = %d: %w", proto.StateProofInterval, errStateProofNotEnabled)
		}

		nextStateProofRnd := sp.GetStateProofNextRound()
		if nextStateProofRnd == 0 || nextStateProofRnd != lastRoundInIntervalHdr.Round {
			return fmt.Errorf("expecting state proof for %d, but new state proof is for %d :%w",
				nextStateProofRnd, lastRoundInIntervalHdr.Round, errExpectedDifferentStateProofRound)
		}

		if lastRoundInIntervalHdr.Round%basics.Round(proto.StateProofInterval) != 0 {
			return fmt.Errorf("state proof at %d for non-multiple of %d: %w", lastRoundInIntervalHdr.Round, proto.StateProofInterval, errNotAtRightMultiple)
		}

		votersRound := lastRoundInIntervalHdr.Round.SubSaturate(basics.Round(proto.StateProofInterval))
		votersHdr, err := sp.BlockHdr(votersRound)
		if err != nil {
			return err
		}

		acceptableWeight := verify.AcceptableStateProofWeight(votersHdr, atRound, logging.Base())
		if tx.StateProof.SignedWeight < acceptableWeight {
			return fmt.Errorf("insufficient weight at round %d: %d < %d: %w",
				atRound, tx.StateProof.SignedWeight, acceptableWeight, errInsufficientWeight)
		}
	}

	sp.SetStateProofNextRound(lastRoundInInterval + basics.Round(proto.StateProofInterval))
	return nil
}
