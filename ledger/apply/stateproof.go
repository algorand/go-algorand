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
	"fmt"
	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/transactions"
	"github.com/algorand/go-algorand/protocol"
	"github.com/algorand/go-algorand/stateproof/verify"
)

// StateProof applies the StateProof transaction and setting the next StateProof round
func StateProof(tx transactions.StateProofTxnFields, atRound basics.Round, sp StateProofs, validate bool) error {
	spType := tx.StateProofType
	if spType != protocol.StateProofBasic {
		return fmt.Errorf("applyStateProof type %d not supported", spType)
	}

	nextStateProofRnd := sp.GetStateProofNextRound()

	latestRoundInInterval := tx.StateProofIntervalLastRound
	latestRoundHdr, err := sp.BlockHdr(latestRoundInInterval)
	if err != nil {
		return err
	}

	proto := config.Consensus[latestRoundHdr.CurrentProtocol]

	if validate {
		votersRnd := latestRoundInInterval.SubSaturate(basics.Round(proto.StateProofInterval))
		votersHdr, err := sp.BlockHdr(votersRnd)
		if err != nil {
			return err
		}

		err = verify.ValidateStateProof(&latestRoundHdr, &tx.StateProof, &votersHdr, nextStateProofRnd, atRound, &tx.Message)
		if err != nil {
			return err
		}
	}

	sp.SetStateProofNextRound(latestRoundInInterval + basics.Round(proto.StateProofInterval))
	return nil
}
