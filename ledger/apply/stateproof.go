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
)

// StateProof applies the StateProof transaction and by setting the next StateProof round
func StateProof(tx transactions.StateProofTxnFields, atRound basics.Round, cs StateProofs, validate bool) error {
	latestRoundInInterval := tx.StateProofIntervalLatestRound
	spType := tx.StateProofType
	stateProof := tx.StateProof
	stateProofMsg := tx.Message

	if spType != protocol.StateProofBasic {
		return fmt.Errorf("applyStateProof type %d not supported", spType)
	}

	nextStateProofRnd := cs.StateProofNext()

	latestRoundHdr, err := cs.BlockHdr(latestRoundInInterval)
	if err != nil {
		return err
	}

	proto := config.Consensus[latestRoundHdr.CurrentProtocol]

	if validate {
		votersRnd := latestRoundInInterval.SubSaturate(basics.Round(proto.StateProofInterval))
		votersHdr, err := cs.BlockHdr(votersRnd)
		if err != nil {
			return err
		}

		err = cs.ValidateStateProof(latestRoundHdr, stateProof, votersHdr, nextStateProofRnd, atRound, stateProofMsg)
		if err != nil {
			return err
		}
	}

	cs.SetStateProofNext(latestRoundInInterval + basics.Round(proto.StateProofInterval))
	return nil
}
