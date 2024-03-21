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
	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/bookkeeping"
	"github.com/algorand/go-algorand/protocol"
)

// GetOldestExpectedStateProof returns the lowest round for which the node should create a state proof.
func GetOldestExpectedStateProof(latestHeader *bookkeeping.BlockHeader) basics.Round {
	proto := config.Consensus[latestHeader.CurrentProtocol]
	if proto.StateProofInterval == 0 {
		return 0
	}

	recentRoundOnRecoveryPeriod := basics.Round(uint64(latestHeader.Round) - uint64(latestHeader.Round)%proto.StateProofInterval)
	oldestRoundOnRecoveryPeriod := recentRoundOnRecoveryPeriod.SubSaturate(basics.Round(proto.StateProofInterval * (proto.StateProofMaxRecoveryIntervals)))

	nextStateproofRound := latestHeader.StateProofTracking[protocol.StateProofBasic].StateProofNextRound

	if nextStateproofRound > oldestRoundOnRecoveryPeriod {
		return nextStateproofRound
	}
	return oldestRoundOnRecoveryPeriod
}
