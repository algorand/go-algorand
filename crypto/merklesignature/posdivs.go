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

package merklesignature

import (
	"errors"
)

var errRoundFirstValid = errors.New("the round cannot be less than firstValid")

func checkMerkleSignatureSchemeParams(firstValid, round, keyLifetime uint64) error {
	if keyLifetime == 0 {
		return ErrKeyLifetimeIsZero
	}
	if round < firstValid {
		return errRoundFirstValid
	}
	return nil
}

func roundToIndex(firstValid, currentRound, interval uint64) uint64 {
	rofi := roundOfFirstIndex(firstValid, interval)
	return (currentRound - rofi) / interval
}

func indexToRound(firstValid, interval, pos uint64) uint64 {
	return roundOfFirstIndex(firstValid, interval) + pos*interval
}

func roundOfFirstIndex(firstValid, interval uint64) uint64 {
	return ((firstValid + interval - 1) / interval) * interval
}

// firstRoundInKeyLifetime calculates the round of the valid key for a given round by lowering to the closest KeyLiftime divisor.
// It is implicitly assumed that round is larger than keyLifetime, as an MSS key for round 0 is not valid.
// A key lifetime of 0 is invalid.
func firstRoundInKeyLifetime(round, keyLifetime uint64) uint64 {
	return round - (round % keyLifetime)
}
