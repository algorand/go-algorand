// Copyright (C) 2019-2021 Algorand, Inc.
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

package merklekeystore

import (
	"errors"
)

var errRoundMultipleOfInterval = errors.New("the round should be a multiple of the interval")
var errRoundFirstValid = errors.New("the round cannot be less than firstValid")
var errIntervalZero = errors.New("the interval should not be zero")
var errRoundNotZero = errors.New("the round should not be zero")

func checkKeystoreParams(firstValid, round, interval uint64) error {
	if interval == 0 {
		return errIntervalZero
	}
	if round == 0 {
		return errRoundNotZero
	}
	if round%interval != 0 {
		return errRoundMultipleOfInterval
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
