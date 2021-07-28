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

func roundToIndex(firstValid, currentRound, divisor uint64) uint64 {
	return currentRound/divisor - ((firstValid - 1) / divisor) - 1
}

func numkeys(lastValid, firstValid, divisor uint64) int {
	return int((lastValid - firstValid) / divisor)
}

func indexToRound(firstValid, divisor, pos uint64) uint64 {
	return (((firstValid - 1) / divisor) + 1 + pos) * divisor
}

//
// first <= round <= last : error

// (round - first) % k
// i  = round/k - ((firstRound - 1) / k) -1
