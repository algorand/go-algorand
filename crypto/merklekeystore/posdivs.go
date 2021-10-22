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

func roundToIndex(firstValid, currentRound, interval uint64) uint64 {
	if currentRound < firstValid || interval == 0 {
		return 0
	}
	rofi := roundOfFirstIndex(firstValid, interval)
	if currentRound < rofi {
		return 0
	}
	return ((currentRound - rofi) + interval - 1) / interval
}

func indexToRound(firstValid, interval, pos uint64) uint64 {
	if interval == 0 {
		return 0
	}
	return roundOfFirstIndex(firstValid, interval) + pos*interval
}

func roundOfFirstIndex(firstValid, interval uint64) uint64 {
	return ((firstValid+interval-1)/interval)*interval
}
