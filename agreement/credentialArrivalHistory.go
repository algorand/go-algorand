// Copyright (C) 2019-2025 Algorand, Inc.
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

package agreement

import (
	"slices"
	"time"
)

// credentialArrivalHistory maintains a circular buffer of time.Duration samples.
type credentialArrivalHistory struct {
	history  []time.Duration
	writePtr int
	full     bool
}

func makeCredentialArrivalHistory(size int) credentialArrivalHistory {
	if size < 0 {
		panic("can't create CredentialArrivalHistory with negative size")
	}
	history := credentialArrivalHistory{history: make([]time.Duration, size)}
	history.reset()
	return history
}

// store saves a new sample into the circular buffer.
// If the buffer is full, it overwrites the oldest sample.
func (history *credentialArrivalHistory) store(sample time.Duration) {
	if len(history.history) == 0 {
		return
	}

	history.history[history.writePtr] = sample
	history.writePtr++
	if history.writePtr == len(history.history) {
		history.full = true
		history.writePtr = 0
	}
}

// reset marks the history buffer as empty
func (history *credentialArrivalHistory) reset() {
	history.writePtr = 0
	history.full = false
}

// isFull checks if the circular buffer has been fully populated at least once.
func (history *credentialArrivalHistory) isFull() bool {
	return history.full
}

// orderStatistics returns the idx'th time duration in the sorted history array.
// It assumes that history is full and the idx is within the array bounds, and
// panics if either of these assumptions doesn't hold.
func (history *credentialArrivalHistory) orderStatistics(idx int) time.Duration {
	if !history.isFull() {
		panic("history not full")
	}
	if idx < 0 || idx >= len(history.history) {
		panic("index out of bounds")
	}

	// if history.history is long, then we could optimize this function to use
	// the linear time order statistics algorithm.
	sortedArrivals := make([]time.Duration, len(history.history))
	copy(sortedArrivals[:], history.history[:])
	slices.Sort(sortedArrivals)
	return sortedArrivals[idx]
}
