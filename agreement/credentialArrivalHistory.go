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

package agreement

import (
	"sort"
	"time"
)

// credentialArrivalHistory maintains a circular buffer of time.Duration samples.
type credentialArrivalHistory struct {
	history  []time.Duration
	writePtr int
	full     bool
}

func newCredentialArrivalHistory(size int) *credentialArrivalHistory {
	history := credentialArrivalHistory{history: make([]time.Duration, size)}
	history.reset()
	return &history
}

// store saves a new sample into the circular buffer.
// If the buffer is full, it overwrites the oldest sample.
func (history *credentialArrivalHistory) store(sample time.Duration) {
	history.history[history.writePtr] = sample
	history.writePtr++
	if history.writePtr == cap(history.history) {
		history.full = true
		history.writePtr = 0
	}
}

func (history *credentialArrivalHistory) reset() {
	history.writePtr = 0
	history.full = len(history.history) == 0
}

// isFull checks if the circular buffer has been fully populated at least once.
func (history *credentialArrivalHistory) isFull() bool {
	if history == nil {
		return false
	}
	return history.full
}

func (history *credentialArrivalHistory) orderStatistics(idx int) time.Duration {
	// if history.history is long, then we could optimize this function to use
	// the linear time order statistics algorithm.
	sortedArrivals := make([]time.Duration, len(history.history))
	copy(sortedArrivals[:], history.history[:])
	sort.Slice(sortedArrivals, func(i, j int) bool { return sortedArrivals[i] < sortedArrivals[j] })
	return sortedArrivals[idx]
}
