package agreement

import (
	"sort"
	"time"
)

type credentialArrivalHistory struct {
	history  []time.Duration
	writePtr int
	full     bool
}

func newCredentialArrivalHistory(size int) *credentialArrivalHistory {
	history := credentialArrivalHistory{history: make([]time.Duration, size, size)}
	history.reset()
	return &history
}

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
