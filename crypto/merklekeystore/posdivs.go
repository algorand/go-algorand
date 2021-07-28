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
