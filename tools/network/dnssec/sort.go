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

package dnssec

import (
	"math/rand"
	"net"
	"sort"
)

type srvRecArray []*net.SRV

func (a srvRecArray) Len() int {
	return len(a)
}

func (a srvRecArray) Less(i, j int) bool {
	return a[i].Priority < a[j].Priority || a[i].Priority == a[j].Priority && a[i].Weight < a[j].Weight
}

func (a srvRecArray) Swap(i, j int) {
	a[i], a[j] = a[j], a[i]
}

// randomize SRV records by weight within the same priority with indices [start, end)
// https://tools.ietf.org/html/rfc2782
func (a srvRecArray) randomize(start, end int) {
	// Compute the sum of the weights of those RRs
	sum := 0
	for i := start; i < end; i++ {
		sum += int(a[i].Weight)
	}
	for sum > 0 && end-start > 0 {
		// Then choose a uniform random number between 0 and the sum computed (inclusive)
		num := rand.Intn(sum + 1)
		// And select the RR whose running sum value is the first in the selected order
		// which is greater than or equal to the random number selected.
		rSum := 0
		for i := start; i < end; i++ {
			rSum += int(a[i].Weight)
			if rSum >= num {
				// Remove this SRV RR from the set of the unordered SRV RRs
				a[start], a[i] = a[i], a[start]
				break
			}
		}
		// And apply the described algorithm to the unordered SRV RRs to select the next target host.
		sum -= int(a[start].Weight)
		start++
	}
}

func (a srvRecArray) sortAndRand() {
	sort.Sort(a)
	i := 0
	for j := 1; j < len(a); j++ {
		if a[i].Priority != a[j].Priority {
			a.randomize(i, j)
			i = j
		}
	}
	a.randomize(i, len(a))
}
