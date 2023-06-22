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

package dnssec

import (
	"net"
	"testing"

	"github.com/algorand/go-algorand/test/partitiontest"
	"github.com/stretchr/testify/require"
)

func TestSrvSort(t *testing.T) {
	partitiontest.PartitionTest(t)

	a := require.New(t)

	arr := make([]*net.SRV, 0, 7)
	arr = append(arr, &net.SRV{Priority: 4, Weight: 1})
	arr = append(arr, &net.SRV{Priority: 3, Weight: 1})
	arr = append(arr, &net.SRV{Priority: 1, Weight: 200})
	arr = append(arr, &net.SRV{Priority: 1, Weight: 1})
	arr = append(arr, &net.SRV{Priority: 1, Weight: 1})
	arr = append(arr, &net.SRV{Priority: 1, Weight: 1})
	arr = append(arr, &net.SRV{Priority: 1, Weight: 1})

	retryCounter := 0
retry:
	srvRecArray(arr).sortAndRand()
	if (*arr[0] != net.SRV{Priority: 1, Weight: 200}) {
		// there is a small change that random number from 0 to 204 would 0 or 1
		// so the first element would be with weight of 1 and not 200
		// if this happens, we will try again
		if retryCounter > 3 {
			a.Fail("randomization failed")
		}
		retryCounter++
		goto retry
	}
	a.Equal(net.SRV{Priority: 1, Weight: 200}, *arr[0])
	a.Equal(net.SRV{Priority: 1, Weight: 1}, *arr[1])
	a.Equal(net.SRV{Priority: 1, Weight: 1}, *arr[2])
	a.Equal(net.SRV{Priority: 1, Weight: 1}, *arr[3])
	a.Equal(net.SRV{Priority: 1, Weight: 1}, *arr[4])
	a.Equal(net.SRV{Priority: 3, Weight: 1}, *arr[5])
	a.Equal(net.SRV{Priority: 4, Weight: 1}, *arr[6])
}
