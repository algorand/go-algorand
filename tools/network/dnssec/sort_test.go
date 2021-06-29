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
	"net"
	"testing"

	"github.com/algorand/go-algorand/testPartitioning"
	"github.com/stretchr/testify/require"
)

func TestSrvSort(t *testing.T) {
	testPartitioning.PartitionTest(t)

	a := require.New(t)

	arr := make([]*net.SRV, 0, 7)
	arr = append(arr, &net.SRV{Priority: 4, Weight: 1})
	arr = append(arr, &net.SRV{Priority: 3, Weight: 1})
	arr = append(arr, &net.SRV{Priority: 1, Weight: 200})
	arr = append(arr, &net.SRV{Priority: 1, Weight: 1})
	arr = append(arr, &net.SRV{Priority: 1, Weight: 1})
	arr = append(arr, &net.SRV{Priority: 1, Weight: 1})
	arr = append(arr, &net.SRV{Priority: 1, Weight: 1})

	srvRecArray(arr).sortAndRand()
	a.Equal(net.SRV{Priority: 1, Weight: 200}, *arr[0])
	a.Equal(net.SRV{Priority: 1, Weight: 1}, *arr[1])
	a.Equal(net.SRV{Priority: 1, Weight: 1}, *arr[2])
	a.Equal(net.SRV{Priority: 1, Weight: 1}, *arr[3])
	a.Equal(net.SRV{Priority: 1, Weight: 1}, *arr[4])
	a.Equal(net.SRV{Priority: 3, Weight: 1}, *arr[5])
	a.Equal(net.SRV{Priority: 4, Weight: 1}, *arr[6])
}
