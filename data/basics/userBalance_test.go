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

package basics

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/algorand/go-algorand/protocol"
	"github.com/algorand/go-algorand/test/partitiontest"
)

func TestEmptyEncoding(t *testing.T) {
	partitiontest.PartitionTest(t)

	var ub BalanceRecord
	require.Equal(t, 1, len(protocol.Encode(&ub)))
}

func TestAppIndexHashing(t *testing.T) {
	partitiontest.PartitionTest(t)

	i := AppIndex(12)
	prefix, buf := i.ToBeHashed()
	require.Equal(t, protocol.HashID("appID"), prefix)
	require.Equal(t, []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0c}, buf)

	i = AppIndex(12 << 16)
	prefix, buf = i.ToBeHashed()
	require.Equal(t, protocol.HashID("appID"), prefix)
	require.Equal(t, []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x0c, 0x00, 0x00}, buf)

	// test value created with:
	// python -c "import algosdk.encoding as e; print(e.encode_address(e.checksum(b'appID'+($APPID).to_bytes(8, 'big'))))"
	i = AppIndex(77)
	require.Equal(t, "PCYUFPA2ZTOYWTP43MX2MOX2OWAIAXUDNC2WFCXAGMRUZ3DYD6BWFDL5YM", i.Address().String())
}
