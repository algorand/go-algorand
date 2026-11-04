// Copyright (C) 2019-2026 Algorand Foundation Ltd.
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

package committee

import (
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/algorand/go-algorand/protocol"
	"github.com/algorand/go-algorand/test/partitiontest"
)

func TestEmptyEncoding(t *testing.T) {
	partitiontest.PartitionTest(t)

	var c Credential
	require.Equal(t, 1, len(protocol.Encode(&c)))
}

func TestSeedFormatsAsHex(t *testing.T) {
	partitiontest.PartitionTest(t)

	var s Seed
	s[0], s[1] = 0x01, 0xab
	want := "01ab" + strings.Repeat("00", 30)
	require.Equal(t, want, fmt.Sprintf("%v", s))
	require.Equal(t, want, fmt.Sprintf("%s", s))
}
