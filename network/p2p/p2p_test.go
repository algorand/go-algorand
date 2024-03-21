// Copyright (C) 2019-2024 Algorand, Inc.
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

package p2p

import (
	"fmt"
	"testing"

	"github.com/algorand/go-algorand/test/partitiontest"
	"github.com/stretchr/testify/require"
)

// Tests the helper function netAddressToListenAddress which converts
// a config value netAddress to a multiaddress usable by libp2p.
func TestNetAddressToListenAddress(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	tests := []struct {
		input  string
		output string
		err    bool
	}{
		{
			input:  "192.168.1.1:8080",
			output: "/ip4/192.168.1.1/tcp/8080",
			err:    false,
		},
		{
			input:  ":8080",
			output: "/ip4/0.0.0.0/tcp/8080",
			err:    false,
		},
		{
			input:  "192.168.1.1:",
			output: "",
			err:    true,
		},
		{
			input:  "192.168.1.1",
			output: "",
			err:    true,
		},
		{
			input:  "192.168.1.1:8080:9090",
			output: "",
			err:    true,
		},
	}

	for _, test := range tests { //nolint:paralleltest
		t.Run(fmt.Sprintf("input: %s", test.input), func(t *testing.T) {
			res, err := netAddressToListenAddress(test.input)
			if test.err {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
				require.Equal(t, test.output, res)
			}
		})
	}
}
