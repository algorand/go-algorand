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

package participation

import (
	"github.com/algorand/go-algorand/data/account"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/test/partitiontest"

	"github.com/stretchr/testify/require"

	"testing"
)

func TestGenParticipationKeysTo_Install(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	testcases := []struct {
		name      string
		outDir    string
		installed bool
	}{
		{
			name:      "install",
			installed: true,
		},
		{
			name:      "do not install",
			outDir:    t.TempDir(),
			installed: false,
		},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			var err error
			var called bool
			installFunc := func(keyPath string) error {
				called = true
				return nil
			}
			var addr basics.Address
			addr[1] = 1

			_, _, err = GenParticipationKeysTo(addr.String(), 1000, 2000, 0, tc.outDir, installFunc)
			require.NoError(t, err)
			require.Equal(t, tc.installed, called, "The install function should only be called when outDir is not set.")
		})
	}
}

func TestGenParticipationKeysTo_DefaultKeyDilution(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	var addr basics.Address
	addr[1] = 1
	const first = 1000
	const last = 2000

	testcases := []struct {
		name     string
		dilution uint64
		expected uint64
	}{
		{
			name:     "default",
			dilution: 0,
			expected: account.DefaultKeyDilution(first, last),
		}, {
			name:     "override",
			dilution: 5,
			expected: 5,
		},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			part, _, err := GenParticipationKeysTo(addr.String(), first, last, tc.dilution, t.TempDir(), nil)
			require.NoError(t, err)
			require.Equal(t, tc.expected, part.KeyDilution)
		})
	}
}

func TestBadInput(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	_, _, err := GenParticipationKeysTo("", 0, 0, 0, "", nil)
	require.ErrorContains(t, err, "must provide an install function when installing keys")
}
