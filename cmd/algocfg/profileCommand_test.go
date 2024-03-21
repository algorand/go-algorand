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

package main

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/algorand/go-algorand/test/partitiontest"
)

func Test_getConfigForArg(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	t.Run("invalid config test", func(t *testing.T) {
		t.Parallel()
		_, err := getConfigForArg("invalid")

		for name := range profileNames {
			require.ErrorContains(t, err, name)
		}

	})

	t.Run("valid config test", func(t *testing.T) {
		t.Parallel()
		cfg, err := getConfigForArg("conduit")
		require.NoError(t, err)
		require.True(t, cfg.EnableFollowMode)
	})

	t.Run("valid config test development", func(t *testing.T) {
		t.Parallel()
		cfg, err := getConfigForArg("development")
		require.NoError(t, err)
		require.True(t, cfg.DisableAPIAuth)
	})

	t.Run("valid config test archival node", func(t *testing.T) {
		t.Parallel()
		cfg, err := getConfigForArg("archival")
		require.NoError(t, err)
		require.True(t, cfg.Archival)
		require.True(t, cfg.EnableLedgerService)
		require.True(t, cfg.EnableBlockService)
		require.Equal(t, ":4160", cfg.NetAddress)
		require.False(t, cfg.EnableGossipService)
	})
}
