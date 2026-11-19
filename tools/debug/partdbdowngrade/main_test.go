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

package main

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/gofrs/flock"
	"github.com/stretchr/testify/require"

	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/data/account"
	"github.com/algorand/go-algorand/logging"
	"github.com/algorand/go-algorand/test/partitiontest"
	"github.com/algorand/go-algorand/util/db"
)

// makeDataDir creates a data directory with a genesis.json and an empty
// registry, as algod would leave it, in each named genesis directory.
func makeDataDir(t *testing.T, genesisDirs ...string) string {
	dataDir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dataDir, config.GenesisJSONFile), []byte("{}"), 0o600))
	for _, dir := range genesisDirs {
		require.NoError(t, os.Mkdir(filepath.Join(dataDir, dir), 0o700))
		pair, err := db.OpenErasablePair(filepath.Join(dataDir, dir, config.ParticipationRegistryFilename))
		require.NoError(t, err)
		registry, err := account.MakeParticipationRegistry(pair, logging.TestingLog(t))
		require.NoError(t, err)
		registry.Close()
	}
	return dataDir
}

func TestRun(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	// the registry is found in the genesis directory, converted, and left
	// alone the second time
	dataDir := makeDataDir(t, "net-v1")
	var out bytes.Buffer
	require.NoError(t, run(dataDir, "", true, &out))
	require.Contains(t, out.String(), "nothing was changed")
	out.Reset()
	require.NoError(t, run(dataDir, "", false, &out))
	require.Contains(t, out.String(), "converted to 1")
	out.Reset()
	require.NoError(t, run(dataDir, "", false, &out))
	require.Contains(t, out.String(), "already has schema version 1")

	// a running algod holds algod.lock
	dataDir = makeDataDir(t, "net-v1")
	lock := flock.New(filepath.Join(dataDir, "algod.lock"))
	locked, err := lock.TryLock()
	require.NoError(t, err)
	require.True(t, locked)
	require.ErrorContains(t, run(dataDir, "", false, &out), "algod is running")
	require.NoError(t, lock.Unlock())

	// more than one registry needs -f
	dataDir = makeDataDir(t, "net-v1", "othernet-v1")
	require.ErrorContains(t, run(dataDir, "", false, &out), "name one with -f")
	out.Reset()
	require.NoError(t, run(dataDir, filepath.Join(dataDir, "othernet-v1", config.ParticipationRegistryFilename), false, &out))
	require.Contains(t, out.String(), "converted to 1")

	// a directory without genesis.json is refused
	require.ErrorContains(t, run(t.TempDir(), "", false, &out), "not an algod data directory")
}
