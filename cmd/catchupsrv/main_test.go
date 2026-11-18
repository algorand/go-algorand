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
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/algorand/go-algorand/test/partitiontest"
)

func TestReadBlockFile(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	dir := t.TempDir()
	block := []byte("block data")
	blockPath := filepath.Join(dir, "v1", "test-v1", "block", blockToPath(1000))
	require.NoError(t, os.MkdirAll(filepath.Dir(blockPath), 0700))
	require.NoError(t, os.WriteFile(blockPath, block, 0600))

	data, err := readBlockFile(dir, "1", "test-v1", 1000)
	require.NoError(t, err)
	require.Equal(t, block, data)

	outside := t.TempDir()
	outsideBlockDir := filepath.Join(outside, "block")
	outsideBlockPath := filepath.Join(outsideBlockDir, blockToPath(1000))
	outsideData := []byte("outside data")
	require.NoError(t, os.MkdirAll(filepath.Dir(outsideBlockPath), 0700))
	require.NoError(t, os.WriteFile(outsideBlockPath, outsideData, 0600))

	_, err = readBlockFile(dir, "1", "../../"+filepath.Base(outside), 1000)
	var pathErr *os.PathError
	require.ErrorAs(t, err, &pathErr)

	// Backslashes are separators on Windows and literal filename characters
	// on other platforms. Mux accepts them within a single genesisID segment.
	genesisID := `..\..\` + filepath.Base(outside)
	rel := filepath.Join("v1", genesisID, "block", blockToPath(1000))
	if runtime.GOOS == "windows" {
		require.False(t, filepath.IsLocal(rel))
		_, err = readBlockFile(dir, "1", genesisID, 1000)
		require.ErrorIs(t, err, os.ErrNotExist)
	} else {
		require.True(t, filepath.IsLocal(rel))
		literalPath := filepath.Join(dir, rel)
		require.NoError(t, os.MkdirAll(filepath.Dir(literalPath), 0700))
		require.NoError(t, os.WriteFile(literalPath, block, 0600))
		data, err = readBlockFile(dir, "1", genesisID, 1000)
		require.NoError(t, err)
		require.Equal(t, block, data)
	}

	for _, tc := range []struct {
		name     string
		target   string
		want     []byte
		relative bool
	}{
		{"relative", outsideBlockDir, outsideData, true},
		{"absolute", outsideBlockDir, outsideData, false},
		{"absolute-inside", filepath.Join(dir, "v1", "test-v1", "block"), block, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			linkDir := filepath.Join(dir, "v1", tc.name)
			require.NoError(t, os.MkdirAll(linkDir, 0700))
			target := tc.target
			if tc.relative {
				var err error
				target, err = filepath.Rel(linkDir, target)
				require.NoError(t, err)
			}
			if err := os.Symlink(target, filepath.Join(linkDir, "block")); err != nil {
				t.Skipf("symlinks unavailable: %v", err)
			}
			data, err := readBlockFile(dir, "1", tc.name, 1000)
			require.NoError(t, err)
			require.Equal(t, tc.want, data)
		})
	}
}
