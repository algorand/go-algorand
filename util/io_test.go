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

package util

import (
	"os"
	"os/exec"
	"path"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/algorand/go-algorand/test/partitiontest"
)

func TestIsEmpty(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	testPath := path.Join(t.TempDir(), "this", "is", "a", "long", "path")
	err := os.MkdirAll(testPath, os.ModePerm)
	assert.NoError(t, err)
	defer os.RemoveAll(testPath)
	assert.True(t, IsEmpty(testPath))

	_, err = os.Create(path.Join(testPath, "file.txt"))
	assert.NoError(t, err)
	assert.False(t, IsEmpty(testPath))
}

func testMoveFile(t *testing.T, src, dst string) {
	t.Helper()

	require.NoFileExists(t, src)
	require.NoFileExists(t, dst)

	defer os.Remove(src)
	defer os.Remove(dst)

	f, err := os.Create(src)
	require.NoError(t, err)

	_, err = f.WriteString("test file contents")
	require.NoError(t, err)
	require.NoError(t, f.Close())

	err = MoveFile(src, dst)
	require.NoError(t, err)

	require.FileExists(t, dst)
	require.NoFileExists(t, src)

	dstContents, err := os.ReadFile(dst)
	require.NoError(t, err)
	assert.Equal(t, "test file contents", string(dstContents))
}

func TestMoveFile(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	tmpDir := t.TempDir()

	src := path.Join(tmpDir, "src.txt")
	dst := path.Join(tmpDir, "dst.txt")
	testMoveFile(t, src, dst)
}

func TestMoveFileAcrossFilesystems(t *testing.T) {
	partitiontest.PartitionTest(t)

	t.Skip("This is a manual test that must be run on a linux system")

	os.Mkdir("/mnt/tmpfs", os.ModePerm)
	defer os.Remove("/mnt/tmpfs")

	err := exec.Command("mount", "-t", "tmpfs", "-o", "size=1K", "tmpfs", "/mnt/tmpfs").Run()
	require.NoError(t, err)
	defer exec.Command("umount", "/mnt/tmpfs").Run()

	src := path.Join(t.TempDir(), "src.txt")
	dst := "/mnt/tmpfs/dst.txt"

	testMoveFile(t, src, dst)
}
