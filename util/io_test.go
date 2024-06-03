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
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/algorand/go-algorand/test/partitiontest"
)

func TestIsEmpty(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	testPath := filepath.Join(t.TempDir(), "this", "is", "a", "long", "path")
	err := os.MkdirAll(testPath, os.ModePerm)
	assert.NoError(t, err)
	defer os.RemoveAll(testPath)
	assert.True(t, IsEmpty(testPath))

	_, err = os.Create(filepath.Join(testPath, "file.txt"))
	assert.NoError(t, err)
	assert.False(t, IsEmpty(testPath))
}

func testMoveFileSimple(t *testing.T, src, dst string) {
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

	src := filepath.Join(tmpDir, "src.txt")
	dst := filepath.Join(tmpDir, "dst.txt")
	testMoveFileSimple(t, src, dst)
}

func execCommand(t *testing.T, cmdAndArsg ...string) {
	t.Helper()

	cmd := exec.Command(cmdAndArsg[0], cmdAndArsg[1:]...)
	var errOutput strings.Builder
	cmd.Stderr = &errOutput
	err := cmd.Run()
	require.NoError(t, err, errOutput.String())
}

func TestMoveFileAcrossFilesystems(t *testing.T) {
	partitiontest.PartitionTest(t)

	isLinux := strings.HasPrefix(runtime.GOOS, "linux")

	// Skip unless CIRCLECI or TEST_MOUNT_TMPFS is set, and we are on a linux system
	if !isLinux || (os.Getenv("CIRCLECI") == "" && os.Getenv("TEST_MOUNT_TMPFS") == "") {
		t.Skip("This test must be run on a linux system with administrator privileges")
	}

	mountDir := t.TempDir()
	execCommand(t, "sudo", "mount", "-t", "tmpfs", "-o", "size=1K", "tmpfs", mountDir)

	defer execCommand(t, "sudo", "umount", mountDir)

	src := filepath.Join(t.TempDir(), "src.txt")
	dst := filepath.Join(mountDir, "dst.txt")

	testMoveFileSimple(t, src, dst)
}

func TestMoveFileSourceDoesNotExist(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	tmpDir := t.TempDir()

	src := filepath.Join(tmpDir, "src.txt")
	dst := filepath.Join(tmpDir, "dst.txt")

	err := MoveFile(src, dst)
	var pathError *os.PathError
	require.ErrorAs(t, err, &pathError)
	require.Equal(t, "lstat", pathError.Op)
	require.Equal(t, src, pathError.Path)
}

func TestMoveFileSourceIsASymlink(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	tmpDir := t.TempDir()

	root := filepath.Join(tmpDir, "root.txt")
	src := filepath.Join(tmpDir, "src.txt")
	dst := filepath.Join(tmpDir, "dst.txt")

	_, err := os.Create(root)
	require.NoError(t, err)

	err = os.Symlink(root, src)
	require.NoError(t, err)

	// os.Rename should work in this case
	err = MoveFile(src, dst)
	require.NoError(t, err)

	// Undo the move
	require.NoError(t, MoveFile(dst, src))

	// But our moveFileByCopying should fail, since we haven't implemented this case
	err = moveFileByCopying(src, dst)
	require.ErrorContains(t, err, fmt.Sprintf("cannot move source file '%s': it is not a regular file", src))
}

func TestMoveFileSourceAndDestinationAreSame(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	tmpDir := t.TempDir()
	require.NoError(t, os.Mkdir(filepath.Join(tmpDir, "folder"), os.ModePerm))

	src := filepath.Join(tmpDir, "src.txt")
	dst := src[:len(src)-len("src.txt")] + "folder/../src.txt"

	// dst refers to the same file as src, but with a different path
	require.NotEqual(t, src, dst)
	require.Equal(t, src, filepath.Clean(dst))

	_, err := os.Create(src)
	require.NoError(t, err)

	// os.Rename can handle this case, but our moveFileByCopying should fail
	err = moveFileByCopying(src, dst)
	require.ErrorContains(t, err, fmt.Sprintf("cannot move source file '%s' to destination '%s': source and destination are the same file", src, dst))
}

func TestMoveFileDestinationIsADirectory(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	tmpDir := t.TempDir()

	src := filepath.Join(tmpDir, "src.txt")
	dst := filepath.Join(tmpDir, "dst.txt")

	_, err := os.Create(src)
	require.NoError(t, err)

	err = os.Mkdir(dst, os.ModePerm)
	require.NoError(t, err)

	err = MoveFile(src, dst)
	require.ErrorContains(t, err, fmt.Sprintf("cannot move source file '%s' to destination '%s': destination is a directory", src, dst))
}
