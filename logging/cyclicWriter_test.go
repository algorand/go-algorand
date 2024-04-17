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

package logging

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/algorand/go-algorand/test/partitiontest"
	"github.com/stretchr/testify/require"
)

func testCyclicWrite(t *testing.T, liveFileName, archiveFileName string) {
	t.Helper()

	defer os.Remove(liveFileName)
	defer os.Remove(archiveFileName)

	space := 1024
	limit := uint64(space)
	cyclicWriter := MakeCyclicFileWriter(liveFileName, archiveFileName, limit, 0)

	firstWrite := make([]byte, space, space)
	for i := 0; i < space; i++ {
		firstWrite[i] = 'A'
	}
	n, err := cyclicWriter.Write(firstWrite)
	require.NoError(t, err)
	require.Equal(t, len(firstWrite), n)

	secondWrite := []byte{'B'}
	n, err = cyclicWriter.Write(secondWrite)
	require.NoError(t, err)
	require.Equal(t, len(secondWrite), n)

	liveData, err := os.ReadFile(liveFileName)
	require.NoError(t, err)
	require.Len(t, liveData, len(secondWrite))
	require.Equal(t, byte('B'), liveData[0])

	oldData, err := os.ReadFile(archiveFileName)
	require.NoError(t, err)
	require.Len(t, oldData, space)
	for i := 0; i < space; i++ {
		require.Equal(t, byte('A'), oldData[i])
	}
}

func TestCyclicWrite(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	tmpDir := t.TempDir()

	liveFileName := filepath.Join(tmpDir, "live.test")
	archiveFileName := filepath.Join(tmpDir, "archive.test")

	testCyclicWrite(t, liveFileName, archiveFileName)
}

func execCommand(t *testing.T, cmdAndArsg ...string) {
	t.Helper()

	cmd := exec.Command(cmdAndArsg[0], cmdAndArsg[1:]...)
	var errOutput strings.Builder
	cmd.Stderr = &errOutput
	err := cmd.Run()
	require.NoError(t, err, errOutput.String())
}

func TestCyclicWriteAcrossFilesystems(t *testing.T) {
	partitiontest.PartitionTest(t)

	isLinux := strings.HasPrefix(runtime.GOOS, "linux")

	// Skip unless CIRCLECI or TEST_MOUNT_TMPFS is set, and we are on a linux system
	if !isLinux || (os.Getenv("CIRCLECI") == "" && os.Getenv("TEST_MOUNT_TMPFS") == "") {
		t.Skip("This test must be run on a linux system with administrator privileges")
	}

	mountDir := t.TempDir()
	execCommand(t, "sudo", "mount", "-t", "tmpfs", "-o", "size=2K", "tmpfs", mountDir)

	defer execCommand(t, "sudo", "umount", mountDir)

	liveFileName := filepath.Join(t.TempDir(), "live.test")
	archiveFileName := filepath.Join(mountDir, "archive.test")

	testCyclicWrite(t, liveFileName, archiveFileName)
}
