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
	"os"
	"testing"

	"github.com/algorand/go-algorand/cmd/util/datadir"
	"github.com/algorand/go-algorand/test/partitiontest"
	"github.com/stretchr/testify/require"
)

func TestEnsureDataDirReturnsWhenDataDirIsProvided(t *testing.T) { // nolint:paralleltest // Sets shared OS environment variable.
	partitiontest.PartitionTest(t)
	expectedDir := "~/.algorand"
	os.Setenv("ALGORAND_DATA", expectedDir)
	actualDir := datadir.EnsureFirstDataDir()
	require.Equal(t, expectedDir, actualDir)
}

func TestEnsureDataDirReturnsWhenWorkDirIsProvided(t *testing.T) { // nolint:paralleltest // Sets shared OS environment variable.
	partitiontest.PartitionTest(t)
	expectedDir, err := os.Getwd()
	if err != nil {
		reportErrorf("Error getting work dir: %s", err)
	}
	datadir.DataDirs[0] = "."
	actualDir := datadir.EnsureFirstDataDir()
	require.Equal(t, expectedDir, actualDir)
}

func TestEnsureDataDirReturnsWhenRelPath1IsProvided(t *testing.T) { // nolint:paralleltest // Sets shared OS environment variable.
	partitiontest.PartitionTest(t)
	expectedDir, err := os.Getwd()
	if err != nil {
		reportErrorf("Error getting work dir: %s", err)
	}
	datadir.DataDirs[0] = "./../goal"
	actualDir := datadir.EnsureFirstDataDir()
	require.Equal(t, expectedDir, actualDir)
}

func TestEnsureDataDirReturnsWhenRelPath2IsProvided(t *testing.T) { // nolint:paralleltest // Sets shared OS environment variable.
	partitiontest.PartitionTest(t)
	expectedDir, err := os.Getwd()
	if err != nil {
		reportErrorf("Error getting work dir: %s", err)
	}
	datadir.DataDirs[0] = "../goal"
	actualDir := datadir.EnsureFirstDataDir()
	require.Equal(t, expectedDir, actualDir)
}

func TestEnsureDataDirReturnsWhenRelPath3IsProvided(t *testing.T) { // nolint:paralleltest // Sets shared OS environment variable.
	partitiontest.PartitionTest(t)
	expectedDir, err := os.Getwd()
	if err != nil {
		reportErrorf("Error getting work dir: %s", err)
	}
	datadir.DataDirs[0] = "../../cmd/goal"
	actualDir := datadir.EnsureFirstDataDir()
	require.Equal(t, expectedDir, actualDir)
}
