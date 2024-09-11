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
	"path/filepath"
	"testing"

	"github.com/algorand/go-algorand/test/partitiontest"
	"github.com/stretchr/testify/require"
)

func abs(t *testing.T, path string) string {
	t.Helper()
	absPath, err := filepath.Abs(path)
	require.NoError(t, err)
	return absPath
}

func TestDeterminePathToSourceFromSourceMap(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	testCases := []struct {
		name       string
		sourceFile string
		outFile    string

		expectedPath string
	}{
		{
			name:         "same directory",
			sourceFile:   filepath.FromSlash("data/program.teal"),
			outFile:      filepath.FromSlash("data/program.teal.tok"),
			expectedPath: "program.teal",
		},
		{
			name:         "output one level up",
			sourceFile:   filepath.FromSlash("data/program.teal"),
			outFile:      filepath.FromSlash("data/output/program.teal.tok"),
			expectedPath: filepath.FromSlash("../program.teal"),
		},
		{
			name:         "output one level down",
			sourceFile:   filepath.FromSlash("data/program.teal"),
			outFile:      "program.teal.tok",
			expectedPath: filepath.FromSlash("data/program.teal"),
		},
		{
			name:         "input stdin",
			sourceFile:   stdinFileNameValue,
			outFile:      "program.teal.tok",
			expectedPath: "<stdin>",
		},
		{
			name:         "output stdout",
			sourceFile:   filepath.FromSlash("data/program.teal"),
			outFile:      stdoutFilenameValue,
			expectedPath: abs(t, filepath.FromSlash("data/program.teal")),
		},
	}

	for _, tc := range testCases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			sources := []string{tc.sourceFile}
			if tc.sourceFile != stdinFileNameValue {
				sources = append(sources, abs(t, tc.sourceFile))
			}
			outs := []string{tc.outFile}
			if tc.outFile != stdoutFilenameValue {
				outs = append(outs, abs(t, tc.outFile))
			}

			for sourceIndex, source := range sources {
				for outIndex, out := range outs {
					actualPath, err := determinePathToSourceFromSourceMap(source, out)
					require.NoError(t, err, "sourceIndex: %d, outIndex: %d", sourceIndex, outIndex)
					require.Equal(t, tc.expectedPath, actualPath, "sourceIndex: %d, outIndex: %d", sourceIndex, outIndex)
				}
			}
		})
	}
}
