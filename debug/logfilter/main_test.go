// Copyright (C) 2019-2021 Algorand, Inc.
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

// logfilter buffer go test output and make sure to limit the output to only the error-related stuff.
package main

import (
	"bytes"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestLogFilterExamples(t *testing.T) {
	// iterate on all the example files in the local directroy.
	exampleFiles := []string{}
	filepath.Walk(".", func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			return nil
		}
		if strings.Contains(info.Name(), "example") && strings.HasSuffix(info.Name(), ".in") {
			exampleFiles = append(exampleFiles, path)
		}
		return nil
	})
	for _, exampleFileName := range exampleFiles {
		// load the expected result file.
		expectedOutFile := strings.Replace(exampleFileName, ".in", ".out.expected", 1)
		expectedOutBytes, err := ioutil.ReadFile(expectedOutFile)
		require.NoError(t, err)

		inFile, err := os.Open(exampleFileName)
		require.NoError(t, err)
		writingBuffer := bytes.NewBuffer(nil)
		errCode := logFilter(inFile, writingBuffer)
		require.Zero(t, errCode)
		require.Equal(t, string(expectedOutBytes), writingBuffer.String())
	}
}
