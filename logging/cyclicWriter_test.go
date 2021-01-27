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

package logging

import (
	"io/ioutil"
	"os"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestCyclicWrite(t *testing.T) {
	liveFileName := "live.test"
	archiveFileName := "archive.test"
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

	liveData, err := ioutil.ReadFile(liveFileName)
	require.NoError(t, err)
	require.Len(t, liveData, len(secondWrite))
	require.Equal(t, byte('B'), liveData[0])

	oldData, err := ioutil.ReadFile(archiveFileName)
	require.NoError(t, err)
	require.Len(t, oldData, space)
	for i := 0; i < space; i++ {
		require.Equal(t, byte('A'), oldData[i])
	}
}
