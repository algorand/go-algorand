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

package network

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/algorand/go-algorand/crypto"
)

func TestLimitedReaderSlurper(t *testing.T) {
	for _, arraySize := range []uint64{30000, 90000, 200000} {
		// create a random bytes array.
		bytesBlob := make([]byte, arraySize)
		crypto.RandBytes(bytesBlob[:])
		for baseBufferSize := uint64(0); baseBufferSize < uint64(len(bytesBlob)); baseBufferSize += 731 {
			for _, maxSize := range []uint64{arraySize - 10000, arraySize, arraySize + 10000} {
				buffer := bytes.NewBuffer(bytesBlob)
				reader := MakeLimitedReaderSlurper(baseBufferSize, maxSize)
				err := reader.Read(buffer)
				if maxSize <= uint64(len(bytesBlob)) {
					require.Equal(t, ErrIncomingMsgTooLarge, err)
					continue
				}

				require.NoError(t, err)
				bytes := reader.Bytes()
				require.Equal(t, bytesBlob, bytes)
			}
		}
	}
}
