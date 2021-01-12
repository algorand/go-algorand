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
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/protocol"
)

func BenchmarkGenerateMessageDigest(b *testing.B) {
	for i := 0; i < b.N; i++ {
		msgData := crypto.Hash([]byte{byte(i & 0xff), byte((i >> 8) & 0xff), byte((i >> 16) & 0xff), byte((i >> 24) & 0xff)})
		generateMessageDigest(protocol.AgreementVoteTag, msgData[:])
	}
}

func TestHashingFunctionChange(t *testing.T) {
	for i := 0; i < 10; i++ {
		tag := make([]byte, 0, 2)
		nonce := make([]byte, 0, 8)
		msg := make([]byte, 0, 250)
		crypto.RandBytes(tag[:])
		crypto.RandBytes(nonce[:])
		crypto.RandBytes(msg[:])

		// calculate digest using the old method.
		hasher := crypto.NewHash()
		hasher.Write(nonce[:])
		hasher.Write([]byte(tag))
		hasher.Write(msg)
		var oldDigest crypto.Digest
		hasher.Sum(oldDigest[:0])

		// calculate digest using the new method.
		newDigest := crypto.Hash(append(append(nonce[:], []byte(tag)...), msg...))

		// compare the two.
		require.Equal(t, oldDigest, newDigest)
	}

	for i := 0; i < 10; i++ {
		tag := make([]byte, 0, 2)
		nonce := make([]byte, 0, 8)
		msg := make([]byte, 0, 250)
		crypto.RandBytes(tag[:])
		crypto.RandBytes(nonce[:])
		crypto.RandBytes(msg[:])

		// calculate digest using the old method.
		hasher := crypto.NewHash()
		hasher.Write([]byte(tag))
		hasher.Write(msg)
		var oldDigest crypto.Digest
		hasher.Sum(oldDigest[:0])

		// calculate digest using the new method.
		newDigest := crypto.Hash(append([]byte(tag), msg...))

		// compare the two.
		require.Equal(t, oldDigest, newDigest)
	}
}
