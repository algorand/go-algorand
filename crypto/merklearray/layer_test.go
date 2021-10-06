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

package merklearray

import (
	"testing"

	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/test/partitiontest"
	"github.com/stretchr/testify/require"
)

func TestLayerHash(t *testing.T) {
	partitiontest.PartitionTest(t)

	var p = pair{make([]byte, crypto.Sha512_256Size), make([]byte, crypto.Sha512_256Size)}
	crypto.RandBytes(p.l[:])
	crypto.RandBytes(p.r[:])
	hsh, _ := crypto.HashFactory{HashType: crypto.Sha512_256}.NewHash()

	require.Equal(t, crypto.GenereicHashObj(hsh, &p), crypto.HashBytes(hsh, p.Marshal()))
}
