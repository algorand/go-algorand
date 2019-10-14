// Copyright (C) 2019 Algorand, Inc.
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

package basics

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/protocol"
)

func TestChecksumAssetUnmarshal(t *testing.T) {
	addr := crypto.Hash([]byte("randomString"))
	asset := AssetID{Creator: Address(addr), Index: crypto.RandUint64()}

	var asset0 AssetID
	err := asset0.UnmarshalText([]byte(asset.String()))
	require.NoError(t, err)
	require.Equal(t, asset, asset0)
}

func TestAssetChecksumMalformedIndex(t *testing.T) {
	addr := crypto.Hash([]byte("randomString"))
	asset := AssetID{Creator: Address(addr), Index: crypto.RandUint64()}

	// Change it slightly
	var asset0 AssetID
	err := asset0.UnmarshalText([]byte(asset.String() + "r"))
	require.Error(t, err)
}

func TestAssetChecksumMalformedAddress(t *testing.T) {
	addr := crypto.Hash([]byte("randomString"))
	asset := AssetID{Creator: Address(addr), Index: crypto.RandUint64()}

	// Change it slightly
	var asset0 AssetID
	err := asset0.UnmarshalText([]byte("4" + asset.String()))
	require.Error(t, err)
}

func TestAssetChecksumCanonical(t *testing.T) {
	asset := "G5PM2K5RIEHHO7ZKR2ZTQDYY6DVBYOMGOFZMMNGJCW4BYNMT7HC4HTZIDU/39"
	nonCanonicalAddr := "G5PM2K5RIEHHO7ZKR2ZTQDYY6DVBYOMGOFZMMNGJCW4BYNMT7HC4HTZIDV/39"
	nonCanonicalIndex := "G5PM2K5RIEHHO7ZKR2ZTQDYY6DVBYOMGOFZMMNGJCW4BYNMT7HC4HTZIDV/0x27"
	nonCanonicalFmt := "G5PM2K5RIEHHO7ZKR2ZTQDYY6DVBYOMGOFZMMNGJCW4BYNMT7HC4HTZIDV_0x27"

	var asset0 AssetID
	err := asset0.UnmarshalText([]byte(asset))
	require.NoError(t, err)

	err = asset0.UnmarshalText([]byte(nonCanonicalAddr))
	require.Error(t, err)
	err = asset0.UnmarshalText([]byte(nonCanonicalIndex))
	require.Error(t, err)
	err = asset0.UnmarshalText([]byte(nonCanonicalFmt))
	require.Error(t, err)
}

type TestOb2 struct {
	Aaaa AssetID `codec:"aaaa,omitempty"`
}

func TestAssetMarshalUnmarshal(t *testing.T) {
	var asset AssetID
	crypto.RandBytes(asset.Creator[:])
	asset.Index = crypto.RandUint64()
	testob := TestOb2{Aaaa: asset}
	data := protocol.EncodeJSON(testob)
	var nob TestOb2
	err := protocol.DecodeJSON(data, &nob)
	require.NoError(t, err)
	require.Equal(t, testob, nob)
}
