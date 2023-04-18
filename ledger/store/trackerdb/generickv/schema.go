// Copyright (C) 2019-2023 Algorand, Inc.
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

package generickv

import (
	"encoding/binary"
	"encoding/hex"

	"github.com/algorand/go-algorand/data/basics"
)

const (
	kvPrefixAccount              = "account"
	kvPrefixAccountBalance       = "account_balance"
	kvPrefixResource             = "resource"
	kvPrefixAppKv                = "appkv"
	kvPrefixCreatorIndex         = "creator"
	kvPrefixOnlineAccount        = "online_account_base"
	kvPrefixOnlineAccountBalance = "online_account_balance"
	kvRoundKey                   = "global_round"
	kvSchemaVersionKey           = "global_schema_version"
	kvTotalsKey                  = "global_total"
	kvTxTail                     = "txtail"
	kvOnlineAccountRoundParams   = "online_account_round_params"
)

// return the big-endian binary encoding of a uint64
func bigEndianUint64(v uint64) []byte {
	ret := make([]byte, 8)
	binary.BigEndian.PutUint64(ret, v)
	return ret
}

// return the big-endian binary encoding of a uint32
func bigEndianUint32(v uint32) []byte {
	ret := make([]byte, 4)
	binary.BigEndian.PutUint32(ret, v)
	return ret
}

// accountKey: 4-byte prefix + 32-byte address
func accountKey(address basics.Address) []byte {
	ret := []byte(kvPrefixAccount)
	ret = append(ret, "-"...)
	ret = append(ret, hex.EncodeToString(address[:])...)
	return ret
}

// accountBalanceKey: 4-byte prefix + 8-byte big-endian uint64 + 32-byte address
func accountBalanceKey(normBalance uint64, address basics.Address) []byte {
	ret := []byte(kvPrefixAccountBalance)
	ret = append(ret, "-"...)
	ret = append(ret, bigEndianUint64(normBalance)...)
	ret = append(ret, "-"...)
	ret = append(ret, address[:]...)
	return ret
}

// resourceKey: 4-byte prefix + 32-byte address + 8-byte big-endian uint64
func resourceKey(address basics.Address, aidx basics.CreatableIndex) []byte {
	ret := []byte(kvPrefixResource)
	ret = append(ret, "-"...)
	ret = append(ret, hex.EncodeToString(address[:])...)
	ret = append(ret, "-"...)
	ret = append(ret, bigEndianUint64(uint64(aidx))...)
	return ret
}

func resourceAddrOnlyPartialKey(address basics.Address) []byte {
	ret := []byte(kvPrefixResource)
	ret = append(ret, "-"...)
	ret = append(ret, hex.EncodeToString(address[:])...)
	ret = append(ret, "-"...)
	return ret
}

func appKvKey(key string) []byte {
	ret := []byte(kvPrefixAppKv)
	ret = append(ret, "-"...)
	ret = append(ret, key...)
	return ret
}

func creatableKey(cidx basics.CreatableIndex) []byte {
	ret := []byte(kvPrefixCreatorIndex)
	ret = append(ret, "-"...)
	ret = append(ret, bigEndianUint64(uint64(cidx))...)
	return ret
}

func onlineAccountKey(address basics.Address, round basics.Round) []byte {
	ret := []byte(kvPrefixOnlineAccount)
	ret = append(ret, "-"...)
	ret = append(ret, address[:]...)
	ret = append(ret, "-"...)
	ret = append(ret, bigEndianUint64(uint64(round))...)
	return ret
}

func onlineAccountOnlyPartialKey(address basics.Address) []byte {
	ret := []byte(kvPrefixOnlineAccount)
	ret = append(ret, "-"...)
	ret = append(ret, address[:]...)
	return ret
}

// TODO: use basics.Round
func onlineAccountBalanceKey(round uint64, normBalance uint64, address basics.Address) []byte {
	ret := []byte(kvPrefixOnlineAccountBalance)
	ret = append(ret, "-"...)
	ret = append(ret, bigEndianUint64(round)...)
	ret = append(ret, "-"...)
	ret = append(ret, bigEndianUint64(normBalance)...)
	ret = append(ret, "-"...)
	ret = append(ret, address[:]...)
	return ret
}

func onlineAccountBalanceOnlyPartialKey(round basics.Round) []byte {
	ret := []byte(kvPrefixOnlineAccountBalance)
	ret = append(ret, "-"...)
	ret = append(ret, bigEndianUint64(uint64(round))...)
	return ret
}

func roundKey() []byte {
	ret := []byte(kvRoundKey)
	return ret
}

func schemaVersionKey() []byte {
	ret := []byte(kvSchemaVersionKey)
	return ret
}

func totalsKey(catchpointStaging bool) []byte {
	ret := []byte(kvTotalsKey)
	ret = append(ret, "-"...)
	if catchpointStaging {
		ret = append(ret, "staging"...)
	} else {
		ret = append(ret, "live"...)
	}
	return ret
}

func txTailKey(rnd basics.Round) []byte {
	ret := []byte(kvTxTail)
	ret = append(ret, "-"...)
	ret = append(ret, bigEndianUint64(uint64(rnd))...)
	return ret
}

func onlineAccountRoundParamsKey(rnd basics.Round) []byte {
	ret := []byte(kvOnlineAccountRoundParams)
	ret = append(ret, "-"...)
	ret = append(ret, bigEndianUint64(uint64(rnd))...)
	return ret
}
