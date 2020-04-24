// Copyright (C) 2019-2020 Algorand, Inc.
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
	"strings"
	"testing"

	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/transactions"
	"github.com/algorand/go-algorand/protocol"
	"github.com/stretchr/testify/require"
)

var txnSample string = `{
	"sig": "+FQBnfGQMNxzwW85WjpSKfOYoEKqzTChhJ+h2WYEx9C8Zt5THdKvHLd3IkPO/usubboFG/0Wcvb8C5Ps1h+IBQ==",
	"txn": {
	  "amt": 1000,
	  "close": "IDUTJEUIEVSMXTU4LGTJWZ2UE2E6TIODUKU6UW3FU3UKIQQ77RLUBBBFLA",
	  "fee": 1176,
	  "fv": 12466,
	  "gen": "devnet-v33.0",
	  "gh": "JgsgCaCTqIaLeVhyL6XlRu3n7Rfk2FxMeK+wRSaQ7dI=",
	  "lv": 13466,
	  "note": "6gAVR0Nsv5Y=",
	  "rcv": "PNWOET7LLOWMBMLE4KOCELCX6X3D3Q4H2Q4QJASYIEOF7YIPPQBG3YQ5YI",
	  "snd": "47YPQTIGQEO7T4Y4RWDYWEKV6RTR2UNBQXBABEEGM72ESWDQNCQ52OPASU",
	  "type": "pay"
	}
  }
`

func TestTxnJSONInput(t *testing.T) {
	a := require.New(t)

	dp := DebugParams{
		TxnBlob: []byte(txnSample),
	}

	txnGroup, _, err := txnGroupFromParams(&dp)
	a.NoError(err)
	a.Equal(1, len(txnGroup))
	a.Equal(basics.MicroAlgos{Raw: 1176}, txnGroup[0].Txn.Fee)

	dp.TxnBlob = []byte("[" + strings.Join([]string{txnSample, txnSample}, ",") + "]")
	txnGroup, _, err = txnGroupFromParams(&dp)
	a.NoError(err)
	a.Equal(2, len(txnGroup))
	a.Equal(basics.MicroAlgos{Raw: 1176}, txnGroup[0].Txn.Fee)
	a.Equal(basics.MicroAlgos{Raw: 1000}, txnGroup[1].Txn.Amount)
}

func TestTxnMessagePackInput(t *testing.T) {
	a := require.New(t)

	var txn transactions.SignedTxn
	err := protocol.DecodeJSON([]byte(txnSample), &txn)
	a.NoError(err)

	blob := protocol.EncodeMsgp(&txn)
	dp := DebugParams{
		TxnBlob: blob,
	}

	txnGroup, _, err := txnGroupFromParams(&dp)
	a.NoError(err)
	a.Equal(1, len(txnGroup))
	a.Equal(basics.MicroAlgos{Raw: 1176}, txnGroup[0].Txn.Fee)

	dp.TxnBlob = append(blob, blob...)
	txnGroup, _, err = txnGroupFromParams(&dp)
	a.NoError(err)
	a.Equal(2, len(txnGroup))
	a.Equal(basics.MicroAlgos{Raw: 1176}, txnGroup[0].Txn.Fee)
	a.Equal(basics.MicroAlgos{Raw: 1000}, txnGroup[1].Txn.Amount)
}

var balanceSample string = `{
	"addr": "47YPQTIGQEO7T4Y4RWDYWEKV6RTR2UNBQXBABEEGM72ESWDQNCQ52OPASU",
	"onl": 1,
	"algo": 500000000,
	"apar": {
		"50": {
			"an": "asset",
			"t": 100,
			"un": "tok"
		}
	},
	"asset": {
		"50": {
			"a": 10
		}
	},
	"appl": {
		"100": {
			"hsch": {
				"nbs": 3,
				"nui": 2
			},
			"tkv": {
				"lkeybyte": {
					"tb": "local",
					"tt": 1
				},
				"lkeyint": {
					"tt": 2,
					"ui": 1
				}
			}
		}
	},
	"appp": {
		"100": {
			"approv": "AQE=",
			"gs": {
				"gkeyint": {
					"tt": 2,
					"ui": 2
				}
			},
			"gsch": {
				"nbs": 1,
				"nui": 1
			},
			"lsch": {
				"nbs": 3,
				"nui": 2
			}
		}
	}
}`

func makeSampleBalanceRecord(addr basics.Address, assetIdx basics.AssetIndex, appIdx basics.AppIndex) basics.BalanceRecord {
	var br basics.BalanceRecord
	br.Addr = addr

	br.MicroAlgos = basics.MicroAlgos{Raw: 500000000}
	br.Status = basics.Status(1)
	br.AssetParams = map[basics.AssetIndex]basics.AssetParams{
		assetIdx: basics.AssetParams{
			Total:     100,
			UnitName:  "tok",
			AssetName: "asset",
		},
	}
	br.Assets = map[basics.AssetIndex]basics.AssetHolding{
		assetIdx: basics.AssetHolding{
			Amount: 10,
		},
	}
	br.AppLocalStates = map[basics.AppIndex]basics.AppLocalState{
		appIdx: basics.AppLocalState{
			Schema: basics.StateSchema{
				NumUint:      2,
				NumByteSlice: 3,
			},
			KeyValue: basics.TealKeyValue{
				"lkeyint": {
					Type: basics.TealType(basics.TealUintType),
					Uint: 1,
				},
				"lkeybyte": {
					Type:  basics.TealType(basics.TealBytesType),
					Bytes: "local",
				},
			},
		},
	}
	br.AppParams = map[basics.AppIndex]basics.AppParams{
		appIdx: basics.AppParams{
			ApprovalProgram: []byte{1, 1},
			LocalStateSchema: basics.StateSchema{
				NumUint:      2,
				NumByteSlice: 3,
			},
			GlobalStateSchema: basics.StateSchema{
				NumUint:      1,
				NumByteSlice: 1,
			},
			GlobalState: basics.TealKeyValue{
				"gkeyint": {
					Type: basics.TealType(basics.TealUintType),
					Uint: 2,
				},
				"gkeybyte": {
					Type:  basics.TealType(basics.TealBytesType),
					Bytes: "global",
				},
			},
		},
	}
	return br
}

func makeSampleSerializedBalanceRecord(addr basics.Address, toJSON bool) []byte {
	br := makeSampleBalanceRecord(addr, 50, 100)
	if toJSON {
		return protocol.EncodeJSON(&br)
	}
	return protocol.EncodeMsgp(&br)
}

func TestBalanceJSONInput(t *testing.T) {
	a := require.New(t)

	addr, err := basics.UnmarshalChecksumAddress("47YPQTIGQEO7T4Y4RWDYWEKV6RTR2UNBQXBABEEGM72ESWDQNCQ52OPASU")
	a.NoError(err)

	dp := DebugParams{
		BalanceBlob: []byte(balanceSample),
	}
	balances, err := balanceRecordsFromParams(&dp)
	a.NoError(err)
	a.Equal(1, len(balances))
	a.Equal(addr, balances[0].Addr)

	dp.BalanceBlob = []byte("[" + strings.Join([]string{balanceSample, balanceSample}, ",") + "]")
	balances, err = balanceRecordsFromParams(&dp)
	a.NoError(err)
	a.Equal(2, len(balances))
	a.Equal(addr, balances[0].Addr)
	a.Equal(basics.MicroAlgos{Raw: 500000000}, balances[1].MicroAlgos)
}

func TestBalanceMessagePackInput(t *testing.T) {
	a := require.New(t)
	addr, err := basics.UnmarshalChecksumAddress("47YPQTIGQEO7T4Y4RWDYWEKV6RTR2UNBQXBABEEGM72ESWDQNCQ52OPASU")
	a.NoError(err)

	var br basics.BalanceRecord
	err = protocol.DecodeJSON([]byte(balanceSample), &br)
	a.NoError(err)

	blob := protocol.EncodeMsgp(&br)
	dp := DebugParams{
		BalanceBlob: blob,
	}

	balances, err := balanceRecordsFromParams(&dp)
	a.NoError(err)
	a.Equal(1, len(balances))
	a.Equal(addr, balances[0].Addr)

	dp.BalanceBlob = append(blob, blob...)
	balances, err = balanceRecordsFromParams(&dp)
	a.NoError(err)
	a.Equal(2, len(balances))
	a.Equal(addr, balances[0].Addr)
	a.Equal(basics.MicroAlgos{Raw: 500000000}, balances[1].MicroAlgos)
}
