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

package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strconv"
	"strings"
	"testing"

	"github.com/algorand/go-algorand/config"
	v2 "github.com/algorand/go-algorand/daemon/algod/api/server/v2"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/transactions"
	"github.com/algorand/go-algorand/data/transactions/logic"
	"github.com/algorand/go-algorand/ledger/apply"
	"github.com/algorand/go-algorand/protocol"
	"github.com/algorand/go-algorand/test/partitiontest"
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
	partitiontest.PartitionTest(t)
	a := require.New(t)

	dp := DebugParams{
		TxnBlob: []byte(txnSample),
	}

	txnGroup, err := txnGroupFromParams(&dp)
	a.NoError(err)
	a.Equal(1, len(txnGroup))
	a.Equal(basics.MicroAlgos{Raw: 1176}, txnGroup[0].Txn.Fee)

	dp.TxnBlob = []byte("[" + strings.Join([]string{txnSample, txnSample}, ",") + "]")
	txnGroup, err = txnGroupFromParams(&dp)
	a.NoError(err)
	a.Equal(2, len(txnGroup))
	a.Equal(basics.MicroAlgos{Raw: 1176}, txnGroup[0].Txn.Fee)
	a.Equal(basics.MicroAlgos{Raw: 1000}, txnGroup[1].Txn.Amount)
}

func TestTxnMessagePackInput(t *testing.T) {
	partitiontest.PartitionTest(t)
	a := require.New(t)

	var txn transactions.SignedTxn
	err := protocol.DecodeJSON([]byte(txnSample), &txn)
	a.NoError(err)

	blob := protocol.EncodeMsgp(&txn)
	dp := DebugParams{
		TxnBlob: blob,
	}

	txnGroup, err := txnGroupFromParams(&dp)
	a.NoError(err)
	a.Equal(1, len(txnGroup))
	a.Equal(basics.MicroAlgos{Raw: 1176}, txnGroup[0].Txn.Fee)

	dp.TxnBlob = append(blob, blob...)
	txnGroup, err = txnGroupFromParams(&dp)
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
			"clearp": "AQE=",
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
		assetIdx: {
			Total:     100,
			UnitName:  "tok",
			AssetName: "asset",
			Manager:   addr,
			Reserve:   addr,
			Freeze:    addr,
			Clawback:  addr,
			URL:       "http://127.0.0.1/8000",
		},
	}
	br.Assets = map[basics.AssetIndex]basics.AssetHolding{
		assetIdx: {
			Amount: 10,
		},
	}
	br.AppLocalStates = map[basics.AppIndex]basics.AppLocalState{
		appIdx: {
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
		appIdx: {
			ApprovalProgram:   []byte{1},
			ClearStateProgram: []byte{1, 1},
			StateSchemas: basics.StateSchemas{
				LocalStateSchema: basics.StateSchema{
					NumUint:      2,
					NumByteSlice: 3,
				},
				GlobalStateSchema: basics.StateSchema{
					NumUint:      1,
					NumByteSlice: 2,
				},
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

func TestBalanceJSONInput(t *testing.T) {
	partitiontest.PartitionTest(t)
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
	partitiontest.PartitionTest(t)
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

func TestDebugEnvironment(t *testing.T) {
	partitiontest.PartitionTest(t)
	a := require.New(t)

	sender, err := basics.UnmarshalChecksumAddress("47YPQTIGQEO7T4Y4RWDYWEKV6RTR2UNBQXBABEEGM72ESWDQNCQ52OPASU")
	a.NoError(err)

	receiver, err := basics.UnmarshalChecksumAddress("PNWOET7LLOWMBMLE4KOCELCX6X3D3Q4H2Q4QJASYIEOF7YIPPQBG3YQ5YI")
	a.NoError(err)

	addr1, err := basics.UnmarshalChecksumAddress("OC6IROKUJ7YCU5NV76AZJEDKYQG33V2CJ7HAPVQ4ENTAGMLIOINSQ6EKGE")
	a.NoError(err)

	addr2, err := basics.UnmarshalChecksumAddress("YYKRMERAFXMXCDWMBNR6BUUWQXDCUR53FPUGXLUYS7VNASRTJW2ENQ7BMQ")
	a.NoError(err)

	// make balance records
	assetIdx := basics.AssetIndex(50)
	appIdx := basics.AppIndex(100)
	appIdx1 := basics.AppIndex(200)
	appIdx2 := basics.AppIndex(300)
	brs := makeSampleBalanceRecord(sender, assetIdx, appIdx)
	brr := makeSampleBalanceRecord(receiver, assetIdx, appIdx)
	bra1 := makeSampleBalanceRecord(addr1, assetIdx, appIdx1)
	bra2 := makeSampleBalanceRecord(addr2, assetIdx, appIdx2)
	// fix receiver so that it only has asset holding and app local
	delete(brr.AssetParams, assetIdx)
	delete(brr.AppParams, appIdx)
	delete(bra1.AssetParams, assetIdx)
	delete(bra2.AssetParams, assetIdx)
	balanceBlob := protocol.EncodeMsgp(&brs)
	balanceBlob = append(balanceBlob, protocol.EncodeMsgp(&brr)...)
	balanceBlob = append(balanceBlob, protocol.EncodeMsgp(&bra1)...)
	balanceBlob = append(balanceBlob, protocol.EncodeMsgp(&bra2)...)

	// make transaction group: app call + sample payment
	txn := transactions.SignedTxn{
		Txn: transactions.Transaction{
			Header: transactions.Header{
				Sender: sender,
				Fee:    basics.MicroAlgos{Raw: 1000},
				Note:   []byte{1, 2, 3},
			},
			ApplicationCallTxnFields: transactions.ApplicationCallTxnFields{
				ApplicationID:   appIdx,
				ApplicationArgs: [][]byte{[]byte("ALGO"), []byte("RAND")},
				Accounts:        []basics.Address{receiver},
				ForeignApps:     []basics.AppIndex{appIdx1},
				ForeignAssets:   []basics.AssetIndex{assetIdx},
			},
		},
	}

	txnEnc := protocol.EncodeJSON(&txn)
	txnBlob := []byte("[" + strings.Join([]string{string(txnEnc), txnSample}, ",") + "]")

	// create sample programs that checks all the environment:
	// transaction fields, global properties,
	source := `#pragma version 2
global Round
int 222
==
global LatestTimestamp
int 333
==
&&
global GroupSize
int 2
==
&&
global LogicSigVersion
int 2
>=
&&
txn NumAppArgs
int 2
==
&&
txn NumAccounts
int 1
==
&&
txna Accounts 0
addr 47YPQTIGQEO7T4Y4RWDYWEKV6RTR2UNBQXBABEEGM72ESWDQNCQ52OPASU
==
&&
txna Accounts 1
addr PNWOET7LLOWMBMLE4KOCELCX6X3D3Q4H2Q4QJASYIEOF7YIPPQBG3YQ5YI
==
&&
gtxn 1 Amount
int 1000
==
&&
// now check stateful opcodes
int 0
balance
int 500000000
==
&&
int 1
int 100
app_opted_in
int 1
==
&&
int 1
int 200
app_opted_in
int 1
!=
&&
int 1
byte 0x6c6b6579696e74 // lkeyint
app_local_get
int 1
==
&&
int 0
int 100
byte 0x6c6b657962797465 // lkeybyte
app_local_get_ex
bnz ok
err
ok:
byte 0x6c6f63616c // local
==
&&
byte 0x676b6579696e74 // gkeyint
app_global_get
int 2
==
&&
int 1 // ForeignApps index
byte 0x676b657962797465 // gkeybyte
app_global_get_ex
bnz ok2
err
ok2:
byte 0x676c6f62616c // global
==
&&

// write
int 1
byte 0x6c6b65796279746565 // lkeybytee
byte 0x6c6f63616c // local
app_local_put
byte 0x676b65796279746565 // gkeybytee
byte 0x676c6f62616c // global
app_global_put
int 1
byte 0x6c6b65796279746565 // lkeybytee
app_local_del
byte 0x676b65796279746565
app_global_del

// asssets
int 1
int 50
asset_holding_get AssetBalance
bnz ok3
err
ok3:
int 10
==
&&
int 0
asset_params_get AssetTotal
bnz ok4
err
ok4:
int 100
==
&&
`

	ds := DebugParams{
		ProgramNames:    []string{"test"},
		ProgramBlobs:    [][]byte{[]byte(source)},
		BalanceBlob:     balanceBlob,
		TxnBlob:         txnBlob,
		Proto:           string(protocol.ConsensusCurrentVersion),
		Round:           222,
		LatestTimestamp: 333,
		GroupIndex:      0,
		RunMode:         "application",
	}

	local := MakeLocalRunner(nil) // no debugger
	err = local.Setup(&ds)
	a.NoError(err)

	pass, err := local.Run()
	a.NoError(err)
	a.True(pass)

	// check relaxed - opted in for both
	source = `#pragma version 2
int 1
int 100
app_opted_in
int 1
==
int 1
int 200
app_opted_in
int 1
==
&&
`
	ds.Painless = true
	ds.ProgramBlobs = [][]byte{[]byte(source)}
	err = local.Setup(&ds)
	a.NoError(err)

	pass, err = local.Run()
	a.NoError(err)
	a.True(pass)
	ds.Painless = false

	// check ForeignApp
	source = `#pragma version 2
int 300
byte 0x676b657962797465 // gkeybyte
app_global_get_ex
bnz ok
err
ok:
byte 0x676c6f62616c // global
==
`
	ds.ProgramBlobs = [][]byte{[]byte(source)}
	err = local.Setup(&ds)
	a.NoError(err)

	pass, err = local.Run()
	a.Error(err)
	a.False(pass)
}

func TestDebugFromPrograms(t *testing.T) {
	partitiontest.PartitionTest(t)
	a := require.New(t)

	txnBlob := []byte("[" + strings.Join([]string{string(txnSample), txnSample}, ",") + "]")

	l := LocalRunner{}
	dp := DebugParams{
		ProgramNames: []string{"test"},
		ProgramBlobs: [][]byte{{1}},
		TxnBlob:      []byte(txnSample),
		GroupIndex:   1,
	}

	err := l.Setup(&dp)
	a.Error(err)
	a.Contains(err.Error(), "invalid group index 1 for a single transaction")

	dp = DebugParams{
		ProgramNames: []string{"test"},
		ProgramBlobs: [][]byte{{1}},
		TxnBlob:      txnBlob,
		GroupIndex:   3,
	}

	err = l.Setup(&dp)
	a.Error(err)
	a.Contains(err.Error(), "invalid group index 3 for a txn in a transaction group of 2")

	dp = DebugParams{
		ProgramNames: []string{"test"},
		ProgramBlobs: [][]byte{{1}},
		TxnBlob:      txnBlob,
		GroupIndex:   0,
		AppID:        100,
	}

	err = l.Setup(&dp)
	a.Error(err)
	a.Contains(err.Error(), "unknown run mode")

	dp = DebugParams{
		ProgramNames: []string{"test"},
		ProgramBlobs: [][]byte{{1}},
		TxnBlob:      txnBlob,
		GroupIndex:   0,
		RunMode:      "signature",
	}

	err = l.Setup(&dp)
	a.NoError(err)
	a.Equal(1, len(l.runs))
	a.Equal(uint64(0), l.runs[0].groupIndex)
	a.Nil(l.runs[0].ba)
	a.Equal(modeLogicsig, l.runs[0].mode)
	a.Empty(l.runs[0].aidx)

	dp = DebugParams{
		ProgramNames: []string{"test", "test"},
		ProgramBlobs: [][]byte{{1}, {1}},
		TxnBlob:      txnBlob,
		GroupIndex:   0,
		RunMode:      "signature",
	}

	err = l.Setup(&dp)
	a.NoError(err)
	a.Equal(2, len(l.runs))
	a.Equal(uint64(0), l.runs[0].groupIndex)
	a.Equal(uint64(0), l.runs[1].groupIndex)
	a.Nil(l.runs[0].ba)
	a.Equal(modeLogicsig, l.runs[0].mode)
	a.Empty(l.runs[0].aidx)

	a.Nil(l.runs[1].ba)
	a.Equal(modeLogicsig, l.runs[1].mode)
	a.Empty(l.runs[1].aidx)
}

func TestRunMode(t *testing.T) {
	partitiontest.PartitionTest(t)
	a := require.New(t)

	txnBlob := []byte("[" + strings.Join([]string{string(txnSample), txnSample}, ",") + "]")
	l := LocalRunner{}

	// check run mode auto on stateful code
	dp := DebugParams{
		ProgramNames: []string{"test"},
		ProgramBlobs: [][]byte{{2, 0x20, 1, 1, 0x22, 0x22, 0x61}}, // version, intcb, int 1, int 1, app_opted_in
		TxnBlob:      txnBlob,
		GroupIndex:   0,
		RunMode:      "auto",
		AppID:        100,
	}

	err := l.Setup(&dp)
	a.NoError(err)
	a.Equal(1, len(l.runs))
	a.Equal(uint64(0), l.runs[0].groupIndex)
	a.NotNil(l.runs[0].eval)
	a.NotNil(l.runs[0].ba)
	a.Equal(modeStateful, l.runs[0].mode)
	a.Equal(basics.AppIndex(100), l.runs[0].aidx)
	a.NotEqual(
		reflect.ValueOf(logic.Eval).Pointer(),
		reflect.ValueOf(l.runs[0].eval).Pointer(),
	)

	// check run mode auto on stateless code
	dp = DebugParams{
		ProgramNames: []string{"test"},
		ProgramBlobs: [][]byte{{2, 0x20, 1, 1, 0x22}}, // version, intcb, int 1
		TxnBlob:      txnBlob,
		GroupIndex:   0,
		RunMode:      "auto",
		AppID:        100,
	}

	err = l.Setup(&dp)
	a.NoError(err)
	a.Equal(1, len(l.runs))
	a.Equal(uint64(0), l.runs[0].groupIndex)
	a.NotNil(l.runs[0].eval)
	a.Nil(l.runs[0].ba)
	a.Equal(modeLogicsig, l.runs[0].mode)
	a.Equal(basics.AppIndex(0), l.runs[0].aidx)

	// check run mode application
	dp = DebugParams{
		ProgramNames: []string{"test"},
		ProgramBlobs: [][]byte{{2, 0x20, 1, 1, 0x22, 0x22, 0x61}}, // version, intcb, int 1, int 1, app_opted_in
		TxnBlob:      txnBlob,
		GroupIndex:   0,
		RunMode:      "application",
		AppID:        100,
	}

	err = l.Setup(&dp)
	a.NoError(err)
	a.Equal(1, len(l.runs))
	a.Equal(uint64(0), l.runs[0].groupIndex)
	a.NotNil(l.runs[0].eval)
	a.NotNil(l.runs[0].ba)
	a.Equal(modeStateful, l.runs[0].mode)
	a.Equal(basics.AppIndex(100), l.runs[0].aidx)

	// check run mode signature
	dp = DebugParams{
		ProgramNames: []string{"test"},
		ProgramBlobs: [][]byte{{2, 0x20, 1, 1, 0x22}}, // version, intcb, int 1
		TxnBlob:      txnBlob,
		GroupIndex:   0,
		RunMode:      "signature",
	}

	err = l.Setup(&dp)
	a.NoError(err)
	a.Equal(1, len(l.runs))
	a.Equal(uint64(0), l.runs[0].groupIndex)
	a.NotNil(l.runs[0].eval)
	a.Nil(l.runs[0].ba)
	a.Equal(modeLogicsig, l.runs[0].mode)
	a.Equal(basics.AppIndex(0), l.runs[0].aidx)
}

func TestDebugFromTxn(t *testing.T) {
	partitiontest.PartitionTest(t)
	a := require.New(t)

	sender, err := basics.UnmarshalChecksumAddress("47YPQTIGQEO7T4Y4RWDYWEKV6RTR2UNBQXBABEEGM72ESWDQNCQ52OPASU")
	a.NoError(err)
	// make balance records
	appIdx := basics.AppIndex(100)
	brs := makeSampleBalanceRecord(sender, 0, appIdx+1)
	balanceBlob := protocol.EncodeMsgp(&brs)

	// make transaction group: app call + sample payment
	appTxn := transactions.SignedTxn{
		Txn: transactions.Transaction{
			Header: transactions.Header{
				Sender: sender,
			},
			ApplicationCallTxnFields: transactions.ApplicationCallTxnFields{
				ApplicationID: appIdx,
			},
		},
	}

	var payTxn transactions.SignedTxn
	err = protocol.DecodeJSON([]byte(txnSample), &payTxn)
	a.NoError(err)

	txnBlob := protocol.EncodeMsgp(&appTxn)
	txnBlob = append(txnBlob, protocol.EncodeMsgp(&payTxn)...)

	l := LocalRunner{}
	dp := DebugParams{
		BalanceBlob: balanceBlob,
		TxnBlob:     txnBlob,
	}

	err = l.Setup(&dp)
	a.Error(err)
	a.Contains(err.Error(), "no programs found in transactions")
	a.Equal(2, len(l.txnGroup))

	// ensure clear logic sig program is supposed to be debugged
	payTxn.Lsig.Logic = []byte{3}
	txnBlob = protocol.EncodeMsgp(&appTxn)
	txnBlob = append(txnBlob, protocol.EncodeMsgp(&payTxn)...)

	dp = DebugParams{
		BalanceBlob: balanceBlob,
		TxnBlob:     txnBlob,
		GroupIndex:  10, // must be ignored
	}

	err = l.Setup(&dp)
	a.NoError(err)
	a.Equal(1, len(l.runs))
	a.Equal(uint64(1), l.runs[0].groupIndex)
	a.NotNil(l.runs[0].eval)
	a.Equal([]byte{3}, l.runs[0].program)
	a.Nil(l.runs[0].ba)
	a.Equal(modeLogicsig, l.runs[0].mode)
	a.Equal(basics.AppIndex(0), l.runs[0].aidx)

	// ensure clear approval program is supposed to be debugged
	brs = makeSampleBalanceRecord(sender, 0, appIdx)
	balanceBlob = protocol.EncodeMsgp(&brs)

	payTxn.Lsig.Logic = nil
	appTxn.Txn.Type = protocol.ApplicationCallTx
	txnBlob = protocol.EncodeMsgp(&appTxn)
	txnBlob = append(txnBlob, protocol.EncodeMsgp(&payTxn)...)

	dp = DebugParams{
		BalanceBlob: balanceBlob,
		TxnBlob:     txnBlob,
		GroupIndex:  10, // must be ignored
	}

	err = l.Setup(&dp)
	a.NoError(err)
	a.Equal(2, len(l.txnGroup))
	a.Equal(1, len(l.runs))
	a.Equal(uint64(0), l.runs[0].groupIndex)
	a.NotNil(l.runs[0].eval)
	a.Equal([]byte{1}, l.runs[0].program)
	a.NotNil(l.runs[0].ba)
	a.Equal(modeStateful, l.runs[0].mode)
	a.NotEmpty(l.runs[0].aidx)

	// ensure clear state program is supposed to be debugged
	appTxn.Txn.Type = protocol.ApplicationCallTx
	appTxn.Txn.OnCompletion = transactions.ClearStateOC
	txnBlob = protocol.EncodeMsgp(&appTxn)
	txnBlob = append(txnBlob, protocol.EncodeMsgp(&payTxn)...)

	dp = DebugParams{
		BalanceBlob: balanceBlob,
		TxnBlob:     txnBlob,
		GroupIndex:  10, // must be ignored
	}

	err = l.Setup(&dp)
	a.NoError(err)
	a.Equal(2, len(l.txnGroup))
	a.Equal(1, len(l.runs))
	a.Equal(uint64(0), l.runs[0].groupIndex)
	a.NotNil(l.runs[0].eval)
	a.Equal([]byte{1, 1}, l.runs[0].program)
	a.NotNil(l.runs[0].ba)
	a.Equal(modeStateful, l.runs[0].mode)
	a.NotEmpty(l.runs[0].aidx)

	// check app create txn uses approval program from the txn
	appTxn.Txn.Type = protocol.ApplicationCallTx
	appTxn.Txn.OnCompletion = transactions.NoOpOC
	appTxn.Txn.ApplicationID = 0
	appTxn.Txn.ApprovalProgram = []byte{4}
	txnBlob = protocol.EncodeMsgp(&appTxn)

	dp = DebugParams{
		BalanceBlob: balanceBlob,
		TxnBlob:     txnBlob,
		GroupIndex:  10, // must be ignored
		AppID:       100,
	}

	err = l.Setup(&dp)
	a.NoError(err)
	a.Equal(1, len(l.txnGroup))
	a.Equal(1, len(l.runs))
	a.Equal(uint64(0), l.runs[0].groupIndex)
	a.NotNil(l.runs[0].eval)
	a.Equal([]byte{4}, l.runs[0].program)
	a.NotNil(l.runs[0].ba)
	a.Equal(modeStateful, l.runs[0].mode)
	a.NotEmpty(l.runs[0].aidx)

	// check error on no programs
	txnBlob = protocol.EncodeMsgp(&payTxn)
	txnBlob = append(txnBlob, protocol.EncodeMsgp(&payTxn)...)

	dp = DebugParams{
		BalanceBlob: balanceBlob,
		TxnBlob:     txnBlob,
		GroupIndex:  10, // must be ignored
	}

	err = l.Setup(&dp)
	a.Error(err)
	a.Equal(2, len(l.txnGroup))
}

func checkBalanceAdapter(
	a *require.Assertions, ba apply.Balances, sender basics.Address, receiver basics.Address,
	assetIdx basics.AssetIndex, appIdx basics.AppIndex,
) {
	ad, err := ba.Get(sender, false)
	a.NoError(err)
	a.Equal(basics.MicroAlgos{Raw: 500000000}, ad.MicroAlgos)

	holdings, ok := ad.Assets[assetIdx+1]
	a.False(ok)
	holdings, ok = ad.Assets[assetIdx]
	a.True(ok)
	a.Equal(basics.AssetHolding{Amount: 10, Frozen: false}, holdings)

	aparams, ok := ad.AssetParams[assetIdx]
	a.True(ok)
	a.Equal(uint64(100), aparams.Total)
	a.Equal("tok", aparams.UnitName)

	params, ok := ad.AppParams[appIdx+1]
	a.False(ok)
	params, ok = ad.AppParams[appIdx]
	a.True(ok)

	addr, ok, err := ba.GetCreator(basics.CreatableIndex(assetIdx), basics.AssetCreatable)
	a.NoError(err)
	a.True(ok)
	a.Equal(sender, addr)

	addr, ok, err = ba.GetCreator(basics.CreatableIndex(assetIdx+1), basics.AssetCreatable)
	a.NoError(err)
	a.False(ok)

	addr, ok, err = ba.GetCreator(basics.CreatableIndex(appIdx), basics.AppCreatable)
	a.NoError(err)
	a.True(ok)
	a.Equal(sender, addr)

	addr, ok, err = ba.GetCreator(basics.CreatableIndex(appIdx+1), basics.AppCreatable)
	a.NoError(err)
	a.False(ok)

	v, ok := params.GlobalState["gkeyint"]
	a.True(ok)
	a.Equal(uint64(2), v.Uint)

	v, ok = params.GlobalState["gkeybyte"]
	a.True(ok)
	a.Equal("global", v.Bytes)

	loc, ok := ad.AppLocalStates[appIdx+1]
	a.False(ok)
	loc, ok = ad.AppLocalStates[appIdx]
	a.True(ok)

	v, ok = loc.KeyValue["lkeyint"]
	a.True(ok)
	a.Equal(uint64(1), v.Uint)

	v, ok = loc.KeyValue["lkeybyte"]
	a.True(ok)
	a.Equal("local", v.Bytes)

	ad, err = ba.Get(receiver, false)
	a.NoError(err)
	loc, ok = ad.AppLocalStates[appIdx]
	a.False(ok)
}

func TestLocalBalanceAdapter(t *testing.T) {
	partitiontest.PartitionTest(t)
	a := require.New(t)

	sender, err := basics.UnmarshalChecksumAddress("47YPQTIGQEO7T4Y4RWDYWEKV6RTR2UNBQXBABEEGM72ESWDQNCQ52OPASU")
	a.NoError(err)
	// make balance records
	appIdx := basics.AppIndex(100)
	assetIdx := basics.AssetIndex(50)
	brs := makeSampleBalanceRecord(sender, assetIdx, appIdx)
	balanceBlob := protocol.EncodeMsgp(&brs)

	// make transaction group: app call + sample payment
	appTxn := transactions.SignedTxn{
		Txn: transactions.Transaction{
			Header: transactions.Header{
				Sender: sender,
			},
			ApplicationCallTxnFields: transactions.ApplicationCallTxnFields{
				ApplicationID: appIdx,
			},
		},
	}

	var payTxn transactions.SignedTxn
	err = protocol.DecodeJSON([]byte(txnSample), &payTxn)
	a.NoError(err)

	txnBlob := protocol.EncodeMsgp(&appTxn)
	txnBlob = append(txnBlob, protocol.EncodeMsgp(&payTxn)...)

	l := LocalRunner{}
	dp := DebugParams{
		ProgramNames:    []string{"test"},
		ProgramBlobs:    [][]byte{{1}},
		BalanceBlob:     balanceBlob,
		TxnBlob:         txnBlob,
		RunMode:         "application",
		GroupIndex:      0,
		Round:           100,
		LatestTimestamp: 333,
	}

	err = l.Setup(&dp)
	a.NoError(err)
	a.Equal(2, len(l.txnGroup))
	a.Equal(1, len(l.runs))
	a.Equal(uint64(0), l.runs[0].groupIndex)
	a.NotNil(l.runs[0].eval)
	a.Equal([]byte{1}, l.runs[0].program)
	a.NotNil(l.runs[0].ba)
	a.Equal(modeStateful, l.runs[0].mode)
	a.NotEmpty(l.runs[0].aidx)
	a.NotEqual(
		reflect.ValueOf(logic.Eval).Pointer(),
		reflect.ValueOf(l.runs[0].eval).Pointer(),
	)
	ba := l.runs[0].ba
	checkBalanceAdapter(a, ba, sender, payTxn.Txn.Receiver, assetIdx, appIdx)
}

func TestLocalBalanceAdapterIndexer(t *testing.T) {
	partitiontest.PartitionTest(t)
	a := require.New(t)

	sender, err := basics.UnmarshalChecksumAddress("47YPQTIGQEO7T4Y4RWDYWEKV6RTR2UNBQXBABEEGM72ESWDQNCQ52OPASU")
	a.NoError(err)
	// make balance records
	appIdx := basics.AppIndex(100)
	assetIdx := basics.AssetIndex(50)
	brs := makeSampleBalanceRecord(sender, assetIdx, appIdx)
	//balanceBlob := protocol.EncodeMsgp(&brs)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		accountPath := "/v2/accounts/"
		applicationPath := "/v2/applications/"
		switch {
		case strings.HasPrefix(r.URL.Path, accountPath):
			w.WriteHeader(200)
			if r.URL.Path[len(accountPath):] == brs.Addr.String() {
				account, err := v2.AccountDataToAccount(brs.Addr.String(), &brs.AccountData, map[basics.AssetIndex]string{}, 100, &config.ConsensusParams{MinBalance: 100000}, basics.MicroAlgos{Raw: 0})
				a.NoError(err)
				accountResponse := AccountIndexerResponse{Account: account, CurrentRound: 100}
				response, err := json.Marshal(accountResponse)
				a.NoError(err)
				w.Write(response)
			}
		case strings.HasPrefix(r.URL.Path, applicationPath):
			w.WriteHeader(200)
			if r.URL.Path[len(applicationPath):] == strconv.FormatUint(uint64(appIdx), 10) {
				appParams := brs.AppParams[appIdx]
				app := v2.AppParamsToApplication(sender.String(), appIdx, &appParams)
				a.NoError(err)
				applicationResponse := ApplicationIndexerResponse{Application: app, CurrentRound: 100}
				response, err := json.Marshal(applicationResponse)
				a.NoError(err)
				w.Write(response)
			}
		default:
			w.WriteHeader(404)
		}
	}))
	defer srv.Close()

	// make transaction group: app call + sample payment
	appTxn := transactions.SignedTxn{
		Txn: transactions.Transaction{
			Header: transactions.Header{
				Sender: sender,
			},
			ApplicationCallTxnFields: transactions.ApplicationCallTxnFields{
				ApplicationID: appIdx,
			},
		},
	}

	var payTxn transactions.SignedTxn
	err = protocol.DecodeJSON([]byte(txnSample), &payTxn)
	a.NoError(err)

	txnBlob := protocol.EncodeMsgp(&appTxn)
	txnBlob = append(txnBlob, protocol.EncodeMsgp(&payTxn)...)

	l := LocalRunner{}
	dp := DebugParams{
		ProgramNames:    []string{"test"},
		ProgramBlobs:    [][]byte{{1}},
		TxnBlob:         txnBlob,
		IndexerURL:      srv.URL,
		RunMode:         "application",
		GroupIndex:      0,
		Round:           100,
		LatestTimestamp: 333,
	}

	err = l.Setup(&dp)
	a.NoError(err)
	a.Equal(2, len(l.txnGroup))
	a.Equal(1, len(l.runs))
	a.Equal(uint64(0), l.runs[0].groupIndex)
	a.NotNil(l.runs[0].eval)
	a.Equal([]byte{1}, l.runs[0].program)
	a.NotNil(l.runs[0].ba)
	a.Equal(modeStateful, l.runs[0].mode)
	a.NotEmpty(l.runs[0].aidx)
	a.NotEqual(
		reflect.ValueOf(logic.Eval).Pointer(),
		reflect.ValueOf(l.runs[0].eval).Pointer(),
	)

	ba := l.runs[0].ba
	checkBalanceAdapter(a, ba, sender, payTxn.Txn.Receiver, assetIdx, appIdx)
}

func TestDebugTxSubmit(t *testing.T) {
	partitiontest.PartitionTest(t)
	a := require.New(t)

	sender, err := basics.UnmarshalChecksumAddress("47YPQTIGQEO7T4Y4RWDYWEKV6RTR2UNBQXBABEEGM72ESWDQNCQ52OPASU")
	a.NoError(err)
	app, err := basics.UnmarshalChecksumAddress("6BPQU5WNZMTO4X72A2THZCGNJNTTE7YL6AWCYSUUTZEIYMJSEPJCQQ6DQI")
	a.NoError(err)

	// make balance records
	assetIdx := basics.AssetIndex(50)
	appIdx := basics.AppIndex(100)
	brs := makeSampleBalanceRecord(sender, assetIdx, appIdx)
	bra := makeSampleBalanceRecord(app, assetIdx, appIdx)
	balanceBlob := protocol.EncodeMsgp(&brs)
	balanceBlob = append(balanceBlob, protocol.EncodeMsgp(&bra)...)

	txn := transactions.SignedTxn{
		Txn: transactions.Transaction{
			Type: protocol.ApplicationCallTx,
			Header: transactions.Header{
				Sender: sender,
				Fee:    basics.MicroAlgos{Raw: 1000},
				Note:   []byte{1, 2, 3},
			},
			ApplicationCallTxnFields: transactions.ApplicationCallTxnFields{
				ApplicationID: appIdx,
			},
		},
	}

	txnEnc := protocol.EncodeJSON(&txn)
	txnBlob := []byte("[" + strings.Join([]string{string(txnEnc), txnSample}, ",") + "]")

	source := `#pragma version 5
itxn_begin
int acfg
itxn_field TypeEnum
int 1000000
itxn_field ConfigAssetTotal
int 3
itxn_field ConfigAssetDecimals
byte "oz"
itxn_field ConfigAssetUnitName
byte "Gold"
itxn_field ConfigAssetName
byte "https://gold.rush/"
itxn_field ConfigAssetURL
byte 0x67f0cd61653bd34316160bc3f5cd3763c85b114d50d38e1f4e72c3b994411e7b
itxn_field ConfigAssetMetadataHash
itxn_submit
int 1`

	ds := DebugParams{
		ProgramNames:    []string{"test"},
		ProgramBlobs:    [][]byte{[]byte(source)},
		BalanceBlob:     balanceBlob,
		TxnBlob:         txnBlob,
		Proto:           string(protocol.ConsensusCurrentVersion),
		Round:           222,
		LatestTimestamp: 333,
		GroupIndex:      0,
		RunMode:         "application",
	}

	local := MakeLocalRunner(nil) // no debugger
	err = local.Setup(&ds)
	a.NoError(err)

	pass, err := local.Run()
	a.NoError(err)
	a.True(pass)
}

func TestDebugFeePooling(t *testing.T) {
	partitiontest.PartitionTest(t)
	a := require.New(t)

	sender, err := basics.UnmarshalChecksumAddress("47YPQTIGQEO7T4Y4RWDYWEKV6RTR2UNBQXBABEEGM72ESWDQNCQ52OPASU")
	a.NoError(err)

	source := `#pragma version 5
itxn_begin
int pay
itxn_field TypeEnum
int 0
itxn_field Amount
txn Sender
itxn_field Receiver
itxn_submit
int 1`

	ops, err := logic.AssembleString(source)
	a.NoError(err)
	prog := ops.Program

	stxn := transactions.SignedTxn{
		Txn: transactions.Transaction{
			Type: protocol.ApplicationCallTx,
			Header: transactions.Header{
				Sender: sender,
				Note:   []byte{1, 2, 3},
			},
			ApplicationCallTxnFields: transactions.ApplicationCallTxnFields{
				ApplicationID:     0,
				ApprovalProgram:   prog,
				ClearStateProgram: prog,
			},
		},
	}

	appIdx := basics.AppIndex(1)
	br := basics.BalanceRecord{
		Addr: sender,
		AccountData: basics.AccountData{
			MicroAlgos: basics.MicroAlgos{Raw: 5000000},
			AppParams: map[basics.AppIndex]basics.AppParams{
				appIdx: {
					ApprovalProgram:   prog,
					ClearStateProgram: prog,
				},
			},
		},
	}
	balanceBlob := protocol.EncodeMsgp(&br)

	// two testcase: success with enough fees and fail otherwise
	var tests = []struct {
		pass bool
		fee  uint64
	}{
		{true, 2000},
		{false, 1500},
	}
	for _, test := range tests {
		t.Run(fmt.Sprintf("fee=%d", test.fee), func(t *testing.T) {

			stxn.Txn.Fee = basics.MicroAlgos{Raw: test.fee}
			encoded := protocol.EncodeJSON(&stxn)

			ds := DebugParams{
				ProgramNames:    []string{"test"},
				BalanceBlob:     balanceBlob,
				TxnBlob:         encoded,
				Proto:           string(protocol.ConsensusCurrentVersion),
				Round:           222,
				LatestTimestamp: 333,
				GroupIndex:      0,
				RunMode:         "application",
				AppID:           uint64(appIdx),
			}

			local := MakeLocalRunner(nil)
			err = local.Setup(&ds)
			a.NoError(err)

			pass, err := local.Run()
			if test.pass {
				a.NoError(err)
				a.True(pass)
			} else {
				a.Error(err)
				a.False(pass)
			}
		})
	}
}

func TestDebugCostPooling(t *testing.T) {
	partitiontest.PartitionTest(t)
	a := require.New(t)

	sender, err := basics.UnmarshalChecksumAddress("47YPQTIGQEO7T4Y4RWDYWEKV6RTR2UNBQXBABEEGM72ESWDQNCQ52OPASU")
	a.NoError(err)

	// cost is 2000 (ecdsa_pk_recover) + 130 (keccak256) + 8 (rest opcodes)
	// needs 4 app calls to pool together
	source := `#pragma version 5
byte "hello from ethereum" // msg
keccak256
int 0 // v
byte 0x745e8f55ac6189ee89ed707c36694868e3903988fbf776c8096c45da2e60c638 // r
byte 0x30c8e4a9b5d2eb53ddc6294587dd00bed8afe2c45dd72f6b4cf752e46d5ba681 // s
ecdsa_pk_recover Secp256k1
concat // convert public key X and Y to ethereum addr
keccak256
substring 12 32
byte 0x5ce9454909639d2d17a3f753ce7d93fa0b9ab12e // addr
==
`
	ops, err := logic.AssembleString(source)
	a.NoError(err)
	prog := ops.Program

	ops, err = logic.AssembleString("#pragma version 2\nint 1")
	a.NoError(err)
	trivial := ops.Program

	stxn := transactions.SignedTxn{
		Txn: transactions.Transaction{
			Type: protocol.ApplicationCallTx,
			Header: transactions.Header{
				Sender: sender,
				Fee:    basics.MicroAlgos{Raw: 1000},
				Note:   []byte{1, 2, 3},
			},
			ApplicationCallTxnFields: transactions.ApplicationCallTxnFields{
				ApplicationID:     0,
				ApprovalProgram:   prog,
				ClearStateProgram: trivial,
			},
		},
	}

	appIdx := basics.AppIndex(1)
	trivialAppIdx := basics.AppIndex(2)
	trivialStxn := transactions.SignedTxn{
		Txn: transactions.Transaction{
			Type: protocol.ApplicationCallTx,
			Header: transactions.Header{
				Sender: sender,
				Fee:    basics.MicroAlgos{Raw: 1000},
			},
			ApplicationCallTxnFields: transactions.ApplicationCallTxnFields{
				ApplicationID: trivialAppIdx,
			},
		},
	}

	br := basics.BalanceRecord{
		Addr: sender,
		AccountData: basics.AccountData{
			MicroAlgos: basics.MicroAlgos{Raw: 5000000},
			AppParams: map[basics.AppIndex]basics.AppParams{
				appIdx: {
					ApprovalProgram:   prog,
					ClearStateProgram: trivial,
				},
				trivialAppIdx: {
					ApprovalProgram:   trivial,
					ClearStateProgram: trivial,
				},
			},
		},
	}
	balanceBlob := protocol.EncodeMsgp(&br)

	var tests = []struct {
		pass           bool
		additionalApps int
	}{
		{false, 2},
		{true, 3},
	}
	for _, test := range tests {
		t.Run(fmt.Sprintf("txn-count=%d", test.additionalApps+1), func(t *testing.T) {
			txnBlob := protocol.EncodeMsgp(&stxn)
			for i := 0; i < test.additionalApps; i++ {
				val, err := getRandomAddress()
				a.NoError(err)
				trivialStxn.Txn.Note = val[:]
				txnBlob = append(txnBlob, protocol.EncodeMsgp(&trivialStxn)...)
			}

			ds := DebugParams{
				ProgramNames:    []string{"test"},
				BalanceBlob:     balanceBlob,
				TxnBlob:         txnBlob,
				Proto:           string(protocol.ConsensusCurrentVersion),
				Round:           222,
				LatestTimestamp: 333,
				GroupIndex:      0,
				RunMode:         "application",
				AppID:           uint64(appIdx),
			}

			local := MakeLocalRunner(nil)
			err = local.Setup(&ds)
			a.NoError(err)

			pass, err := local.Run()
			if test.pass {
				a.NoError(err)
				a.True(pass)
			} else {
				a.Error(err)
				a.Contains(err.Error(), "dynamic cost budget exceeded")
				a.False(pass)
			}
		})
	}
}

func TestGroupTxnIdx(t *testing.T) {

	partitiontest.PartitionTest(t)
	a := require.New(t)

	ddrBlob := `{
		"accounts": [
		  {
			"address": "FPVVJ7N42QRVP2OWBGZ3XPTQAZFQNBYHJGZ2CJFOATAQNWFA5NWB4MPWBQ",
			"amount": 3999999999497000,
			"amount-without-pending-rewards": 3999999999497000,
			"created-apps": [
			  {
				"id": 1,
				"params": {
				  "approval-program": "BSABATEQIhJAABExEIEGEkAAByJAAAEAIkMiQ4EAQw==",
				  "clear-state-program": "BYEBQw==",
				  "creator": "FPVVJ7N42QRVP2OWBGZ3XPTQAZFQNBYHJGZ2CJFOATAQNWFA5NWB4MPWBQ"
				}
			  }
			],
			"pending-rewards": 0,
			"rewards": 0,
			"round": 2,
			"status": "Online"
		  },
		  {
			"address": "WCS6TVPJRBSARHLN2326LRU5BYVJZUKI2VJ53CAWKYYHDE455ZGKANWMGM",
			"amount": 500000,
			"amount-without-pending-rewards": 500000,
			"pending-rewards": 0,
			"rewards": 0,
			"round": 2,
			"status": "Offline"
		  }
		],
		"apps": [
		  {
			"id": 1,
			"params": {
			  "approval-program": "BSABATEQIhJAABExEIEGEkAAByJAAAEAIkMiQ4EAQw==",
			  "clear-state-program": "BYEBQw==",
			  "creator": "FPVVJ7N42QRVP2OWBGZ3XPTQAZFQNBYHJGZ2CJFOATAQNWFA5NWB4MPWBQ"
			}
		  }
		],
		"latest-timestamp": 1634765269,
		"protocol-version": "future",
		"round": 2,
		"sources": null,
		"txns": [
		  {
		"sig": "8Z/ECart3vFBSKp5sFuNRN4coliea4TE+xttZNn9E15DJ8GZ++kgtZKhG4Tiopv7r61Lqh8VBuyuTf9AC3uQBQ==",
		"txn": {
		  "amt": 5000,
		  "fee": 1000,
		  "fv": 3,
		  "gen": "sandnet-v1",
		  "gh": "pjM5GFR9MpNkWIibcfqtu/a2OIZTBy/mSQc++sF1r0Q=",
		  "grp": "2ca4sSb5aGab0k065qIT3J3AcB5YWYezrRh6bLB0ve8=",
		  "lv": 1003,
		  "note": "V+GSPgDmLQo=",
		  "rcv": "WCS6TVPJRBSARHLN2326LRU5BYVJZUKI2VJ53CAWKYYHDE455ZGKANWMGM",
		  "snd": "FPVVJ7N42QRVP2OWBGZ3XPTQAZFQNBYHJGZ2CJFOATAQNWFA5NWB4MPWBQ",
		  "type": "pay"
		}
	  },
		  {
		"sig": "4/gj+6rllN/Uc55kAJ0BOKTzoUJKJ7gExE3vp7cr5vC9XVStx0QNZq1DFXLhpTZnTQAl3zOrGzIxfS5HOpSyCg==",
		"txn": {
		  "apid": 1,
		  "fee": 1000,
		  "fv": 3,
		  "gh": "pjM5GFR9MpNkWIibcfqtu/a2OIZTBy/mSQc++sF1r0Q=",
		  "grp": "2ca4sSb5aGab0k065qIT3J3AcB5YWYezrRh6bLB0ve8=",
		  "lv": 1003,
		  "note": "+fl8jkXqyFc=",
		  "snd": "FPVVJ7N42QRVP2OWBGZ3XPTQAZFQNBYHJGZ2CJFOATAQNWFA5NWB4MPWBQ",
		  "type": "appl"
		}
	  }
		]
	  }`

	ds := DebugParams{
		Proto:      string(protocol.ConsensusCurrentVersion),
		DdrBlob:    []byte(ddrBlob),
		GroupIndex: 0,
		RunMode:    "application",
	}

	local := MakeLocalRunner(nil)
	err := local.Setup(&ds)
	a.NoError(err)

	pass, err := local.Run()
	a.NoError(err)
	a.True(pass)
}
