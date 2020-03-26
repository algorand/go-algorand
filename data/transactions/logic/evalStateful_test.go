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

package logic

import (
	"encoding/hex"
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/protocol"
)

type balanceRecord struct {
	addr     basics.Address
	balance  uint64
	apps     map[basics.AppIndex]map[string]basics.TealValue
	holdings map[uint64]basics.AssetHolding
	assets   map[uint64]basics.AssetParams
}

type testLedger struct {
	balances     map[basics.Address]balanceRecord
	applications map[basics.AppIndex]map[string]basics.TealValue
	localCount   int
	globalCount  int
	appID        uint64
}

func makeBalanceRecord(addr basics.Address, balance uint64) balanceRecord {
	br := balanceRecord{
		addr:     addr,
		balance:  balance,
		apps:     make(map[basics.AppIndex]map[string]basics.TealValue),
		holdings: make(map[uint64]basics.AssetHolding),
		assets:   make(map[uint64]basics.AssetParams),
	}
	return br
}

func makeTestLedger(balances map[basics.Address]uint64) *testLedger {
	l := new(testLedger)
	l.balances = make(map[basics.Address]balanceRecord)
	if balances != nil {
		for addr, balance := range balances {
			l.balances[addr] = makeBalanceRecord(addr, balance)

		}
	}
	l.applications = make(map[basics.AppIndex]map[string]basics.TealValue)
	return l
}

func (l *testLedger) resetCounters() {
	l.localCount = 0
	l.globalCount = 0
}

func (l *testLedger) newApp(addr basics.Address, appID uint64) {
	l.appID = appID
	appIdx := basics.AppIndex(appID)
	l.applications[appIdx] = make(map[string]basics.TealValue)
	br, ok := l.balances[addr]
	if !ok {
		br = makeBalanceRecord(addr, 0)
	}
	br.apps[appIdx] = make(map[string]basics.TealValue)
	l.balances[addr] = br
}

func (l *testLedger) setAsset(addr basics.Address, assetID uint64, params basics.AssetParams) {
	br, ok := l.balances[addr]
	if !ok {
		br = makeBalanceRecord(addr, 0)
	}
	br.assets[assetID] = params
	l.balances[addr] = br
}

func (l *testLedger) setHolding(addr basics.Address, assetID uint64, holding basics.AssetHolding) {
	br, ok := l.balances[addr]
	if !ok {
		br = makeBalanceRecord(addr, 0)
	}
	br.holdings[assetID] = holding
	l.balances[addr] = br
}

func (l *testLedger) Balance(addr basics.Address) (amount uint64, err error) {
	if l.balances == nil {
		return 0, fmt.Errorf("empty ledger")
	}
	br, ok := l.balances[addr]
	if !ok {
		return 0, fmt.Errorf("no such address")
	}
	return br.balance, nil
}

func (l *testLedger) AppLocalState(addr basics.Address, appIdx basics.AppIndex) (basics.TealKeyValue, error) {
	l.localCount++
	if appIdx == 0 {
		appIdx = basics.AppIndex(l.appID)
	}
	if br, ok := l.balances[addr]; ok {
		if state, ok := br.apps[appIdx]; ok {
			return state, nil
		}
		return nil, fmt.Errorf("No app for account")
	}
	return nil, fmt.Errorf("no such address")
}

func (l *testLedger) AppGlobalState() (basics.TealKeyValue, error) {
	l.globalCount++
	var appIdx basics.AppIndex = basics.AppIndex(l.appID)
	if state, ok := l.applications[appIdx]; ok {
		return state, nil
	}
	return nil, fmt.Errorf("no such app")
}

func (l *testLedger) AssetHolding(addr basics.Address, assetID basics.AssetIndex) (basics.AssetHolding, error) {
	if br, ok := l.balances[addr]; ok {
		if asset, ok := br.holdings[uint64(assetID)]; ok {
			return asset, nil
		}
		return basics.AssetHolding{}, fmt.Errorf("No asset for account")
	}
	return basics.AssetHolding{}, fmt.Errorf("no such address")
}

func (l *testLedger) AssetParams(addr basics.Address, assetID basics.AssetIndex) (basics.AssetParams, error) {
	if br, ok := l.balances[addr]; ok {
		if asset, ok := br.assets[uint64(assetID)]; ok {
			return asset, nil
		}
		return basics.AssetParams{}, fmt.Errorf("No asset for account")
	}
	return basics.AssetParams{}, fmt.Errorf("no such address")
}

func TestEvalModes(t *testing.T) {
	t.Parallel()
	// ed25519verify and err are tested separately below

	// check modeAny (TEAL v1 + txna/gtxna) are available in RunModeSignature
	// check all opcodes available in runModeApplication
	opcodesRunModeAny := `intcblock 0 1 1 1 1 5 100
	bytecblock 0x414c474f 0x1337 0x2001 0xdeadbeef 0x70077007
bytec 0
sha256
keccak256
sha512_256
len
intc_0
+
intc_1
-
intc_2
/
intc_3
*
intc 4
<
intc_1
>
intc_1
<=
intc_1
>=
intc_1
&&
intc_1
||
bytec_1
bytec_2
!=
bytec_3
bytec 4
==
!
itob
btoi
%	// use values left after bytes comparison
|
intc_1
&
txn Fee
^
global MinTxnFee
~
gtxn 0 LastValid
mulw
pop
store 0
load 0
bnz label
label:
dup
pop
txna Accounts 0
gtxna 0 ApplicationArgs 0
==
`
	opcodesRunModeSignature := `arg_0
arg_1
!=
arg_2
arg_3
!=
&&
txn Sender
arg 4
!=
&&
!=
&&
`

	opcodesRunModeApplication := `int 0
balance
&&
intc_0
intc 6  // 100
app_opted_in
&&
intc_0
bytec_0 // ALGO
intc_1
app_local_put
bytec_0
intc_1
app_global_put
intc_0
intc 6
bytec_0
app_local_get
pop
&&
bytec_0
app_global_get
pop
&&
intc_0
bytec_0
app_local_del
bytec_0
app_global_del
intc_0
intc 5 // 5
asset_holding_get AssetBalance
pop
&&
intc_0
intc 5
asset_params_get AssetTotal
pop
&&
!=
`
	type desc struct {
		source string
		eval   func([]byte, EvalParams) (bool, error)
		check  func([]byte, EvalParams) (int, error)
	}
	tests := map[runMode]desc{
		runModeSignature: desc{
			source: opcodesRunModeAny + opcodesRunModeSignature,
			eval:   func(program []byte, ep EvalParams) (bool, error) { return Eval(program, ep) },
			check:  func(program []byte, ep EvalParams) (int, error) { return Check(program, ep) },
		},
		runModeApplication: desc{
			source: opcodesRunModeAny + opcodesRunModeApplication,
			eval: func(program []byte, ep EvalParams) (bool, error) {
				pass, _, err := EvalStateful(program, ep)
				return pass, err
			},
			check: func(program []byte, ep EvalParams) (int, error) { return CheckStateful(program, ep) },
		},
	}

	txn := makeSampleTxn()
	txgroup := makeSampleTxnGroup(txn)
	txn.Lsig.Args = [][]byte{
		txn.Txn.Sender[:],
		txn.Txn.Receiver[:],
		txn.Txn.CloseRemainderTo[:],
		txn.Txn.VotePK[:],
		txn.Txn.SelectionPK[:],
		txn.Txn.Note,
	}
	params := basics.AssetParams{
		Total:         1000,
		Decimals:      2,
		DefaultFrozen: false,
		UnitName:      "ALGO",
		AssetName:     "",
		URL:           string(protocol.PaymentTx),
		Manager:       txn.Txn.Sender,
		Reserve:       txn.Txn.Receiver,
		Freeze:        txn.Txn.Receiver,
		Clawback:      txn.Txn.Receiver,
	}
	algoValue := basics.TealValue{Type: basics.TealUintType, Uint: 0x77}
	ledger := makeTestLedger(
		map[basics.Address]uint64{
			txn.Txn.Sender: 1,
		},
	)
	ledger.newApp(txn.Txn.Sender, 100)
	ledger.balances[txn.Txn.Sender].apps[100]["ALGO"] = algoValue
	ledger.setAsset(txn.Txn.Receiver, 5, params)
	ledger.setHolding(txn.Txn.Sender, 5, basics.AssetHolding{Amount: 123, Frozen: true})

	for mode, test := range tests {
		t.Run(fmt.Sprintf("opcodes_mode=%d", mode), func(t *testing.T) {
			program, err := AssembleString(test.source)
			require.NoError(t, err)
			sb := strings.Builder{}
			ep := defaultEvalParams(&sb, &txn)
			ep.TxnGroup = txgroup
			ep.Ledger = ledger
			_, err = test.check(program, ep)
			require.NoError(t, err)
			_, err = test.eval(program, ep)
			if err != nil {
				t.Log(hex.EncodeToString(program))
				t.Log(sb.String())
			}
			require.NoError(t, err)
		})
	}

	// check err opcode work in both modes
	for mode, test := range tests {
		t.Run(fmt.Sprintf("err_mode=%d", mode), func(t *testing.T) {
			source := "err"
			program, err := AssembleString(source)
			require.NoError(t, err)
			ep := defaultEvalParams(nil, nil)
			_, err = test.check(program, ep)
			require.NoError(t, err)
			_, err = test.eval(program, ep)
			require.Error(t, err)
			require.NotContains(t, err.Error(), "not allowed in current mode")
			require.Contains(t, err.Error(), "err opcode")
		})
	}

	// check ed25519verify and arg are not allowed in statefull mode
	disallowed := []string{
		"byte 0x01\nbyte 0x01\nbyte 0x01\ned25519verify",
		"arg 0",
		"arg_0",
		"arg_1",
		"arg_2",
		"arg_3",
	}
	for _, source := range disallowed {
		program, err := AssembleString(source)
		require.NoError(t, err)
		ep := defaultEvalParams(nil, nil)
		_, err = CheckStateful(program, ep)
		require.Error(t, err)
		_, _, err = EvalStateful(program, ep)
		require.Error(t, err)
		require.Contains(t, err.Error(), "not allowed in current mode")
	}

	// check new opcodes are not allowed in stateless mode
	newOpcodeCalls := []string{
		"int 0\nbalance",
		"int 0\nint 0\napp_opted_in",
		"int 0\nint 0\nbyte 0x01\napp_local_get",
		"byte 0x01\napp_global_get",
		"int 1\nbyte 0x01\nbyte 0x01\napp_local_put",
		"byte 0x01\nint 0\napp_global_put",
		"int 0\nbyte 0x01\napp_local_del",
		"byte 0x01\napp_global_del",
		"int 0\nint 0\nasset_holding_get AssetFrozen",
		"int 0\nint 0\nasset_params_get AssetManager",
	}

	for _, source := range newOpcodeCalls {
		program, err := AssembleString(source)
		require.NoError(t, err)
		ep := defaultEvalParams(nil, nil)
		_, err = Check(program, ep)
		require.Error(t, err)
		_, err = Eval(program, ep)
		require.Error(t, err)
		require.Contains(t, err.Error(), "not allowed in current mode")
	}

	require.Equal(t, runMode(1), runModeSignature)
	require.Equal(t, runMode(2), runModeApplication)
	require.True(t, modeAny == runModeSignature|runModeApplication)
	require.True(t, modeAny.Any())
}

func TestBalance(t *testing.T) {
	t.Parallel()

	text := `int 2
balance
int 1
==`
	program, err := AssembleString(text)
	require.NoError(t, err)

	txn := makeSampleTxn()
	txgroup := makeSampleTxnGroup(txn)
	ep := defaultEvalParams(nil, nil)
	ep.Txn = &txn
	ep.TxnGroup = txgroup
	_, _, err = EvalStateful(program, ep)
	require.Error(t, err)
	require.Contains(t, err.Error(), "ledger not available")

	ep.Ledger = makeTestLedger(
		map[basics.Address]uint64{
			txn.Txn.Receiver: 1,
		},
	)
	_, _, err = EvalStateful(program, ep)
	require.Error(t, err)
	require.Contains(t, err.Error(), "cannot load account")

	text = `int 1
balance
int 1
==`
	program, err = AssembleString(text)
	require.NoError(t, err)
	cost, err := CheckStateful(program, ep)
	require.NoError(t, err)
	require.True(t, cost < 1000)
	pass, _, err := EvalStateful(program, ep)
	require.NoError(t, err)
	require.True(t, pass)

	text = `int 0
balance
int 1
==`
	program, err = AssembleString(text)
	require.NoError(t, err)
	var addr basics.Address
	copy(addr[:], []byte("aoeuiaoeuiaoeuiaoeuiaoeuiaoeui02"))
	ep.Ledger = makeTestLedger(
		map[basics.Address]uint64{
			addr: 1,
		},
	)
	pass, _, err = EvalStateful(program, ep)
	require.Error(t, err)
	require.Contains(t, err.Error(), "failed to fetch balance")

	ep.Ledger = makeTestLedger(
		map[basics.Address]uint64{
			txn.Txn.Sender: 1,
		},
	)
	cost, err = CheckStateful(program, ep)
	require.NoError(t, err)
	require.True(t, cost < 1000)
	pass, _, err = EvalStateful(program, ep)
	require.NoError(t, err)
	require.True(t, pass)
}

func TestAppCheckOptedIn(t *testing.T) {
	t.Parallel()

	text := `int 2  // account idx
int 100  // app idx
app_opted_in
int 1
==`
	program, err := AssembleString(text)
	require.NoError(t, err)

	txn := makeSampleTxn()
	txgroup := makeSampleTxnGroup(txn)
	ep := defaultEvalParams(nil, nil)
	ep.Txn = &txn
	ep.TxnGroup = txgroup
	_, _, err = EvalStateful(program, ep)
	require.Error(t, err)
	require.Contains(t, err.Error(), "ledger not available")

	ep.Ledger = makeTestLedger(
		map[basics.Address]uint64{
			txn.Txn.Receiver: 1,
		},
	)
	_, _, err = EvalStateful(program, ep)
	require.Error(t, err)
	require.Contains(t, err.Error(), "cannot load account")

	// Receiver is not opted in
	text = `int 1  // account idx
int 100  // app idx
app_opted_in
int 0
==`
	program, err = AssembleString(text)
	require.NoError(t, err)
	cost, err := CheckStateful(program, ep)
	require.NoError(t, err)
	require.True(t, cost < 1000)
	pass, _, err := EvalStateful(program, ep)
	require.NoError(t, err)
	require.True(t, pass)

	// Sender is not opted in
	text = `int 0  // account idx
int 100  // app idx
app_opted_in
int 0
==`
	program, err = AssembleString(text)
	require.NoError(t, err)
	ledger := makeTestLedger(
		map[basics.Address]uint64{
			txn.Txn.Sender: 1,
		},
	)
	ep.Ledger = ledger
	cost, err = CheckStateful(program, ep)
	require.NoError(t, err)
	require.True(t, cost < 1000)
	pass, _, err = EvalStateful(program, ep)
	require.NoError(t, err)
	require.True(t, pass)

	// Receiver opted in
	text = `int 1  // account idx
int 100  // app idx
app_opted_in
int 1
==`
	ledger.newApp(txn.Txn.Receiver, 100)

	program, err = AssembleString(text)
	require.NoError(t, err)
	pass, _, err = EvalStateful(program, ep)
	require.NoError(t, err)
	require.True(t, pass)

	// Sender opted in
	text = `int 0  // account idx
int 100  // app idx
app_opted_in
int 1
==`
	ledger.newApp(txn.Txn.Sender, 100)

	program, err = AssembleString(text)
	require.NoError(t, err)
	pass, _, err = EvalStateful(program, ep)
	require.NoError(t, err)
	require.True(t, pass)

}

func TestAppReadLocalState(t *testing.T) {
	t.Parallel()

	text := `int 2  // account idx
int 100 // app id
txn ApplicationArgs 0
app_local_get
bnz exist
int 0
==
bnz exit
exist:
err
exit:
int 1
==`
	program, err := AssembleString(text)
	require.NoError(t, err)

	txn := makeSampleTxn()
	txgroup := makeSampleTxnGroup(txn)
	ep := defaultEvalParams(nil, nil)
	ep.Txn = &txn
	ep.TxnGroup = txgroup
	cost, err := CheckStateful(program, ep)
	require.NoError(t, err)
	require.True(t, cost < 1000)
	_, _, err = EvalStateful(program, ep)
	require.Error(t, err)
	require.Contains(t, err.Error(), "ledger not available")

	ledger := makeTestLedger(
		map[basics.Address]uint64{
			txn.Txn.Receiver: 1,
		},
	)
	ep.Ledger = ledger
	_, _, err = EvalStateful(program, ep)
	require.Error(t, err)
	require.Contains(t, err.Error(), "cannot load account")

	text = `int 1  // account idx
int 100 // app id
txn ApplicationArgs 0
app_local_get
bnz exist
int 0
==
bnz exit
exist:
err
exit:
int 1`
	program, err = AssembleString(text)
	require.NoError(t, err)
	_, _, err = EvalStateful(program, ep)
	require.Error(t, err)
	require.Contains(t, err.Error(), "failed to fetch local state")

	ledger = makeTestLedger(
		map[basics.Address]uint64{
			txn.Txn.Receiver: 1,
		},
	)
	ep.Ledger = ledger
	ledger.newApp(txn.Txn.Receiver, 9999)

	_, _, err = EvalStateful(program, ep)
	require.Error(t, err)
	require.Contains(t, err.Error(), "failed to fetch local state")

	// create the app and check the value from ApplicationArgs[0] (protocol.PaymentTx) does not exist
	ledger.newApp(txn.Txn.Receiver, 100)

	pass, _, err := EvalStateful(program, ep)
	require.NoError(t, err)
	require.True(t, pass)

	text = `int 1  // account idx
int 100 // app id
txn ApplicationArgs 0
app_local_get
bnz exist
err
exist:
byte 0x414c474f
==`
	ledger.balances[txn.Txn.Receiver].apps[100][string(protocol.PaymentTx)] = basics.TealValue{Type: basics.TealBytesType, Bytes: "ALGO"}

	program, err = AssembleString(text)
	require.NoError(t, err)

	cost, err = CheckStateful(program, ep)
	require.NoError(t, err)
	require.True(t, cost < 1000)

	pass, _, err = EvalStateful(program, ep)
	require.NoError(t, err)
	require.True(t, pass)

	// check special case account idx == 0 => sender
	ledger.newApp(txn.Txn.Sender, 100)
	text = `int 0  // account idx
int 100 // app id
txn ApplicationArgs 0
app_local_get
bnz exist
err
exist:
byte 0x414c474f
==`

	program, err = AssembleString(text)
	require.NoError(t, err)

	ledger.balances[txn.Txn.Sender].apps[100][string(protocol.PaymentTx)] = basics.TealValue{Type: basics.TealBytesType, Bytes: "ALGO"}
	pass, _, err = EvalStateful(program, ep)
	require.NoError(t, err)
	require.True(t, pass)

}

func TestAppReadGlobalState(t *testing.T) {
	t.Parallel()

	text := `txn ApplicationArgs 0
app_global_get
bnz exist
err
exist:
byte 0x414c474f
==`
	program, err := AssembleString(text)
	require.NoError(t, err)

	txn := makeSampleTxn()
	txgroup := makeSampleTxnGroup(txn)
	ep := defaultEvalParams(nil, nil)
	ep.Txn = &txn
	ep.TxnGroup = txgroup
	cost, err := CheckStateful(program, ep)
	require.NoError(t, err)
	require.True(t, cost < 1000)
	_, _, err = EvalStateful(program, ep)
	require.Error(t, err)
	require.Contains(t, err.Error(), "ledger not available")

	ledger := makeTestLedger(
		map[basics.Address]uint64{
			txn.Txn.Sender: 1,
		},
	)
	ep.Ledger = ledger

	ep.Txn.Txn.ApplicationID = 100
	_, _, err = EvalStateful(program, ep)
	require.Error(t, err)
	require.Contains(t, err.Error(), "failed to fetch global state")

	// create the app and check the value from ApplicationArgs[0] (protocol.PaymentTx) does not exist
	ledger.newApp(txn.Txn.Sender, 100)

	_, _, err = EvalStateful(program, ep)
	require.Error(t, err)
	require.Contains(t, err.Error(), "err opcode")

	ledger.applications[100][string(protocol.PaymentTx)] = basics.TealValue{Type: basics.TealBytesType, Bytes: "ALGO"}
	cost, err = CheckStateful(program, ep)
	require.NoError(t, err)
	require.True(t, cost < 1000)
	pass, _, err := EvalStateful(program, ep)
	require.NoError(t, err)
	require.True(t, pass)
}

const assetsTestProgram = `int 0
int 55
asset_holding_get AssetBalance
!
bnz error
int 123
==
int 0
int 55
asset_holding_get AssetFrozen
!
bnz error
int 1
==
&&
int 1
int 55
asset_params_get AssetTotal
!
bnz error
int 1000
==
&&
int 1
int 55
asset_params_get AssetDecimals
!
bnz error
int 2
==
&&
int 1
int 55
asset_params_get AssetDefaultFrozen
!
bnz error
int 0
==
&&
int 1
int 55
asset_params_get AssetUnitName
!
bnz error
byte 0x414c474f
==
&&
int 1
int 55
asset_params_get AssetAssetName
!
bnz error
len
int 0
==
&&
int 1
int 55
asset_params_get AssetURL
!
bnz error
txna ApplicationArgs 0
==
&&
int 1
int 55
asset_params_get AssetMetadataHash
!
bnz error
byte 0x0000000000000000000000000000000000000000000000000000000000000000
==
&&
int 1
int 55
asset_params_get AssetManager
!
bnz error
txna Accounts 0
==
&&
int 1
int 55
asset_params_get AssetReserve
!
bnz error
txna Accounts 1
==
&&
int 1
int 55
asset_params_get AssetFreeze
!
bnz error
txna Accounts 1
==
&&
int 1
int 55
asset_params_get AssetClawback
!
bnz error
txna Accounts 1
==
&&
bnz ok
error:
err
ok:
int 1
`

func TestAssets(t *testing.T) {
	t.Parallel()
	for _, field := range AssetHoldingFieldNames {
		if !strings.Contains(assetsTestProgram, field) {
			t.Errorf("TestAssets missing field %v", field)
		}
	}
	for _, field := range AssetParamsFieldNames {
		if !strings.Contains(assetsTestProgram, field) {
			t.Errorf("TestAssets missing field %v", field)
		}
	}

	// check generic errors
	sources := []string{
		"int 5\nint 55\nasset_holding_get AssetBalance",
		"int 5\nint 55\nasset_params_get AssetTotal",
	}
	for _, source := range sources {

		program, err := AssembleString(source)
		require.NoError(t, err)

		txn := makeSampleTxn()
		ep := defaultEvalParams(nil, nil)
		ep.Txn = &txn
		cost, err := CheckStateful(program, ep)
		require.NoError(t, err)
		require.True(t, cost < 1000)
		_, _, err = EvalStateful(program, ep)
		require.Error(t, err)
		require.Contains(t, err.Error(), "ledger not available")

		ledger := makeTestLedger(
			map[basics.Address]uint64{
				txn.Txn.Sender: 1,
			},
		)
		ep.Ledger = ledger

		_, _, err = EvalStateful(program, ep)
		require.Error(t, err)
		require.Contains(t, err.Error(), "cannot load account[5]")
	}

	program, err := AssembleString(assetsTestProgram)
	require.NoError(t, err)
	cost, err := CheckStateful(program, defaultEvalParams(nil, nil))
	require.NoError(t, err)
	require.True(t, cost < 1000)

	txn := makeSampleTxn()
	sb := strings.Builder{}
	ledger := makeTestLedger(
		map[basics.Address]uint64{
			txn.Txn.Sender: 1,
		},
	)
	params := basics.AssetParams{
		Total:         1000,
		Decimals:      2,
		DefaultFrozen: false,
		UnitName:      "ALGO",
		AssetName:     "",
		URL:           string(protocol.PaymentTx),
		Manager:       txn.Txn.Sender,
		Reserve:       txn.Txn.Receiver,
		Freeze:        txn.Txn.Receiver,
		Clawback:      txn.Txn.Receiver,
	}
	ledger.setAsset(txn.Txn.Receiver, 55, params)
	ledger.setHolding(txn.Txn.Sender, 55, basics.AssetHolding{Amount: 123, Frozen: true})

	ep := defaultEvalParams(&sb, &txn)
	ep.Ledger = ledger
	cost, err = CheckStateful(program, ep)
	require.NoError(t, err)
	require.True(t, cost < 1000)
	pass, _, err := EvalStateful(program, ep)
	if !pass {
		t.Log(hex.EncodeToString(program))
		t.Log(sb.String())
	}
	require.NoError(t, err)
	require.True(t, pass)

	// check holdings bool value
	source := `int 0  // account idx (txn.Sender)
int 55
asset_holding_get AssetFrozen
!
bnz error
int 0
==
bnz ok
error:
err
ok:
int 1
`
	program, err = AssembleString(source)
	require.NoError(t, err)
	ledger.setHolding(txn.Txn.Sender, 55, basics.AssetHolding{Amount: 123, Frozen: false})
	cost, err = CheckStateful(program, ep)
	require.NoError(t, err)
	require.True(t, cost < 1000)
	pass, _, err = EvalStateful(program, ep)
	require.NoError(t, err)
	require.True(t, pass)

	// check holdings invalid offsets
	require.Equal(t, opsByName[ep.Proto.LogicSigVersion]["asset_holding_get"].Opcode, program[8])
	program[9] = 0x02
	_, _, err = EvalStateful(program, ep)
	require.Error(t, err)
	require.Contains(t, err.Error(), "invalid asset holding field 2")

	// check holdings bool value
	source = `int 1
int 55
asset_params_get AssetDefaultFrozen
!
bnz error
int 1
==
bnz ok
error:
err
ok:
int 1
`
	program, err = AssembleString(source)
	require.NoError(t, err)
	params.DefaultFrozen = true
	ledger.setAsset(txn.Txn.Receiver, 55, params)
	pass, _, err = EvalStateful(program, ep)
	require.NoError(t, err)
	require.True(t, pass)

	// check holdings invalid offsets
	require.Equal(t, opsByName[ep.Proto.LogicSigVersion]["asset_params_get"].Opcode, program[7])
	program[8] = 0x20
	_, _, err = EvalStateful(program, ep)
	require.Error(t, err)
	require.Contains(t, err.Error(), "invalid asset params field 32")

	// check empty string
	source = `int 1  // account idx (txn.Accounts[1])
int 55
asset_params_get AssetURL
!
bnz error
len
int 0
==
bnz ok
error:
err
ok:
int 1
`
	program, err = AssembleString(source)
	require.NoError(t, err)
	params.URL = ""
	ledger.setAsset(txn.Txn.Receiver, 55, params)
	pass, _, err = EvalStateful(program, ep)
	require.NoError(t, err)
	require.True(t, pass)

	source = `int 1
int 55
asset_params_get AssetURL
!
bnz error
int 0
==
bnz ok
error:
err
ok:
int 1
`
	program, err = AssembleString(source)
	require.NoError(t, err)
	params.URL = ""
	ledger.setAsset(txn.Txn.Receiver, 55, params)
	cost, err = CheckStateful(program, ep)
	require.NoError(t, err)
	require.True(t, cost < 1000)
	pass, _, err = EvalStateful(program, ep)
	require.Error(t, err)
	require.Contains(t, err.Error(), "cannot compare ([]byte == uint64)")
}

func TestAppLocalReadWriteDeleteErrors(t *testing.T) {
	t.Parallel()

	sourceRead := `int 0  // account idx (txn.Sender)
int 100                   // app id
byte 0x414c474f           // key "ALGO"
app_local_get
!
bnz error
int 0x77
==
int 0
int 100
byte 0x414c474f41         // ALGOA
app_local_get
!
bnz error
int 1
==
&&
bnz ok
error:
err
ok:
int 1
`
	sourceWrite := `int 0  // account idx (txn.Sender)
byte 0x414c474f            // key "ALGO"
int 100
app_local_put
int 1
`
	sourceDelete := `int 0   // account idx
byte 0x414c474f              // key "ALGO"
app_local_del
int 100
`
	type test struct {
		source       string
		accNumOffset int
	}

	tests := map[string]test{
		"read":   test{sourceRead, 20},
		"write":  test{sourceWrite, 13},
		"delete": test{sourceDelete, 12},
	}
	for name, test := range tests {
		t.Run(fmt.Sprintf("test=%s", name), func(t *testing.T) {
			source := test.source
			firstCmdOffset := test.accNumOffset

			program, err := AssembleString(source)
			require.NoError(t, err)

			txn := makeSampleTxn()
			ep := defaultEvalParams(nil, nil)
			ep.Txn = &txn
			cost, err := CheckStateful(program, ep)
			require.NoError(t, err)
			require.True(t, cost < 1000)
			_, _, err = EvalStateful(program, ep)
			require.Error(t, err)
			require.Contains(t, err.Error(), "ledger not available")

			ledger := makeTestLedger(
				map[basics.Address]uint64{
					txn.Txn.Sender: 1,
				},
			)
			ep.Ledger = ledger

			saved := program[firstCmdOffset]
			require.Equal(t, opsByName[0]["intc_0"].Opcode, saved)
			program[firstCmdOffset] = opsByName[0]["intc_1"].Opcode
			_, _, err = EvalStateful(program, ep)
			require.Error(t, err)
			require.Contains(t, err.Error(), "cannot load account[100]")

			program[firstCmdOffset] = saved
			_, _, err = EvalStateful(program, ep)
			require.Error(t, err)
			require.Contains(t, err.Error(), "failed to fetch local state")

			ledger.newApp(txn.Txn.Sender, 100)

			if name == "read" {
				_, _, err = EvalStateful(program, ep)
				require.Error(t, err)
				require.Contains(t, err.Error(), "err opcode") // no such key
			}

			ledger.balances[txn.Txn.Sender].apps[100]["ALGO"] = basics.TealValue{Type: basics.TealUintType, Uint: 0x77}
			ledger.balances[txn.Txn.Sender].apps[100]["ALGOA"] = basics.TealValue{Type: basics.TealUintType, Uint: 1}

			ledger.resetCounters()
			pass, delta, err := EvalStateful(program, ep)
			require.NoError(t, err)
			require.True(t, pass)
			require.Equal(t, 0, len(delta.GlobalDelta))
			// for read test: the second call to the state fulfilled from the cache
			require.Equal(t, 1, ledger.localCount)
		})
	}
}

func TestAppLocalStateReadWrite(t *testing.T) {
	t.Parallel()

	ep := defaultEvalParams(nil, nil)
	txn := makeSampleTxn()
	txn.Txn.ApplicationID = 100
	ep.Txn = &txn
	ledger := makeTestLedger(
		map[basics.Address]uint64{
			txn.Txn.Sender: 1,
		},
	)
	ep.Ledger = ledger
	ledger.newApp(txn.Txn.Sender, 100)

	// write int and bytes values
	source := `int 0 // account
byte 0x414c474f      // key "ALGO"
int 0x77             // value
app_local_put
int 0 				 // account
byte 0x414c474f41    // key "ALGOA"
byte 0x414c474f      // value
app_local_put
int 0                // account
int 100              // app id
byte 0x414c474f41    // key "ALGOA"
app_local_get
bnz exist
err
exist:
byte 0x414c474f
==
int 0                // account
int 100              // app id
byte 0x414c474f      // key "ALGO"
app_local_get
bnz exist2
err
exist2:
int 0x77
==
&&
`
	program, err := AssembleString(source)
	require.NoError(t, err)
	cost, err := CheckStateful(program, ep)
	require.NoError(t, err)
	require.True(t, cost < 1000)
	pass, delta, err := EvalStateful(program, ep)
	require.NoError(t, err)
	require.True(t, pass)
	require.Equal(t, 0, len(delta.GlobalDelta))
	require.Equal(t, 1, len(delta.LocalDeltas))

	require.Equal(t, 2, len(delta.LocalDeltas[txn.Txn.Sender]))
	vd := delta.LocalDeltas[txn.Txn.Sender]["ALGO"]
	require.Equal(t, basics.SetUintAction, vd.Action)
	require.Equal(t, uint64(0x77), vd.Uint)

	vd = delta.LocalDeltas[txn.Txn.Sender]["ALGOA"]
	require.Equal(t, basics.SetBytesAction, vd.Action)
	require.Equal(t, "ALGO", vd.Bytes)

	require.Equal(t, 1, ledger.localCount)

	// write same value without writing, expect no local delta
	source = `int 0  // account
byte 0x414c474f       // key
int 0x77              // value
app_local_put
int 0                 // account
int 100               // app id
byte 0x414c474f       // key
app_local_get
bnz exist
err
exist:
int 0x77
==
`
	ledger.resetCounters()
	delete(ledger.balances[txn.Txn.Sender].apps[100], "ALGOA")
	delete(ledger.balances[txn.Txn.Sender].apps[100], "ALGO")

	algoValue := basics.TealValue{Type: basics.TealUintType, Uint: 0x77}
	ledger.balances[txn.Txn.Sender].apps[100]["ALGO"] = algoValue

	program, err = AssembleString(source)
	require.NoError(t, err)
	cost, err = CheckStateful(program, ep)
	require.NoError(t, err)
	require.True(t, cost < 1000)
	pass, delta, err = EvalStateful(program, ep)
	require.NoError(t, err)
	require.True(t, pass)
	require.Equal(t, 0, len(delta.GlobalDelta))
	require.Equal(t, 0, len(delta.LocalDeltas))
	require.Equal(t, 1, ledger.localCount)

	// write same value after reading, expect no local delta
	source = `int 0  // account
int 100              // app id
byte 0x414c474f      // key
app_local_get
bnz exist
err
exist:
int 0                // account
byte 0x414c474f      // key
int 0x77             // value
app_local_put
int 0                // account
int 100              // app id
byte 0x414c474f      // key
app_local_get
bnz exist2
err
exist2:
==
`
	ledger.resetCounters()
	ledger.balances[txn.Txn.Sender].apps[100]["ALGO"] = algoValue
	delete(ledger.balances[txn.Txn.Sender].apps[100], "ALGOA")

	program, err = AssembleString(source)
	require.NoError(t, err)
	pass, delta, err = EvalStateful(program, ep)
	require.NoError(t, err)
	require.True(t, pass)
	require.Equal(t, 0, len(delta.GlobalDelta))
	require.Equal(t, 0, len(delta.LocalDeltas))
	require.Equal(t, 1, ledger.localCount)

	// write a value and expect local delta change
	source = `int 0  // account
byte 0x414c474f41    // key "ALGOA"
int 0x78             // value
app_local_put
int 1
`
	ledger.resetCounters()
	ledger.balances[txn.Txn.Sender].apps[100]["ALGO"] = algoValue
	delete(ledger.balances[txn.Txn.Sender].apps[100], "ALGOA")

	program, err = AssembleString(source)
	require.NoError(t, err)
	pass, delta, err = EvalStateful(program, ep)
	require.NoError(t, err)
	require.True(t, pass)
	require.Equal(t, 0, len(delta.GlobalDelta))
	require.Equal(t, 1, len(delta.LocalDeltas))
	require.Equal(t, 1, len(delta.LocalDeltas[txn.Txn.Sender]))
	vd = delta.LocalDeltas[txn.Txn.Sender]["ALGOA"]
	require.Equal(t, basics.SetUintAction, vd.Action)
	require.Equal(t, uint64(0x78), vd.Uint)
	require.Equal(t, 1, ledger.localCount)

	// write a value to exising key and expect delta change and reading the new value
	source = `int 0  // account
byte 0x414c474f      // key "ALGO"
int 0x78             // value
app_local_put
int 0                // account
int 100              // app id
byte 0x414c474f      // key "ALGO"
app_local_get
bnz exist
err
exist:
int 0x78
==
`
	ledger.resetCounters()
	ledger.balances[txn.Txn.Sender].apps[100]["ALGO"] = algoValue
	delete(ledger.balances[txn.Txn.Sender].apps[100], "ALGOA")

	program, err = AssembleString(source)
	require.NoError(t, err)
	pass, delta, err = EvalStateful(program, ep)
	require.NoError(t, err)
	require.True(t, pass)
	require.Equal(t, 0, len(delta.GlobalDelta))
	require.Equal(t, 1, len(delta.LocalDeltas))
	require.Equal(t, 1, len(delta.LocalDeltas[txn.Txn.Sender]))
	vd = delta.LocalDeltas[txn.Txn.Sender]["ALGO"]
	require.Equal(t, basics.SetUintAction, vd.Action)
	require.Equal(t, uint64(0x78), vd.Uint)
	require.Equal(t, 1, ledger.localCount)

	// write a value after read and expect delta change
	source = `int 0  // account
int 100              // app id
byte 0x414c474f      // key "ALGO"
app_local_get
bnz exist
err
exist:
int 0  				 // account
byte 0x414c474f      // key "ALGO"
int 0x78             // value
app_local_put
`
	ledger.resetCounters()
	ledger.balances[txn.Txn.Sender].apps[100]["ALGO"] = algoValue
	delete(ledger.balances[txn.Txn.Sender].apps[100], "ALGOA")

	program, err = AssembleString(source)
	require.NoError(t, err)
	pass, delta, err = EvalStateful(program, ep)
	require.NoError(t, err)
	require.True(t, pass)
	require.Equal(t, 0, len(delta.GlobalDelta))
	require.Equal(t, 1, len(delta.LocalDeltas))
	require.Equal(t, 1, len(delta.LocalDeltas[txn.Txn.Sender]))
	vd = delta.LocalDeltas[txn.Txn.Sender]["ALGO"]
	require.Equal(t, basics.SetUintAction, vd.Action)
	require.Equal(t, uint64(0x78), vd.Uint)
	require.Equal(t, 1, ledger.localCount)

	// write a few values and expect delta change only for unique changed
	source = `int 0  // account
byte 0x414c474f      // key "ALGO"
int 0x77             // value
app_local_put
int 0                // account
byte 0x414c474f      // key "ALGO"
int 0x78             // value
app_local_put
int 0                // account
byte 0x414c474f41    // key "ALGOA"
int 0x78             // value
app_local_put
int 1                // account
byte 0x414c474f      // key "ALGO"
int 0x79             // value
app_local_put
int 1
`
	ledger.resetCounters()
	ledger.balances[txn.Txn.Sender].apps[100]["ALGO"] = algoValue
	delete(ledger.balances[txn.Txn.Sender].apps[100], "ALGOA")

	ledger.balances[txn.Txn.Receiver] = makeBalanceRecord(txn.Txn.Receiver, 500)
	ledger.balances[txn.Txn.Receiver].apps[100] = make(map[string]basics.TealValue)

	program, err = AssembleString(source)
	require.NoError(t, err)
	cost, err = CheckStateful(program, ep)
	require.NoError(t, err)
	require.True(t, cost < 1000)
	pass, delta, err = EvalStateful(program, ep)
	require.NoError(t, err)
	require.True(t, pass)
	require.Equal(t, 0, len(delta.GlobalDelta))
	require.Equal(t, 2, len(delta.LocalDeltas))
	require.Equal(t, 2, len(delta.LocalDeltas[txn.Txn.Sender]))
	require.Equal(t, 1, len(delta.LocalDeltas[txn.Txn.Receiver]))
	vd = delta.LocalDeltas[txn.Txn.Sender]["ALGO"]
	require.Equal(t, basics.SetUintAction, vd.Action)
	require.Equal(t, uint64(0x78), vd.Uint)

	vd = delta.LocalDeltas[txn.Txn.Sender]["ALGOA"]
	require.Equal(t, basics.SetUintAction, vd.Action)
	require.Equal(t, uint64(0x78), vd.Uint)

	vd = delta.LocalDeltas[txn.Txn.Receiver]["ALGO"]
	require.Equal(t, basics.SetUintAction, vd.Action)
	require.Equal(t, uint64(0x79), vd.Uint)

	require.Equal(t, 2, ledger.localCount) // one call to ledger per account
}

func TestAppGlobalReadWriteDeleteErrors(t *testing.T) {
	t.Parallel()

	sourceRead := `byte 0x414c474f  // key "ALGO"
app_global_get
bnz ok
err
ok:
int 0x77
==
`
	sourceWrite := `byte 0x414c474f  // key "ALGO"
int 100
app_global_put
int 1
`
	sourceDelete := `byte 0x414c474f  // key "ALGO"
app_global_del
int 1
`
	tests := map[string]string{
		"read":   sourceRead,
		"write":  sourceWrite,
		"delete": sourceDelete,
	}
	for name, source := range tests {
		t.Run(fmt.Sprintf("test=%s", name), func(t *testing.T) {
			program, err := AssembleString(source)
			require.NoError(t, err)

			txn := makeSampleTxn()
			ep := defaultEvalParams(nil, nil)
			ep.Txn = &txn
			_, _, err = EvalStateful(program, ep)
			require.Error(t, err)
			require.Contains(t, err.Error(), "ledger not available")

			ledger := makeTestLedger(
				map[basics.Address]uint64{
					txn.Txn.Sender: 1,
				},
			)
			ep.Ledger = ledger

			txn.Txn.ApplicationID = 100
			_, _, err = EvalStateful(program, ep)
			require.Error(t, err)
			require.Contains(t, err.Error(), "failed to fetch global state")

			ledger.newApp(txn.Txn.Sender, 100)

			// a special test for read
			if name == "read" {
				_, _, err = EvalStateful(program, ep)
				require.Error(t, err)
				require.Contains(t, err.Error(), "err opcode") // no such key
			}
			ledger.applications[100]["ALGO"] = basics.TealValue{Type: basics.TealUintType, Uint: 0x77}

			ledger.resetCounters()
			pass, delta, err := EvalStateful(program, ep)
			require.NoError(t, err)
			require.True(t, pass)
			require.Equal(t, 0, len(delta.LocalDeltas))
			require.Equal(t, 1, ledger.globalCount)
		})
	}
}

func TestAppGlobalReadWrite(t *testing.T) {
	t.Parallel()

	// check writing ints and bytes
	source := `byte 0x414c474f  // key "ALGO"
int 0x77						// value
app_global_put
byte 0x414c474f41  // key "ALGOA"
byte 0x414c474f
app_global_put
byte 0x414c474f41
app_global_get
bnz ok1
err
ok1:
byte 0x414c474f
==
byte 0x414c474f
app_global_get
bnz ok2
err
ok2:
int 0x77
==
&&
`
	ep := defaultEvalParams(nil, nil)
	txn := makeSampleTxn()
	txn.Txn.ApplicationID = 100
	ep.Txn = &txn
	ledger := makeTestLedger(
		map[basics.Address]uint64{
			txn.Txn.Sender: 1,
		},
	)
	ep.Ledger = ledger
	ledger.newApp(txn.Txn.Sender, 100)

	program, err := AssembleString(source)
	require.NoError(t, err)
	cost, err := CheckStateful(program, ep)
	require.NoError(t, err)
	require.True(t, cost < 1000)
	pass, delta, err := EvalStateful(program, ep)
	require.NoError(t, err)
	require.True(t, pass)
	require.Equal(t, 2, len(delta.GlobalDelta))
	require.Equal(t, 0, len(delta.LocalDeltas))

	vd := delta.GlobalDelta["ALGO"]
	require.Equal(t, basics.SetUintAction, vd.Action)
	require.Equal(t, uint64(0x77), vd.Uint)

	vd = delta.GlobalDelta["ALGOA"]
	require.Equal(t, basics.SetBytesAction, vd.Action)
	require.Equal(t, "ALGO", vd.Bytes)

	require.Equal(t, 1, ledger.globalCount)
	require.Equal(t, 0, ledger.localCount)

	// write existing value before read
	source = `byte 0x414c474f  // key "ALGO"
int 0x77						// value
app_global_put
byte 0x414c474f
app_global_get
bnz ok
err
ok:
int 0x77
==
`
	ledger.resetCounters()
	delete(ledger.applications[100], "ALGOA")
	delete(ledger.applications[100], "ALGO")

	algoValue := basics.TealValue{Type: basics.TealUintType, Uint: 0x77}
	ledger.applications[100]["ALGO"] = algoValue

	program, err = AssembleString(source)
	require.NoError(t, err)
	pass, delta, err = EvalStateful(program, ep)
	require.NoError(t, err)
	require.True(t, pass)
	require.Equal(t, 0, len(delta.GlobalDelta))
	require.Equal(t, 0, len(delta.LocalDeltas))
	require.Equal(t, 1, ledger.globalCount)

	// write existing value after read
	source = `byte 0x414c474f
app_global_get
bnz ok
err
ok:
pop
byte 0x414c474f
int 0x77
app_global_put
byte 0x414c474f
app_global_get
bnz ok2
err
ok2:
int 0x77
==
`
	ledger.resetCounters()
	delete(ledger.applications[100], "ALGOA")
	ledger.applications[100]["ALGO"] = algoValue

	program, err = AssembleString(source)
	require.NoError(t, err)
	pass, delta, err = EvalStateful(program, ep)
	require.NoError(t, err)
	require.True(t, pass)
	require.Equal(t, 0, len(delta.GlobalDelta))
	require.Equal(t, 0, len(delta.LocalDeltas))
	require.Equal(t, 1, ledger.globalCount)

	// write new values after and before read
	source = `byte 0x414c474f
app_global_get
bnz ok
err
ok:
pop
byte 0x414c474f
int 0x78
app_global_put
byte 0x414c474f
app_global_get
bnz ok2
err
ok2:
int 0x78
==
byte 0x414c474f41
byte 0x414c474f
app_global_put
byte 0x414c474f41
app_global_get
bnz ok3
err
ok3:
byte 0x414c474f
==
&&
`
	ledger.resetCounters()
	delete(ledger.applications[100], "ALGOA")
	ledger.applications[100]["ALGO"] = algoValue

	program, err = AssembleString(source)
	require.NoError(t, err)
	sb := strings.Builder{}
	ep.Trace = &sb
	cost, err = CheckStateful(program, ep)
	require.NoError(t, err)
	require.True(t, cost < 1000)
	pass, delta, err = EvalStateful(program, ep)
	if !pass {
		t.Log(hex.EncodeToString(program))
		t.Log(sb.String())
	}
	require.NoError(t, err)
	require.True(t, pass)
	require.Equal(t, 2, len(delta.GlobalDelta))
	require.Equal(t, 0, len(delta.LocalDeltas))
	require.Equal(t, 1, ledger.globalCount)

	vd = delta.GlobalDelta["ALGO"]
	require.Equal(t, basics.SetUintAction, vd.Action)
	require.Equal(t, uint64(0x78), vd.Uint)

	vd = delta.GlobalDelta["ALGOA"]
	require.Equal(t, basics.SetBytesAction, vd.Action)
	require.Equal(t, "ALGO", vd.Bytes)

	require.Equal(t, 1, ledger.globalCount)
	require.Equal(t, 0, ledger.localCount)
}

func TestAppGlobalDelete(t *testing.T) {
	t.Parallel()

	// check write/delete/read
	source := `byte 0x414c474f  // key "ALGO"
int 0x77						// value
app_global_put
byte 0x414c474f41  // key "ALGOA"
byte 0x414c474f
app_global_put
byte 0x414c474f
app_global_del
byte 0x414c474f41
app_global_del
byte 0x414c474f
app_global_get
bnz error
byte 0x414c474f41
app_global_get
bnz error
==
bnz ok
error:
err
ok:
int 1
`
	ep := defaultEvalParams(nil, nil)
	txn := makeSampleTxn()
	txn.Txn.ApplicationID = 100
	ep.Txn = &txn
	ledger := makeTestLedger(
		map[basics.Address]uint64{
			txn.Txn.Sender: 1,
		},
	)
	ep.Ledger = ledger
	ledger.newApp(txn.Txn.Sender, 100)
	sb := strings.Builder{}
	ep.Trace = &sb

	program, err := AssembleString(source)
	require.NoError(t, err)
	cost, err := CheckStateful(program, ep)
	require.NoError(t, err)
	require.True(t, cost < 1000)
	pass, delta, err := EvalStateful(program, ep)
	if !pass {
		t.Log(hex.EncodeToString(program))
		t.Log(sb.String())
	}
	require.NoError(t, err)
	require.True(t, pass)
	require.Equal(t, 0, len(delta.GlobalDelta))
	require.Equal(t, 0, len(delta.LocalDeltas))
	require.Equal(t, 0, ledger.localCount)
	require.Equal(t, 1, ledger.globalCount)

	ledger.resetCounters()
	delete(ledger.applications[100], "ALGOA")
	delete(ledger.applications[100], "ALGO")

	algoValue := basics.TealValue{Type: basics.TealUintType, Uint: 0x77}
	ledger.applications[100]["ALGO"] = algoValue

	// check delete existing
	source = `byte 0x414c474f   // key "ALGO"
app_global_del
byte 0x414c474f
app_global_get
==  // two zeros
`

	program, err = AssembleString(source)
	require.NoError(t, err)
	pass, delta, err = EvalStateful(program, ep)
	require.NoError(t, err)
	require.True(t, pass)
	require.Equal(t, 1, len(delta.GlobalDelta))
	vd := delta.GlobalDelta["ALGO"]
	require.Equal(t, basics.DeleteAction, vd.Action)
	require.Equal(t, uint64(0), vd.Uint)
	require.Equal(t, "", vd.Bytes)
	require.Equal(t, 0, len(delta.LocalDeltas))
	require.Equal(t, 0, ledger.localCount)
	require.Equal(t, 1, ledger.globalCount)

	ledger.resetCounters()
	delete(ledger.applications[100], "ALGOA")
	delete(ledger.applications[100], "ALGO")

	ledger.applications[100]["ALGO"] = algoValue

	// check delete and write non-existing
	source = `byte 0x414c474f41   // key "ALGOA"
app_global_del
byte 0x414c474f41
app_global_get
==  // two zeros
byte 0x414c474f41
int 0x78
app_global_put
`
	program, err = AssembleString(source)
	require.NoError(t, err)
	pass, delta, err = EvalStateful(program, ep)
	require.NoError(t, err)
	require.True(t, pass)
	require.Equal(t, 1, len(delta.GlobalDelta))
	vd = delta.GlobalDelta["ALGOA"]
	require.Equal(t, basics.SetUintAction, vd.Action)
	require.Equal(t, uint64(0x78), vd.Uint)
	require.Equal(t, "", vd.Bytes)
	require.Equal(t, 0, len(delta.LocalDeltas))
	require.Equal(t, 0, ledger.localCount)
	require.Equal(t, 1, ledger.globalCount)

	ledger.resetCounters()
	delete(ledger.applications[100], "ALGOA")
	delete(ledger.applications[100], "ALGO")

	ledger.applications[100]["ALGO"] = algoValue

	// check delete and write existing
	source = `byte 0x414c474f   // key "ALGO"
app_global_del
byte 0x414c474f
int 0x78
app_global_put
int 1
`
	program, err = AssembleString(source)
	require.NoError(t, err)
	pass, delta, err = EvalStateful(program, ep)
	require.NoError(t, err)
	require.True(t, pass)
	require.Equal(t, 1, len(delta.GlobalDelta))
	vd = delta.GlobalDelta["ALGO"]
	require.Equal(t, basics.SetUintAction, vd.Action)
	require.Equal(t, 0, len(delta.LocalDeltas))
	require.Equal(t, 0, ledger.localCount)
	require.Equal(t, 1, ledger.globalCount)

	ledger.resetCounters()
	delete(ledger.applications[100], "ALGOA")
	delete(ledger.applications[100], "ALGO")

	ledger.applications[100]["ALGO"] = algoValue

	// check delete,write,delete existing
	source = `byte 0x414c474f   // key "ALGO"
app_global_del
byte 0x414c474f
int 0x78
app_global_put
byte 0x414c474f
app_global_del
int 1
`
	program, err = AssembleString(source)
	require.NoError(t, err)
	cost, err = CheckStateful(program, ep)
	require.NoError(t, err)
	require.True(t, cost < 1000)
	pass, delta, err = EvalStateful(program, ep)
	require.NoError(t, err)
	require.True(t, pass)
	require.Equal(t, 1, len(delta.GlobalDelta))
	vd = delta.GlobalDelta["ALGO"]
	require.Equal(t, basics.DeleteAction, vd.Action)
	require.Equal(t, 0, len(delta.LocalDeltas))
	require.Equal(t, 0, ledger.localCount)
	require.Equal(t, 1, ledger.globalCount)

	ledger.resetCounters()
	delete(ledger.applications[100], "ALGOA")
	delete(ledger.applications[100], "ALGO")

	ledger.applications[100]["ALGO"] = algoValue

	// check delete,write,delete non-existing
	source = `byte 0x414c474f41   // key "ALGOA"
app_global_del
byte 0x414c474f41
int 0x78
app_global_put
byte 0x414c474f41
app_global_del
int 1
`
	program, err = AssembleString(source)
	require.NoError(t, err)
	cost, err = CheckStateful(program, ep)
	require.NoError(t, err)
	require.True(t, cost < 1000)
	pass, delta, err = EvalStateful(program, ep)
	require.NoError(t, err)
	require.True(t, pass)
	require.Equal(t, 0, len(delta.GlobalDelta))
	require.Equal(t, 0, len(delta.LocalDeltas))
	require.Equal(t, 0, ledger.localCount)
	require.Equal(t, 1, ledger.globalCount)
}

func TestAppLocalDelete(t *testing.T) {
	t.Parallel()

	// check write/delete/read
	source := `int 0  // account
byte 0x414c474f       // key "ALGO"
int 0x77              // value
app_local_put
int 1
byte 0x414c474f41     // key "ALGOA"
byte 0x414c474f
app_local_put
int 0
byte 0x414c474f
app_local_del
int 1
byte 0x414c474f41
app_local_del
int 0
int 0
byte 0x414c474f
app_local_get
bnz error
int 1
int 100
byte 0x414c474f41
app_local_get
bnz error
==
bnz ok
error:
err
ok:
int 1
`
	ep := defaultEvalParams(nil, nil)
	txn := makeSampleTxn()
	txn.Txn.ApplicationID = 100
	ep.Txn = &txn
	ledger := makeTestLedger(
		map[basics.Address]uint64{
			txn.Txn.Sender: 1,
		},
	)
	ep.Ledger = ledger
	ledger.newApp(txn.Txn.Sender, 100)
	ledger.balances[txn.Txn.Receiver] = makeBalanceRecord(txn.Txn.Receiver, 1)
	ledger.balances[txn.Txn.Receiver].apps[100] = make(basics.TealKeyValue)

	sb := strings.Builder{}
	ep.Trace = &sb

	program, err := AssembleString(source)
	require.NoError(t, err)
	cost, err := CheckStateful(program, ep)
	require.NoError(t, err)
	require.True(t, cost < 1000)
	pass, delta, err := EvalStateful(program, ep)
	if !pass {
		t.Log(hex.EncodeToString(program))
		t.Log(sb.String())
	}
	require.NoError(t, err)
	require.True(t, pass)
	require.Equal(t, 0, len(delta.GlobalDelta))
	require.Equal(t, 0, len(delta.LocalDeltas))
	require.Equal(t, 2, ledger.localCount)
	require.Equal(t, 0, ledger.globalCount)

	ledger.resetCounters()
	delete(ledger.balances[txn.Txn.Sender].apps[100], "ALGOA")
	delete(ledger.balances[txn.Txn.Sender].apps[100], "ALGO")
	delete(ledger.balances[txn.Txn.Receiver].apps[100], "ALGOA")
	delete(ledger.balances[txn.Txn.Receiver].apps[100], "ALGO")

	algoValue := basics.TealValue{Type: basics.TealUintType, Uint: 0x77}
	ledger.balances[txn.Txn.Sender].apps[100]["ALGO"] = algoValue

	// check delete existing
	source = `int 0  // account
byte 0x414c474f      // key "ALGO"
app_local_del
int 0
int 100
byte 0x414c474f
app_local_get
==  // two zeros
`

	program, err = AssembleString(source)
	require.NoError(t, err)
	cost, err = CheckStateful(program, ep)
	require.NoError(t, err)
	require.True(t, cost < 1000)
	pass, delta, err = EvalStateful(program, ep)
	require.NoError(t, err)
	require.True(t, pass)
	require.Equal(t, 0, len(delta.GlobalDelta))
	require.Equal(t, 1, len(delta.LocalDeltas))
	vd := delta.LocalDeltas[txn.Txn.Sender]["ALGO"]
	require.Equal(t, basics.DeleteAction, vd.Action)
	require.Equal(t, uint64(0), vd.Uint)
	require.Equal(t, "", vd.Bytes)
	require.Equal(t, 1, ledger.localCount)
	require.Equal(t, 0, ledger.globalCount)

	ledger.resetCounters()
	delete(ledger.balances[txn.Txn.Sender].apps[100], "ALGOA")
	delete(ledger.balances[txn.Txn.Sender].apps[100], "ALGO")

	ledger.balances[txn.Txn.Sender].apps[100]["ALGO"] = algoValue

	// check delete and write non-existing
	source = `int 0  // account
byte 0x414c474f41    // key "ALGOA"
app_local_del
int 0
int 0
byte 0x414c474f41
app_local_get
==  // two zeros
int 0
byte 0x414c474f41
int 0x78
app_local_put
`
	program, err = AssembleString(source)
	require.NoError(t, err)
	cost, err = CheckStateful(program, ep)
	require.NoError(t, err)
	require.True(t, cost < 1000)
	pass, delta, err = EvalStateful(program, ep)
	require.NoError(t, err)
	require.True(t, pass)
	require.Equal(t, 0, len(delta.GlobalDelta))
	require.Equal(t, 1, len(delta.LocalDeltas))
	vd = delta.LocalDeltas[txn.Txn.Sender]["ALGOA"]
	require.Equal(t, basics.SetUintAction, vd.Action)
	require.Equal(t, uint64(0x78), vd.Uint)
	require.Equal(t, "", vd.Bytes)
	require.Equal(t, 1, ledger.localCount)
	require.Equal(t, 0, ledger.globalCount)

	ledger.resetCounters()
	delete(ledger.balances[txn.Txn.Sender].apps[100], "ALGOA")
	delete(ledger.balances[txn.Txn.Sender].apps[100], "ALGO")

	ledger.balances[txn.Txn.Sender].apps[100]["ALGO"] = algoValue

	// check delete and write existing
	source = `int 0   // account
byte 0x414c474f       // key "ALGO"
app_local_del
int 0
byte 0x414c474f
int 0x78
app_local_put
int 1
`
	program, err = AssembleString(source)
	require.NoError(t, err)
	cost, err = CheckStateful(program, ep)
	require.NoError(t, err)
	require.True(t, cost < 1000)
	pass, delta, err = EvalStateful(program, ep)
	require.NoError(t, err)
	require.True(t, pass)
	require.Equal(t, 0, len(delta.GlobalDelta))
	require.Equal(t, 1, len(delta.LocalDeltas))
	vd = delta.LocalDeltas[txn.Txn.Sender]["ALGO"]
	require.Equal(t, basics.SetUintAction, vd.Action)
	require.Equal(t, uint64(0x78), vd.Uint)
	require.Equal(t, "", vd.Bytes)
	require.Equal(t, 1, ledger.localCount)
	require.Equal(t, 0, ledger.globalCount)

	ledger.resetCounters()
	delete(ledger.balances[txn.Txn.Sender].apps[100], "ALGOA")
	delete(ledger.balances[txn.Txn.Sender].apps[100], "ALGO")

	ledger.balances[txn.Txn.Sender].apps[100]["ALGO"] = algoValue

	// check delete,write,delete existing
	source = `int 0  // account
byte 0x414c474f      // key "ALGO"
app_local_del
int 0
byte 0x414c474f
int 0x78
app_local_put
int 0
byte 0x414c474f
app_local_del
int 1
`
	program, err = AssembleString(source)
	require.NoError(t, err)
	cost, err = CheckStateful(program, ep)
	require.NoError(t, err)
	require.True(t, cost < 1000)
	pass, delta, err = EvalStateful(program, ep)
	require.NoError(t, err)
	require.True(t, pass)
	require.Equal(t, 0, len(delta.GlobalDelta))
	require.Equal(t, 1, len(delta.LocalDeltas))
	vd = delta.LocalDeltas[txn.Txn.Sender]["ALGO"]
	require.Equal(t, basics.DeleteAction, vd.Action)
	require.Equal(t, uint64(0), vd.Uint)
	require.Equal(t, "", vd.Bytes)
	require.Equal(t, 1, ledger.localCount)
	require.Equal(t, 0, ledger.globalCount)

	ledger.resetCounters()
	delete(ledger.balances[txn.Txn.Sender].apps[100], "ALGOA")
	delete(ledger.balances[txn.Txn.Sender].apps[100], "ALGO")

	ledger.balances[txn.Txn.Sender].apps[100]["ALGO"] = algoValue

	// check delete,write,delete non-existing
	source = `int 0  // account
byte 0x414c474f41    // key "ALGOA"
app_local_del
int 0
byte 0x414c474f41
int 0x78
app_local_put
int 0
byte 0x414c474f41
app_local_del
int 1
`
	program, err = AssembleString(source)
	require.NoError(t, err)
	cost, err = CheckStateful(program, ep)
	require.NoError(t, err)
	require.True(t, cost < 1000)
	pass, delta, err = EvalStateful(program, ep)
	require.NoError(t, err)
	require.True(t, pass)
	require.Equal(t, 0, len(delta.GlobalDelta))
	require.Equal(t, 0, len(delta.LocalDeltas))
	require.Equal(t, 1, ledger.localCount)
	require.Equal(t, 0, ledger.globalCount)
}

func TestEnumFieldErrors(t *testing.T) {
	ep := defaultEvalParams(nil, nil)

	source := `txn Amount`
	origTxnType := TxnFieldTypes[Amount]
	TxnFieldTypes[Amount] = StackBytes
	defer func() {
		TxnFieldTypes[Amount] = origTxnType
	}()

	program, err := AssembleString(source)
	require.NoError(t, err)
	_, err = Eval(program, ep)
	require.Error(t, err)
	require.Contains(t, err.Error(), "Amount expected field type is []byte but got uint64")
	_, _, err = EvalStateful(program, ep)
	require.Error(t, err)
	require.Contains(t, err.Error(), "Amount expected field type is []byte but got uint64")

	source = `global MinTxnFee`
	origGlobalType := GlobalFieldTypes[MinTxnFee]
	GlobalFieldTypes[MinTxnFee] = StackBytes
	defer func() {
		GlobalFieldTypes[MinTxnFee] = origGlobalType
	}()

	program, err = AssembleString(source)
	require.NoError(t, err)
	_, err = Eval(program, ep)
	require.Error(t, err)
	require.Contains(t, err.Error(), "MinTxnFee expected field type is []byte but got uint64")
	_, _, err = EvalStateful(program, ep)
	require.Error(t, err)
	require.Contains(t, err.Error(), "MinTxnFee expected field type is []byte but got uint64")

	txn := makeSampleTxn()
	ledger := makeTestLedger(
		map[basics.Address]uint64{
			txn.Txn.Sender: 1,
		},
	)
	params := basics.AssetParams{
		Total:         1000,
		Decimals:      2,
		DefaultFrozen: false,
		UnitName:      "ALGO",
		AssetName:     "",
		URL:           string(protocol.PaymentTx),
		Manager:       txn.Txn.Sender,
		Reserve:       txn.Txn.Receiver,
		Freeze:        txn.Txn.Receiver,
		Clawback:      txn.Txn.Receiver,
	}
	ledger.setAsset(txn.Txn.Receiver, 55, params)
	ledger.setHolding(txn.Txn.Sender, 55, basics.AssetHolding{Amount: 123, Frozen: true})

	ep.Txn = &txn
	ep.Ledger = ledger

	source = `int 0
int 55
asset_holding_get AssetBalance
pop
`
	origAssetHoldingType := AssetHoldingFieldTypes[AssetBalance]
	AssetHoldingFieldTypes[AssetBalance] = StackBytes
	defer func() {
		AssetHoldingFieldTypes[AssetBalance] = origAssetHoldingType
	}()

	program, err = AssembleString(source)
	require.NoError(t, err)
	_, _, err = EvalStateful(program, ep)
	require.Error(t, err)
	require.Contains(t, err.Error(), "AssetBalance expected field type is []byte but got uint64")

	source = `int 1
int 55
asset_params_get AssetTotal
pop
`
	origAssetTotalType := AssetParamsFieldTypes[AssetTotal]
	AssetParamsFieldTypes[AssetTotal] = StackBytes
	defer func() {
		AssetParamsFieldTypes[AssetTotal] = origAssetTotalType
	}()

	program, err = AssembleString(source)
	require.NoError(t, err)
	_, _, err = EvalStateful(program, ep)
	require.Error(t, err)
	require.Contains(t, err.Error(), "AssetTotal expected field type is []byte but got uint64")
}
