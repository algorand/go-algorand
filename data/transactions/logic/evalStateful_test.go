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

package logic

import (
	"encoding/hex"
	"fmt"
	"math/rand"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/transactions"
	"github.com/algorand/go-algorand/protocol"
)

type balanceRecord struct {
	addr     basics.Address
	balance  uint64
	locals   map[basics.AppIndex]basics.TealKeyValue
	holdings map[uint64]basics.AssetHolding
	mods     map[basics.AppIndex]map[string]basics.ValueDelta
}

// In our test ledger, we don't store the AppParams with its creator,
// so we need to carry the creator arround with the params,
type appParams struct {
	basics.AppParams
	Creator basics.Address
}

type testLedger struct {
	balances     map[basics.Address]balanceRecord
	applications map[basics.AppIndex]appParams
	assets       map[basics.AssetIndex]basics.AssetParams
	appID        basics.AppIndex
	creatorAddr  basics.Address
	mods         map[basics.AppIndex]map[string]basics.ValueDelta
}

func makeSchemas(li uint64, lb uint64, gi uint64, gb uint64) basics.StateSchemas {
	return basics.StateSchemas{
		LocalStateSchema:  basics.StateSchema{NumUint: li, NumByteSlice: lb},
		GlobalStateSchema: basics.StateSchema{NumUint: gi, NumByteSlice: gb},
	}
}

func makeBalanceRecord(addr basics.Address, balance uint64) balanceRecord {
	br := balanceRecord{
		addr:     addr,
		balance:  balance,
		locals:   make(map[basics.AppIndex]basics.TealKeyValue),
		holdings: make(map[uint64]basics.AssetHolding),
		mods:     make(map[basics.AppIndex]map[string]basics.ValueDelta),
	}
	return br
}

func makeTestLedger(balances map[basics.Address]uint64) *testLedger {
	l := new(testLedger)
	l.balances = make(map[basics.Address]balanceRecord)
	for addr, balance := range balances {
		l.balances[addr] = makeBalanceRecord(addr, balance)
	}
	l.applications = make(map[basics.AppIndex]appParams)
	l.assets = make(map[basics.AssetIndex]basics.AssetParams)
	l.mods = make(map[basics.AppIndex]map[string]basics.ValueDelta)
	return l
}

func (l *testLedger) reset() {
	l.mods = make(map[basics.AppIndex]map[string]basics.ValueDelta)
	for addr, br := range l.balances {
		br.mods = make(map[basics.AppIndex]map[string]basics.ValueDelta)
		l.balances[addr] = br
	}
}

func (l *testLedger) newApp(addr basics.Address, appID basics.AppIndex, schemas basics.StateSchemas) {
	l.appID = appID
	appIdx := appID
	l.applications[appIdx] = appParams{
		Creator: addr,
		AppParams: basics.AppParams{
			StateSchemas: schemas,
			GlobalState:  make(basics.TealKeyValue),
		},
	}
	br, ok := l.balances[addr]
	if !ok {
		br = makeBalanceRecord(addr, 0)
	}
	br.locals[appIdx] = make(map[string]basics.TealValue)
	l.balances[addr] = br
}

func (l *testLedger) newAsset(creator basics.Address, assetID uint64, params basics.AssetParams) {
	l.assets[basics.AssetIndex(assetID)] = params
	// We're not simulating details of ReserveAddress yet.
	l.setHolding(creator, assetID, params.Total, params.DefaultFrozen)
}

func (l *testLedger) setHolding(addr basics.Address, assetID uint64, amount uint64, frozen bool) {
	br, ok := l.balances[addr]
	if !ok {
		br = makeBalanceRecord(addr, 0)
	}
	br.holdings[assetID] = basics.AssetHolding{Amount: amount, Frozen: frozen}
	l.balances[addr] = br
}

func (l *testLedger) Round() basics.Round {
	return basics.Round(rand.Uint32() + 1)
}

func (l *testLedger) LatestTimestamp() int64 {
	return int64(rand.Uint32() + 1)
}

func (l *testLedger) Balance(addr basics.Address) (amount basics.MicroAlgos, err error) {
	if l.balances == nil {
		err = fmt.Errorf("empty ledger")
		return
	}
	br, ok := l.balances[addr]
	if !ok {
		err = fmt.Errorf("no such address")
		return
	}
	return basics.MicroAlgos{Raw: br.balance}, nil
}

func (l *testLedger) MinBalance(addr basics.Address, proto *config.ConsensusParams) (amount basics.MicroAlgos, err error) {
	if l.balances == nil {
		err = fmt.Errorf("empty ledger")
		return
	}
	br, ok := l.balances[addr]
	if !ok {
		err = fmt.Errorf("no such address")
		return
	}

	var min uint64

	// First, base MinBalance
	min = proto.MinBalance

	// MinBalance for each Asset
	assetCost := basics.MulSaturate(proto.MinBalance, uint64(len(br.holdings)))
	min = basics.AddSaturate(min, assetCost)

	// Base MinBalance + GlobalStateSchema.MinBalance for each created application
	for _, params := range l.applications {
		if params.Creator == addr {
			min = basics.AddSaturate(min, proto.AppFlatParamsMinBalance)
			min = basics.AddSaturate(min, params.GlobalStateSchema.MinBalance(proto).Raw)
		}
	}

	// Base MinBalance + LocalStateSchema.MinBalance for each opted in application
	for idx := range br.locals {
		min = basics.AddSaturate(min, proto.AppFlatParamsMinBalance)
		min = basics.AddSaturate(min, l.applications[idx].LocalStateSchema.MinBalance(proto).Raw)
	}

	return basics.MicroAlgos{Raw: min}, nil
}

func (l *testLedger) GetGlobal(appIdx basics.AppIndex, key string) (basics.TealValue, bool, error) {
	if appIdx == basics.AppIndex(0) {
		appIdx = l.appID
	}
	params, ok := l.applications[appIdx]
	if !ok {
		return basics.TealValue{}, false, fmt.Errorf("no such app")
	}

	// return most recent value if available
	tkvm, ok := l.mods[appIdx]
	if ok {
		val, ok := tkvm[key]
		if ok {
			tv, ok := val.ToTealValue()
			return tv, ok, nil
		}
	}

	// otherwise return original one
	val, ok := params.GlobalState[key]
	return val, ok, nil
}

func (l *testLedger) SetGlobal(key string, value basics.TealValue) error {
	appIdx := l.appID
	params, ok := l.applications[appIdx]
	if !ok {
		return fmt.Errorf("no such app")
	}

	// if writing the same value, return
	// this simulates real ledger behavior for tests
	val, ok := params.GlobalState[key]
	if ok && val == value {
		return nil
	}

	// write to deltas
	_, ok = l.mods[appIdx]
	if !ok {
		l.mods[appIdx] = make(map[string]basics.ValueDelta)
	}
	l.mods[appIdx][key] = value.ToValueDelta()
	return nil
}

func (l *testLedger) DelGlobal(key string) error {
	appIdx := l.appID
	params, ok := l.applications[appIdx]
	if !ok {
		return fmt.Errorf("no such app")
	}

	exist := false
	if _, ok := params.GlobalState[key]; ok {
		exist = true
	}

	_, ok = l.mods[appIdx]
	if !ok && !exist {
		// nothing to delete
		return nil
	}
	if !ok {
		l.mods[appIdx] = make(map[string]basics.ValueDelta)
	}
	_, ok = l.mods[appIdx][key]
	if ok || exist {
		l.mods[appIdx][key] = basics.ValueDelta{Action: basics.DeleteAction}
	}
	return nil
}

func (l *testLedger) GetLocal(addr basics.Address, appIdx basics.AppIndex, key string) (basics.TealValue, bool, error) {
	if appIdx == 0 {
		appIdx = l.appID
	}
	br, ok := l.balances[addr]
	if !ok {
		return basics.TealValue{}, false, fmt.Errorf("no such address")
	}
	tkvd, ok := br.locals[appIdx]
	if !ok {
		return basics.TealValue{}, false, fmt.Errorf("no app for account")
	}

	// check deltas first
	tkvm, ok := br.mods[appIdx]
	if ok {
		val, ok := tkvm[key]
		if ok {
			tv, ok := val.ToTealValue()
			return tv, ok, nil
		}
	}

	val, ok := tkvd[key]
	return val, ok, nil
}

func (l *testLedger) SetLocal(addr basics.Address, key string, value basics.TealValue) error {
	appIdx := l.appID

	br, ok := l.balances[addr]
	if !ok {
		return fmt.Errorf("no such address")
	}
	tkv, ok := br.locals[appIdx]
	if !ok {
		return fmt.Errorf("no app for account")
	}

	// if writing the same value, return
	// this simulates real ledger behavior for tests
	val, ok := tkv[key]
	if ok && val == value {
		return nil
	}

	// write to deltas
	_, ok = br.mods[appIdx]
	if !ok {
		br.mods[appIdx] = make(map[string]basics.ValueDelta)
	}
	br.mods[appIdx][key] = value.ToValueDelta()
	return nil
}

func (l *testLedger) DelLocal(addr basics.Address, key string) error {
	appIdx := l.appID

	br, ok := l.balances[addr]
	if !ok {
		return fmt.Errorf("no such address")
	}
	tkv, ok := br.locals[appIdx]
	if !ok {
		return fmt.Errorf("no app for account")
	}
	exist := false
	if _, ok := tkv[key]; ok {
		exist = true
	}

	_, ok = br.mods[appIdx]
	if !ok && !exist {
		// nothing to delete
		return nil
	}
	if !ok {
		br.mods[appIdx] = make(map[string]basics.ValueDelta)
	}
	_, ok = br.mods[appIdx][key]
	if ok || exist {
		br.mods[appIdx][key] = basics.ValueDelta{Action: basics.DeleteAction}
	}
	return nil
}

func (l *testLedger) OptedIn(addr basics.Address, appIdx basics.AppIndex) (bool, error) {
	if appIdx == 0 {
		appIdx = l.appID
	}
	br, ok := l.balances[addr]
	if !ok {
		return false, fmt.Errorf("no such address")
	}
	_, ok = br.locals[appIdx]
	return ok, nil
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

func (l *testLedger) AssetParams(assetID basics.AssetIndex) (basics.AssetParams, error) {
	if asset, ok := l.assets[assetID]; ok {
		return asset, nil
	}
	return basics.AssetParams{}, fmt.Errorf("no such asset")
}

func (l *testLedger) ApplicationID() basics.AppIndex {
	return l.appID
}

func (l *testLedger) CreatorAddress() basics.Address {
	return l.creatorAddr
}

func (l *testLedger) LocalSchema() basics.StateSchema {
	return basics.StateSchema{
		NumUint:      100,
		NumByteSlice: 100,
	}
}

func (l *testLedger) GlobalSchema() basics.StateSchema {
	return basics.StateSchema{
		NumUint:      100,
		NumByteSlice: 100,
	}
}

func (l *testLedger) GetDelta(txn *transactions.Transaction) (evalDelta basics.EvalDelta, err error) {
	if tkv, ok := l.mods[l.appID]; ok {
		evalDelta.GlobalDelta = tkv
	}
	if len(txn.Accounts) > 0 {
		accounts := make(map[basics.Address]int)
		accounts[txn.Sender] = 0
		for idx, addr := range txn.Accounts {
			accounts[addr] = idx + 1
		}
		evalDelta.LocalDeltas = make(map[uint64]basics.StateDelta)
		for addr, br := range l.balances {
			if idx, ok := accounts[addr]; ok {
				if delta, ok := br.mods[l.appID]; ok {
					evalDelta.LocalDeltas[uint64(idx)] = delta
				}
			}
		}
	}
	return
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
int 0
min_balance
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
app_local_get_ex
pop
&&
int 0
bytec_0
app_global_get_ex
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
		runModeSignature: {
			source: opcodesRunModeAny + opcodesRunModeSignature,
			eval:   func(program []byte, ep EvalParams) (bool, error) { return Eval(program, ep) },
			check:  func(program []byte, ep EvalParams) (int, error) { return Check(program, ep) },
		},
		runModeApplication: {
			source: opcodesRunModeAny + opcodesRunModeApplication,
			eval: func(program []byte, ep EvalParams) (bool, error) {
				pass, err := EvalStateful(program, ep)
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
	ledger.newApp(txn.Txn.Sender, 100, makeSchemas(0, 0, 0, 0))
	ledger.balances[txn.Txn.Sender].locals[100]["ALGO"] = algoValue
	ledger.newAsset(txn.Txn.Sender, 5, params)

	for mode, test := range tests {
		t.Run(fmt.Sprintf("opcodes_mode=%d", mode), func(t *testing.T) {
			ops := testProg(t, test.source, AssemblerMaxVersion)
			sb := strings.Builder{}
			ep := defaultEvalParams(&sb, &txn)
			ep.TxnGroup = txgroup
			ep.Ledger = ledger
			ep.Txn.Txn.ApplicationID = 100
			_, err := test.check(ops.Program, ep)
			require.NoError(t, err)
			_, err = test.eval(ops.Program, ep)
			if err != nil {
				t.Log(hex.EncodeToString(ops.Program))
				t.Log(sb.String())
			}
			require.NoError(t, err)
		})
	}

	// check err opcode work in both modes
	for mode, test := range tests {
		t.Run(fmt.Sprintf("err_mode=%d", mode), func(t *testing.T) {
			source := "err"
			ops, err := AssembleStringWithVersion(source, AssemblerMaxVersion)
			require.NoError(t, err)
			ep := defaultEvalParams(nil, nil)
			_, err = test.check(ops.Program, ep)
			require.NoError(t, err)
			_, err = test.eval(ops.Program, ep)
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
		ops, err := AssembleStringWithVersion(source, AssemblerMaxVersion)
		require.NoError(t, err)
		ep := defaultEvalParams(nil, nil)
		_, err = CheckStateful(ops.Program, ep)
		require.Error(t, err)
		_, err = EvalStateful(ops.Program, ep)
		require.Error(t, err)
		require.Contains(t, err.Error(), "not allowed in current mode")
	}

	// check stateful opcodes are not allowed in stateless mode
	statefulOpcodeCalls := []string{
		"int 0\nbalance",
		"int 0\nmin_balance",
		"int 0\nint 0\napp_opted_in",
		"int 0\nint 0\nbyte 0x01\napp_local_get_ex",
		"byte 0x01\napp_global_get",
		"int 0\nbyte 0x01\napp_global_get_ex",
		"int 1\nbyte 0x01\nbyte 0x01\napp_local_put",
		"byte 0x01\nint 0\napp_global_put",
		"int 0\nbyte 0x01\napp_local_del",
		"byte 0x01\napp_global_del",
		"int 0\nint 0\nasset_holding_get AssetFrozen",
		"int 0\nint 0\nasset_params_get AssetManager",
	}

	for _, source := range statefulOpcodeCalls {
		ops := testProg(t, source, AssemblerMaxVersion)
		ep := defaultEvalParams(nil, nil)
		_, err := Check(ops.Program, ep)
		require.Error(t, err)
		_, err = Eval(ops.Program, ep)
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
int 177
==`
	ops, err := AssembleStringWithVersion(text, AssemblerMaxVersion)
	require.NoError(t, err)

	txn := makeSampleTxn()
	txgroup := makeSampleTxnGroup(txn)
	ep := defaultEvalParams(nil, nil)
	ep.Txn = &txn
	ep.TxnGroup = txgroup
	_, err = EvalStateful(ops.Program, ep)
	require.Error(t, err)
	require.Contains(t, err.Error(), "ledger not available")

	ep.Ledger = makeTestLedger(
		map[basics.Address]uint64{
			txn.Txn.Receiver: 177,
		},
	)
	_, err = EvalStateful(ops.Program, ep)
	require.Error(t, err)
	require.Contains(t, err.Error(), "cannot load account")

	text = `int 1
balance
int 177
==`
	ops, err = AssembleStringWithVersion(text, AssemblerMaxVersion)
	require.NoError(t, err)
	cost, err := CheckStateful(ops.Program, ep)
	require.NoError(t, err)
	require.True(t, cost < 1000)
	pass, err := EvalStateful(ops.Program, ep)
	require.NoError(t, err)
	require.True(t, pass)

	text = `int 0
balance
int 13
==`
	ops, err = AssembleStringWithVersion(text, AssemblerMaxVersion)
	require.NoError(t, err)
	var addr basics.Address
	copy(addr[:], []byte("aoeuiaoeuiaoeuiaoeuiaoeuiaoeui02"))
	ep.Ledger = makeTestLedger(
		map[basics.Address]uint64{
			addr: 13,
		},
	)
	pass, err = EvalStateful(ops.Program, ep)
	require.Error(t, err)
	require.Contains(t, err.Error(), "failed to fetch balance")
	require.False(t, pass)

	ep.Ledger = makeTestLedger(
		map[basics.Address]uint64{
			txn.Txn.Sender: 13,
		},
	)
	cost, err = CheckStateful(ops.Program, ep)
	require.NoError(t, err)
	require.True(t, cost < 1000)
	pass, err = EvalStateful(ops.Program, ep)
	require.NoError(t, err)
	require.True(t, pass)
}

func testApp(t *testing.T, program string, ep EvalParams, problems ...string) basics.EvalDelta {
	ops := testProg(t, program, AssemblerMaxVersion)
	sb := &strings.Builder{}
	ep.Trace = sb
	cost, err := CheckStateful(ops.Program, ep)
	require.NoError(t, err)
	require.True(t, cost < 1000)

	// we only use this to test stateful apps.  While, I suppose
	// it's *legal* to have an app with no stateful ops, this
	// convenience routine can assume it, and check it.
	pass, err := Eval(ops.Program, ep)
	require.Error(t, err)
	require.Contains(t, err.Error(), "not allowed in current mode")
	require.False(t, pass)

	pass, err = EvalStateful(ops.Program, ep)
	if len(problems) == 0 {
		require.NoError(t, err, sb.String())
		require.True(t, pass, sb.String())
		delta, err := ep.Ledger.GetDelta(&ep.Txn.Txn)
		require.NoError(t, err)
		return delta
	} else {
		require.Error(t, err, sb.String())
		for _, problem := range problems {
			require.Contains(t, err.Error(), problem)
		}
		if ep.Ledger != nil {
			delta, err := ep.Ledger.GetDelta(&ep.Txn.Txn)
			require.NoError(t, err)
			require.Empty(t, delta.GlobalDelta)
			require.Empty(t, delta.LocalDeltas)
			return delta
		}
		return basics.EvalDelta{}
	}
}

func TestMinBalance(t *testing.T) {
	t.Parallel()

	txn := makeSampleTxn()
	txgroup := makeSampleTxnGroup(txn)
	ep := defaultEvalParams(nil, nil)
	ep.Txn = &txn
	ep.TxnGroup = txgroup

	testApp(t, "int 0; min_balance; int 1001; ==", ep, "ledger not available")

	ledger := makeTestLedger(
		map[basics.Address]uint64{
			txn.Txn.Sender:   234, // min_balance 0 is Sender
			txn.Txn.Receiver: 123, // Accounts[0] has been packed with the Receiver
		},
	)
	ep.Ledger = ledger

	testApp(t, "int 0; min_balance; int 1001; ==", ep)
	// Sender makes an asset, min blance goes up
	ledger.newAsset(txn.Txn.Sender, 7, basics.AssetParams{Total: 1000})
	testApp(t, "int 0; min_balance; int 2002; ==", ep)
	schemas := makeSchemas(1, 2, 3, 4)
	ledger.newApp(txn.Txn.Sender, 77, schemas)
	// create + optin + 10 schema base + 4 ints + 6 bytes (local
	// and global count b/c newApp opts the creator in)
	minb := 2*1002 + 10*1003 + 4*1004 + 6*1005
	testApp(t, fmt.Sprintf("int 0; min_balance; int %d; ==", 2002+minb), ep)

	testApp(t, "int 1; min_balance; int 1001; ==", ep) // 1 == Accounts[0]
	// Receiver opts in
	ledger.setHolding(txn.Txn.Receiver, 7, 1, true)
	testApp(t, "int 1; min_balance; int 2002; ==", ep) // 1 == Accounts[0]

	testApp(t, "int 2; min_balance; int 1001; ==", ep, "cannot load account")

}

func TestAppCheckOptedIn(t *testing.T) {
	t.Parallel()

	txn := makeSampleTxn()
	txgroup := makeSampleTxnGroup(txn)
	ep := defaultEvalParams(nil, nil)
	ep.Txn = &txn
	ep.TxnGroup = txgroup
	testApp(t, "int 2; int 100; app_opted_in; int 1; ==", ep, "ledger not available")

	ledger := makeTestLedger(
		map[basics.Address]uint64{
			txn.Txn.Receiver: 1,
			txn.Txn.Sender:   1,
		},
	)
	ep.Ledger = ledger
	testApp(t, "int 2; int 100; app_opted_in; int 1; ==", ep, "cannot load account")

	// Receiver is not opted in
	testApp(t, "int 1; int 100; app_opted_in; int 0; ==", ep)

	// Sender is not opted in
	testApp(t, "int 0; int 100; app_opted_in; int 0; ==", ep)

	// Receiver opted in
	ledger.newApp(txn.Txn.Receiver, 100, makeSchemas(0, 0, 0, 0))
	testApp(t, "int 1; int 100; app_opted_in; int 1; ==", ep)

	// Sender opted in
	ledger.newApp(txn.Txn.Sender, 100, makeSchemas(0, 0, 0, 0))
	testApp(t, "int 0; int 100; app_opted_in; int 1; ==", ep)
}

func TestAppReadLocalState(t *testing.T) {
	t.Parallel()

	text := `int 2  // account idx
int 100 // app id
txn ApplicationArgs 0
app_local_get_ex
bnz exist
int 0
==
bnz exit
exist:
err
exit:
int 1
==`

	txn := makeSampleTxn()
	txgroup := makeSampleTxnGroup(txn)
	ep := defaultEvalParams(nil, nil)
	ep.Txn = &txn
	ep.Txn.Txn.ApplicationID = 100
	ep.TxnGroup = txgroup

	testApp(t, text, ep, "ledger not available")

	ledger := makeTestLedger(
		map[basics.Address]uint64{
			txn.Txn.Receiver: 1,
		},
	)
	ep.Ledger = ledger
	testApp(t, text, ep, "cannot load account")

	text = `int 1  // account idx
int 100 // app id
txn ApplicationArgs 0
app_local_get_ex
bnz exist
int 0
==
bnz exit
exist:
err
exit:
int 1`

	testApp(t, text, ep, "no app for account")

	ledger = makeTestLedger(
		map[basics.Address]uint64{
			txn.Txn.Receiver: 1,
		},
	)
	ep.Ledger = ledger
	ledger.newApp(txn.Txn.Receiver, 9999, makeSchemas(0, 0, 0, 0))

	testApp(t, text, ep, "no app for account")

	// create the app and check the value from ApplicationArgs[0] (protocol.PaymentTx) does not exist
	ledger.newApp(txn.Txn.Receiver, 100, makeSchemas(0, 0, 0, 0))
	testApp(t, text, ep)

	text = `int 1  // account idx
int 100 // app id
txn ApplicationArgs 0
app_local_get_ex
bnz exist
err
exist:
byte 0x414c474f
==`
	ledger.balances[txn.Txn.Receiver].locals[100][string(protocol.PaymentTx)] = basics.TealValue{Type: basics.TealBytesType, Bytes: "ALGO"}

	testApp(t, text, ep)

	// check special case account idx == 0 => sender
	ledger.newApp(txn.Txn.Sender, 100, makeSchemas(0, 0, 0, 0))
	text = `int 0  // account idx
int 100 // app id
txn ApplicationArgs 0
app_local_get_ex
bnz exist
err
exist:
byte 0x414c474f
==`

	ledger.balances[txn.Txn.Sender].locals[100][string(protocol.PaymentTx)] = basics.TealValue{Type: basics.TealBytesType, Bytes: "ALGO"}
	testApp(t, text, ep)

	// check reading state of other app
	ledger.newApp(txn.Txn.Sender, 101, makeSchemas(0, 0, 0, 0))
	ledger.newApp(txn.Txn.Sender, 100, makeSchemas(0, 0, 0, 0))
	text = `int 0  // account idx
int 101 // app id
txn ApplicationArgs 0
app_local_get_ex
bnz exist
err
exist:
byte 0x414c474f
==`

	ledger.balances[txn.Txn.Sender].locals[101][string(protocol.PaymentTx)] = basics.TealValue{Type: basics.TealBytesType, Bytes: "ALGO"}
	testApp(t, text, ep)

	// check app_local_get
	text = `int 0  // account idx
txn ApplicationArgs 0
app_local_get
byte 0x414c474f
==`

	ledger.balances[txn.Txn.Sender].locals[100][string(protocol.PaymentTx)] = basics.TealValue{Type: basics.TealBytesType, Bytes: "ALGO"}
	testApp(t, text, ep)

	// check app_local_get default value
	text = `int 0  // account idx
byte 0x414c474f
app_local_get
int 0
==`

	ledger.balances[txn.Txn.Sender].locals[100][string(protocol.PaymentTx)] = basics.TealValue{Type: basics.TealBytesType, Bytes: "ALGO"}
	testApp(t, text, ep)
}

func TestAppReadGlobalState(t *testing.T) {
	t.Parallel()

	text := `int 0
txn ApplicationArgs 0
app_global_get_ex
bnz exist
err
exist:
byte 0x414c474f
==
int 1  // ForeignApps index
txn ApplicationArgs 0
app_global_get_ex
bnz exist1
err
exist1:
byte 0x414c474f
==
&&
txn ApplicationArgs 0
app_global_get
byte 0x414c474f
==
&&
`
	ops, err := AssembleStringWithVersion(text, AssemblerMaxVersion)
	require.NoError(t, err)

	txn := makeSampleTxn()
	txgroup := makeSampleTxnGroup(txn)
	ep := defaultEvalParams(nil, nil)
	ep.Txn = &txn
	ep.TxnGroup = txgroup
	cost, err := CheckStateful(ops.Program, ep)
	require.NoError(t, err)
	require.True(t, cost < 1000)
	_, err = EvalStateful(ops.Program, ep)
	require.Error(t, err)
	require.Contains(t, err.Error(), "ledger not available")

	ledger := makeTestLedger(
		map[basics.Address]uint64{
			txn.Txn.Sender: 1,
		},
	)
	ep.Ledger = ledger

	ep.Txn.Txn.ApplicationID = 100
	ep.Txn.Txn.ForeignApps = []basics.AppIndex{ep.Txn.Txn.ApplicationID}
	_, err = EvalStateful(ops.Program, ep)
	require.Error(t, err)
	require.Contains(t, err.Error(), "no such app")

	// create the app and check the value from ApplicationArgs[0] (protocol.PaymentTx) does not exist
	ledger.newApp(txn.Txn.Sender, 100, makeSchemas(0, 0, 0, 1))

	_, err = EvalStateful(ops.Program, ep)
	require.Error(t, err)
	require.Contains(t, err.Error(), "err opcode")

	ledger.applications[100].GlobalState[string(protocol.PaymentTx)] = basics.TealValue{Type: basics.TealBytesType, Bytes: "ALGO"}

	cost, err = CheckStateful(ops.Program, ep)
	require.NoError(t, err)
	require.True(t, cost < 1000)
	pass, err := EvalStateful(ops.Program, ep)
	require.NoError(t, err)
	require.True(t, pass)

	// check error on invalid app index for app_global_get_ex
	text = `int 2
txn ApplicationArgs 0
app_global_get_ex
`
	ops, err = AssembleStringWithVersion(text, AssemblerMaxVersion)
	require.NoError(t, err)

	_, err = EvalStateful(ops.Program, ep)
	require.Error(t, err)
	require.Contains(t, err.Error(), "invalid ForeignApps index 2")

	// check app_local_get default value
	text = `byte 0x414c474f55
app_global_get
int 0
==`

	ops, err = AssembleStringWithVersion(text, AssemblerMaxVersion)
	require.NoError(t, err)

	ledger.balances[txn.Txn.Sender].locals[100][string(protocol.PaymentTx)] = basics.TealValue{Type: basics.TealBytesType, Bytes: "ALGO"}
	pass, err = EvalStateful(ops.Program, ep)
	require.NoError(t, err)
	require.True(t, pass)

	text = `
byte 0x41414141
int 4141
app_global_put
int 1  // ForeignApps index
byte 0x41414141
app_global_get_ex
bnz exist
err
exist:
int 4141
==
`
	// check that even during application creation (Txn.ApplicationID == 0)
	// we will use the the kvCow if the exact application ID (100) is
	// specified in the transaction
	ops, err = AssembleStringWithVersion(text, AssemblerMaxVersion)
	require.NoError(t, err)

	ep.Txn.Txn.ApplicationID = 0
	ep.Txn.Txn.ForeignApps = []basics.AppIndex{100}
	pass, err = EvalStateful(ops.Program, ep)
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
int 0
asset_params_get AssetTotal
!
bnz error
int 1000
==
&&
int 0
asset_params_get AssetDecimals
!
bnz error
int 2
==
&&
int 0
asset_params_get AssetDefaultFrozen
!
bnz error
int 0
==
&&
int 0
asset_params_get AssetUnitName
!
bnz error
byte 0x414c474f
==
&&
int 0
asset_params_get AssetName
!
bnz error
len
int 0
==
&&
int 0
asset_params_get AssetURL
!
bnz error
txna ApplicationArgs 0
==
&&
int 0
asset_params_get AssetMetadataHash
!
bnz error
byte 0x0000000000000000000000000000000000000000000000000000000000000000
==
&&
int 0
asset_params_get AssetManager
!
bnz error
txna Accounts 0
==
&&
int 0
asset_params_get AssetReserve
!
bnz error
txna Accounts 1
==
&&
int 0
asset_params_get AssetFreeze
!
bnz error
txna Accounts 1
==
&&
int 0
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

	type sourceError struct {
		src string
		err string
	}
	// check generic errors
	sources := []sourceError{
		{"int 5\nint 55\nasset_holding_get AssetBalance", "cannot load account[5]"},
		{"int 5\nasset_params_get AssetTotal", "invalid ForeignAssets index 5"},
	}
	for _, sourceErr := range sources {
		ops, err := AssembleStringWithVersion(sourceErr.src, AssemblerMaxVersion)
		require.NoError(t, err)

		txn := makeSampleTxn()
		ep := defaultEvalParams(nil, nil)
		ep.Txn = &txn
		cost, err := CheckStateful(ops.Program, ep)
		require.NoError(t, err)
		require.True(t, cost < 1000)
		_, err = EvalStateful(ops.Program, ep)
		require.Error(t, err)
		require.Contains(t, err.Error(), "ledger not available")

		ledger := makeTestLedger(
			map[basics.Address]uint64{
				txn.Txn.Sender: 1,
			},
		)
		ep.Ledger = ledger

		_, err = EvalStateful(ops.Program, ep)
		require.Error(t, err)
		require.Contains(t, err.Error(), sourceErr.err)
	}

	ops, err := AssembleStringWithVersion(assetsTestProgram, AssemblerMaxVersion)
	require.NoError(t, err)
	cost, err := CheckStateful(ops.Program, defaultEvalParams(nil, nil))
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
	ledger.newAsset(txn.Txn.Sender, 55, params)
	ledger.setHolding(txn.Txn.Sender, 55, 123, true)

	ep := defaultEvalParams(&sb, &txn)
	ep.Ledger = ledger
	cost, err = CheckStateful(ops.Program, ep)
	require.NoError(t, err)
	require.True(t, cost < 1000)
	pass, err := EvalStateful(ops.Program, ep)
	if !pass {
		t.Log(hex.EncodeToString(ops.Program))
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
	ops, err = AssembleStringWithVersion(source, AssemblerMaxVersion)
	require.NoError(t, err)
	ledger.setHolding(txn.Txn.Sender, 55, 123, false)
	cost, err = CheckStateful(ops.Program, ep)
	require.NoError(t, err)
	require.True(t, cost < 1000)
	pass, err = EvalStateful(ops.Program, ep)
	require.NoError(t, err)
	require.True(t, pass)

	// check holdings invalid offsets
	require.Equal(t, opsByName[ep.Proto.LogicSigVersion]["asset_holding_get"].Opcode, ops.Program[8])
	ops.Program[9] = 0x02
	_, err = EvalStateful(ops.Program, ep)
	require.Error(t, err)
	require.Contains(t, err.Error(), "invalid asset holding field 2")

	// check holdings bool value
	source = `int 0
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
	ops, err = AssembleStringWithVersion(source, AssemblerMaxVersion)
	require.NoError(t, err)
	params.DefaultFrozen = true
	ledger.newAsset(txn.Txn.Sender, 55, params)
	pass, err = EvalStateful(ops.Program, ep)
	require.NoError(t, err)
	require.True(t, pass)
	// check holdings invalid offsets
	require.Equal(t, opsByName[ep.Proto.LogicSigVersion]["asset_params_get"].Opcode, ops.Program[6])
	ops.Program[7] = 0x20
	_, err = EvalStateful(ops.Program, ep)
	require.Error(t, err)
	require.Contains(t, err.Error(), "invalid asset params field 32")

	// check empty string
	source = `int 0  // foreign asset idx (txn.ForeignAssets[0])
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
	ops, err = AssembleStringWithVersion(source, AssemblerMaxVersion)
	require.NoError(t, err)
	params.URL = ""
	ledger.newAsset(txn.Txn.Sender, 55, params)
	pass, err = EvalStateful(ops.Program, ep)
	require.NoError(t, err)
	require.True(t, pass)

	source = `int 1  // foreign asset idx (txn.ForeignAssets[1])
asset_params_get AssetURL
!
bnz error
len
int 9
==
bnz ok
error:
err
ok:
int 1
`
	ops, err = AssembleStringWithVersion(source, AssemblerMaxVersion)
	require.NoError(t, err)
	params.URL = "foobarbaz"
	ledger.newAsset(txn.Txn.Sender, 77, params)
	pass, err = EvalStateful(ops.Program, ep)
	require.NoError(t, err)
	require.True(t, pass)

	source = `int 0
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
	ops, err = AssembleStringWithVersion(source, AssemblerMaxVersion)
	require.NoError(t, err)
	params.URL = ""
	ledger.newAsset(txn.Txn.Sender, 55, params)
	cost, err = CheckStateful(ops.Program, ep)
	require.NoError(t, err)
	require.True(t, cost < 1000)
	pass, err = EvalStateful(ops.Program, ep)
	require.Error(t, err)
	require.Contains(t, err.Error(), "cannot compare ([]byte == uint64)")
	require.False(t, pass)
}

func TestAppLocalReadWriteDeleteErrors(t *testing.T) {
	t.Parallel()

	sourceRead := `int 0  // account idx (txn.Sender)
int 100                   // app id
byte 0x414c474f           // key "ALGO"
app_local_get_ex
!
bnz error
int 0x77
==
int 0
int 100
byte 0x414c474f41         // ALGOA
app_local_get_ex
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
		"read":   {sourceRead, 20},
		"write":  {sourceWrite, 13},
		"delete": {sourceDelete, 12},
	}
	for name, test := range tests {
		t.Run(fmt.Sprintf("test=%s", name), func(t *testing.T) {
			source := test.source
			firstCmdOffset := test.accNumOffset

			ops, err := AssembleStringWithVersion(source, AssemblerMaxVersion)
			require.NoError(t, err)

			txn := makeSampleTxn()
			ep := defaultEvalParams(nil, nil)
			ep.Txn = &txn
			ep.Txn.Txn.ApplicationID = 100
			cost, err := CheckStateful(ops.Program, ep)
			require.NoError(t, err)
			require.True(t, cost < 1000)
			_, err = EvalStateful(ops.Program, ep)
			require.Error(t, err)
			require.Contains(t, err.Error(), "ledger not available")

			ledger := makeTestLedger(
				map[basics.Address]uint64{
					txn.Txn.Sender: 1,
				},
			)
			ep.Ledger = ledger

			saved := ops.Program[firstCmdOffset]
			require.Equal(t, opsByName[0]["intc_0"].Opcode, saved)
			ops.Program[firstCmdOffset] = opsByName[0]["intc_1"].Opcode
			_, err = EvalStateful(ops.Program, ep)
			require.Error(t, err)
			require.Contains(t, err.Error(), "cannot load account[100]")

			ops.Program[firstCmdOffset] = saved
			_, err = EvalStateful(ops.Program, ep)
			require.Error(t, err)
			require.Contains(t, err.Error(), "no app for account")

			ledger.newApp(txn.Txn.Sender, 100, makeSchemas(0, 0, 0, 0))

			if name == "read" {
				_, err = EvalStateful(ops.Program, ep)
				require.Error(t, err)
				require.Contains(t, err.Error(), "err opcode") // no such key
			}

			ledger.balances[txn.Txn.Sender].locals[100]["ALGO"] = basics.TealValue{Type: basics.TealUintType, Uint: 0x77}
			ledger.balances[txn.Txn.Sender].locals[100]["ALGOA"] = basics.TealValue{Type: basics.TealUintType, Uint: 1}

			ledger.reset()
			pass, err := EvalStateful(ops.Program, ep)
			require.NoError(t, err)
			require.True(t, pass)
			delta, err := ledger.GetDelta(&ep.Txn.Txn)
			require.NoError(t, err)
			require.Empty(t, delta.GlobalDelta)
			expLocal := 1
			if name == "read" {
				expLocal = 0
			}
			require.Len(t, delta.LocalDeltas, expLocal)
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
	ledger.newApp(txn.Txn.Sender, 100, makeSchemas(0, 0, 0, 0))

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
app_local_get_ex
bnz exist
err
exist:
byte 0x414c474f
==
int 0                // account
int 100              // app id
byte 0x414c474f      // key "ALGO"
app_local_get_ex
bnz exist2
err
exist2:
int 0x77
==
&&
`
	ops, err := AssembleStringWithVersion(source, AssemblerMaxVersion)
	require.NoError(t, err)
	cost, err := CheckStateful(ops.Program, ep)
	require.NoError(t, err)
	require.True(t, cost < 1000)
	pass, err := EvalStateful(ops.Program, ep)
	require.NoError(t, err)
	require.True(t, pass)
	delta, err := ledger.GetDelta(&ep.Txn.Txn)
	require.NoError(t, err)
	require.Empty(t, 0, delta.GlobalDelta)
	require.Len(t, delta.LocalDeltas, 1)

	require.Len(t, delta.LocalDeltas[0], 2)
	vd := delta.LocalDeltas[0]["ALGO"]
	require.Equal(t, basics.SetUintAction, vd.Action)
	require.Equal(t, uint64(0x77), vd.Uint)

	vd = delta.LocalDeltas[0]["ALGOA"]
	require.Equal(t, basics.SetBytesAction, vd.Action)
	require.Equal(t, "ALGO", vd.Bytes)

	// write same value without writing, expect no local delta
	source = `int 0  // account
byte 0x414c474f       // key
int 0x77              // value
app_local_put
int 0                 // account
int 100               // app id
byte 0x414c474f       // key
app_local_get_ex
bnz exist
err
exist:
int 0x77
==
`
	ledger.reset()
	delete(ledger.balances[txn.Txn.Sender].locals[100], "ALGOA")
	delete(ledger.balances[txn.Txn.Sender].locals[100], "ALGO")

	algoValue := basics.TealValue{Type: basics.TealUintType, Uint: 0x77}
	ledger.balances[txn.Txn.Sender].locals[100]["ALGO"] = algoValue

	ops, err = AssembleStringWithVersion(source, AssemblerMaxVersion)
	require.NoError(t, err)
	cost, err = CheckStateful(ops.Program, ep)
	require.NoError(t, err)
	require.True(t, cost < 1000)
	pass, err = EvalStateful(ops.Program, ep)
	require.NoError(t, err)
	require.True(t, pass)
	delta, err = ledger.GetDelta(&ep.Txn.Txn)
	require.NoError(t, err)
	require.Empty(t, delta.GlobalDelta)
	require.Empty(t, delta.LocalDeltas)

	// write same value after reading, expect no local delta
	source = `int 0  // account
int 100              // app id
byte 0x414c474f      // key
app_local_get_ex
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
app_local_get_ex
bnz exist2
err
exist2:
==
`
	ledger.reset()
	ledger.balances[txn.Txn.Sender].locals[100]["ALGO"] = algoValue
	delete(ledger.balances[txn.Txn.Sender].locals[100], "ALGOA")

	ops, err = AssembleStringWithVersion(source, AssemblerMaxVersion)
	require.NoError(t, err)
	pass, err = EvalStateful(ops.Program, ep)
	require.NoError(t, err)
	require.True(t, pass)
	delta, err = ledger.GetDelta(&ep.Txn.Txn)
	require.NoError(t, err)
	require.Empty(t, delta.GlobalDelta)
	require.Empty(t, delta.LocalDeltas)

	// write a value and expect local delta change
	source = `int 0  // account
byte 0x414c474f41    // key "ALGOA"
int 0x78             // value
app_local_put
int 1
`
	ledger.reset()
	ledger.balances[txn.Txn.Sender].locals[100]["ALGO"] = algoValue
	delete(ledger.balances[txn.Txn.Sender].locals[100], "ALGOA")

	ops, err = AssembleStringWithVersion(source, AssemblerMaxVersion)
	require.NoError(t, err)
	pass, err = EvalStateful(ops.Program, ep)
	require.NoError(t, err)
	require.True(t, pass)
	delta, err = ledger.GetDelta(&ep.Txn.Txn)
	require.NoError(t, err)
	require.Empty(t, delta.GlobalDelta)
	require.Len(t, delta.LocalDeltas, 1)
	require.Len(t, delta.LocalDeltas[0], 1)
	vd = delta.LocalDeltas[0]["ALGOA"]
	require.Equal(t, basics.SetUintAction, vd.Action)
	require.Equal(t, uint64(0x78), vd.Uint)

	// write a value to existing key and expect delta change and reading the new value
	source = `int 0  // account
byte 0x414c474f      // key "ALGO"
int 0x78             // value
app_local_put
int 0                // account
int 100              // app id
byte 0x414c474f      // key "ALGO"
app_local_get_ex
bnz exist
err
exist:
int 0x78
==
`
	ledger.reset()
	ledger.balances[txn.Txn.Sender].locals[100]["ALGO"] = algoValue
	delete(ledger.balances[txn.Txn.Sender].locals[100], "ALGOA")

	ops, err = AssembleStringWithVersion(source, AssemblerMaxVersion)
	require.NoError(t, err)
	pass, err = EvalStateful(ops.Program, ep)
	require.NoError(t, err)
	require.True(t, pass)
	delta, err = ledger.GetDelta(&ep.Txn.Txn)
	require.NoError(t, err)
	require.Empty(t, delta.GlobalDelta)
	require.Len(t, delta.LocalDeltas, 1)
	require.Len(t, delta.LocalDeltas[0], 1)
	vd = delta.LocalDeltas[0]["ALGO"]
	require.Equal(t, basics.SetUintAction, vd.Action)
	require.Equal(t, uint64(0x78), vd.Uint)

	// write a value after read and expect delta change
	source = `int 0  // account
int 100              // app id
byte 0x414c474f      // key "ALGO"
app_local_get_ex
bnz exist
err
exist:
int 0  				 // account
byte 0x414c474f      // key "ALGO"
int 0x78             // value
app_local_put
`
	ledger.reset()
	ledger.balances[txn.Txn.Sender].locals[100]["ALGO"] = algoValue
	delete(ledger.balances[txn.Txn.Sender].locals[100], "ALGOA")

	ops, err = AssembleStringWithVersion(source, AssemblerMaxVersion)
	require.NoError(t, err)
	pass, err = EvalStateful(ops.Program, ep)
	require.NoError(t, err)
	require.True(t, pass)
	delta, err = ledger.GetDelta(&ep.Txn.Txn)
	require.NoError(t, err)
	require.Empty(t, delta.GlobalDelta)
	require.Len(t, delta.LocalDeltas, 1)
	require.Len(t, delta.LocalDeltas[0], 1)
	vd = delta.LocalDeltas[0]["ALGO"]
	require.Equal(t, basics.SetUintAction, vd.Action)
	require.Equal(t, uint64(0x78), vd.Uint)

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
	ledger.reset()
	ledger.balances[txn.Txn.Sender].locals[100]["ALGO"] = algoValue
	delete(ledger.balances[txn.Txn.Sender].locals[100], "ALGOA")

	ledger.balances[txn.Txn.Receiver] = makeBalanceRecord(txn.Txn.Receiver, 500)
	ledger.balances[txn.Txn.Receiver].locals[100] = make(basics.TealKeyValue)

	ops, err = AssembleStringWithVersion(source, AssemblerMaxVersion)
	require.NoError(t, err)
	cost, err = CheckStateful(ops.Program, ep)
	require.NoError(t, err)
	require.True(t, cost < 1000)
	pass, err = EvalStateful(ops.Program, ep)
	require.NoError(t, err)
	require.True(t, pass)
	delta, err = ledger.GetDelta(&ep.Txn.Txn)
	require.NoError(t, err)
	require.Empty(t, delta.GlobalDelta)
	require.Len(t, delta.LocalDeltas, 2)
	require.Len(t, delta.LocalDeltas[0], 2)
	require.Len(t, delta.LocalDeltas[1], 1)
	vd = delta.LocalDeltas[0]["ALGO"]
	require.Equal(t, basics.SetUintAction, vd.Action)
	require.Equal(t, uint64(0x78), vd.Uint)

	vd = delta.LocalDeltas[0]["ALGOA"]
	require.Equal(t, basics.SetUintAction, vd.Action)
	require.Equal(t, uint64(0x78), vd.Uint)

	vd = delta.LocalDeltas[1]["ALGO"]
	require.Equal(t, basics.SetUintAction, vd.Action)
	require.Equal(t, uint64(0x79), vd.Uint)
}

func TestAppGlobalReadWriteDeleteErrors(t *testing.T) {
	t.Parallel()

	sourceRead := `int 0
byte 0x414c474f  // key "ALGO"
app_global_get_ex
bnz ok
err
ok:
int 0x77
==
`
	sourceReadSimple := `byte 0x414c474f  // key "ALGO"
app_global_get
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
		"reads":  sourceReadSimple,
		"write":  sourceWrite,
		"delete": sourceDelete,
	}
	for name, source := range tests {
		t.Run(fmt.Sprintf("test=%s", name), func(t *testing.T) {
			ops, err := AssembleStringWithVersion(source, AssemblerMaxVersion)
			require.NoError(t, err)

			txn := makeSampleTxn()
			ep := defaultEvalParams(nil, nil)
			ep.Txn = &txn
			_, err = EvalStateful(ops.Program, ep)
			require.Error(t, err)
			require.Contains(t, err.Error(), "ledger not available")

			ledger := makeTestLedger(
				map[basics.Address]uint64{
					txn.Txn.Sender: 1,
				},
			)
			ep.Ledger = ledger

			txn.Txn.ApplicationID = 100
			_, err = EvalStateful(ops.Program, ep)
			require.Error(t, err)
			require.Contains(t, err.Error(), "no such app")

			ledger.newApp(txn.Txn.Sender, 100, makeSchemas(0, 0, 1, 0))

			// a special test for read
			if name == "read" {
				_, err = EvalStateful(ops.Program, ep)
				require.Error(t, err)
				require.Contains(t, err.Error(), "err opcode") // no such key
			}
			ledger.applications[100].GlobalState["ALGO"] = basics.TealValue{Type: basics.TealUintType, Uint: 0x77}

			ledger.reset()
			pass, err := EvalStateful(ops.Program, ep)
			require.NoError(t, err)
			require.True(t, pass)
			delta, err := ledger.GetDelta(&ep.Txn.Txn)
			require.NoError(t, err)

			require.Empty(t, delta.LocalDeltas)
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
byte 0x414c474f    // value
app_global_put
// check simple
byte 0x414c474f41  // key "ALGOA"
app_global_get
byte 0x414c474f
==
// check generic with alias
int 0 // current app id alias
byte 0x414c474f41  // key "ALGOA"
app_global_get_ex
bnz ok
err
ok:
byte 0x414c474f
==
&&
// check generic with exact app id
int 1 // ForeignApps index - current app
byte 0x414c474f41  // key "ALGOA"
app_global_get_ex
bnz ok1
err
ok1:
byte 0x414c474f
==
&&
// check simple
byte 0x414c474f
app_global_get
int 0x77
==
&&
// check generic with alias
int 0 // ForeignApps index - current app
byte 0x414c474f
app_global_get_ex
bnz ok2
err
ok2:
int 0x77
==
&&
// check generic with exact app id
int 1 // ForeignApps index - current app
byte 0x414c474f
app_global_get_ex
bnz ok3
err
ok3:
int 0x77
==
&&
`
	ep := defaultEvalParams(nil, nil)
	txn := makeSampleTxn()
	txn.Txn.ApplicationID = 100
	txn.Txn.ForeignApps = []basics.AppIndex{txn.Txn.ApplicationID}
	ep.Txn = &txn
	ledger := makeTestLedger(
		map[basics.Address]uint64{
			txn.Txn.Sender: 1,
		},
	)
	ep.Ledger = ledger
	ledger.newApp(txn.Txn.Sender, 100, makeSchemas(0, 0, 0, 0))

	ops, err := AssembleStringWithVersion(source, AssemblerMaxVersion)
	require.NoError(t, err)
	cost, err := CheckStateful(ops.Program, ep)
	require.NoError(t, err)
	require.True(t, cost < 1000)
	pass, err := EvalStateful(ops.Program, ep)
	require.NoError(t, err)
	require.True(t, pass)
	delta, err := ledger.GetDelta(&ep.Txn.Txn)
	require.NoError(t, err)

	require.Len(t, delta.GlobalDelta, 2)
	require.Empty(t, delta.LocalDeltas)

	vd := delta.GlobalDelta["ALGO"]
	require.Equal(t, basics.SetUintAction, vd.Action)
	require.Equal(t, uint64(0x77), vd.Uint)

	vd = delta.GlobalDelta["ALGOA"]
	require.Equal(t, basics.SetBytesAction, vd.Action)
	require.Equal(t, "ALGO", vd.Bytes)

	// write existing value before read
	source = `byte 0x414c474f  // key "ALGO"
int 0x77						// value
app_global_put
byte 0x414c474f
app_global_get
int 0x77
==
`
	ledger.reset()
	delete(ledger.applications[100].GlobalState, "ALGOA")
	delete(ledger.applications[100].GlobalState, "ALGO")

	algoValue := basics.TealValue{Type: basics.TealUintType, Uint: 0x77}
	ledger.applications[100].GlobalState["ALGO"] = algoValue

	ops, err = AssembleStringWithVersion(source, AssemblerMaxVersion)
	require.NoError(t, err)
	pass, err = EvalStateful(ops.Program, ep)
	require.NoError(t, err)
	require.True(t, pass)
	delta, err = ledger.GetDelta(&ep.Txn.Txn)
	require.NoError(t, err)

	require.Empty(t, delta.GlobalDelta)
	require.Empty(t, delta.LocalDeltas)

	// write existing value after read
	source = `int 0
byte 0x414c474f
app_global_get_ex
bnz ok
err
ok:
pop
byte 0x414c474f
int 0x77
app_global_put
byte 0x414c474f
app_global_get
int 0x77
==
`
	ledger.reset()
	delete(ledger.applications[100].GlobalState, "ALGOA")
	ledger.applications[100].GlobalState["ALGO"] = algoValue

	ops, err = AssembleStringWithVersion(source, AssemblerMaxVersion)
	require.NoError(t, err)
	pass, err = EvalStateful(ops.Program, ep)
	require.NoError(t, err)
	require.True(t, pass)
	delta, err = ledger.GetDelta(&ep.Txn.Txn)
	require.NoError(t, err)
	require.Empty(t, delta.GlobalDelta)
	require.Empty(t, delta.LocalDeltas)

	// write new values after and before read
	source = `int 0
byte 0x414c474f
app_global_get_ex
bnz ok
err
ok:
pop
byte 0x414c474f
int 0x78
app_global_put
int 0
byte 0x414c474f
app_global_get_ex
bnz ok2
err
ok2:
int 0x78
==
byte 0x414c474f41
byte 0x414c474f
app_global_put
int 0
byte 0x414c474f41
app_global_get_ex
bnz ok3
err
ok3:
byte 0x414c474f
==
&&
`
	ledger.reset()
	delete(ledger.applications[100].GlobalState, "ALGOA")
	ledger.applications[100].GlobalState["ALGO"] = algoValue

	ops, err = AssembleStringWithVersion(source, AssemblerMaxVersion)
	require.NoError(t, err)
	sb := strings.Builder{}
	ep.Trace = &sb
	cost, err = CheckStateful(ops.Program, ep)
	require.NoError(t, err)
	require.True(t, cost < 1000)
	pass, err = EvalStateful(ops.Program, ep)
	if !pass {
		t.Log(hex.EncodeToString(ops.Program))
		t.Log(sb.String())
	}
	require.NoError(t, err)
	require.True(t, pass)
	delta, err = ledger.GetDelta(&ep.Txn.Txn)
	require.NoError(t, err)

	require.Len(t, delta.GlobalDelta, 2)
	require.Empty(t, delta.LocalDeltas)

	vd = delta.GlobalDelta["ALGO"]
	require.Equal(t, basics.SetUintAction, vd.Action)
	require.Equal(t, uint64(0x78), vd.Uint)

	vd = delta.GlobalDelta["ALGOA"]
	require.Equal(t, basics.SetBytesAction, vd.Action)
	require.Equal(t, "ALGO", vd.Bytes)
}

func TestAppGlobalReadOtherApp(t *testing.T) {
	t.Parallel()
	source := `int 2 // ForeignApps index
byte "mykey1"
app_global_get_ex
bz ok1
err
ok1:
pop
int 2 // ForeignApps index
byte "mykey"
app_global_get_ex
bnz ok2
err
ok2:
byte "myval"
==
`
	ep := defaultEvalParams(nil, nil)
	txn := makeSampleTxn()
	txn.Txn.ApplicationID = 100
	txn.Txn.ForeignApps = []basics.AppIndex{txn.Txn.ApplicationID, 101}
	ep.Txn = &txn
	ledger := makeTestLedger(
		map[basics.Address]uint64{
			txn.Txn.Sender: 1,
		},
	)
	ep.Ledger = ledger
	ledger.newApp(txn.Txn.Sender, 100, makeSchemas(0, 0, 0, 0))

	delta := testApp(t, source, ep, "no such app")
	require.Empty(t, delta.GlobalDelta)
	require.Empty(t, delta.LocalDeltas)

	ledger.newApp(txn.Txn.Receiver, 101, makeSchemas(0, 0, 0, 0))
	ledger.newApp(txn.Txn.Receiver, 100, makeSchemas(0, 0, 0, 0)) // this keeps current app id = 100
	algoValue := basics.TealValue{Type: basics.TealBytesType, Bytes: "myval"}
	ledger.applications[101].GlobalState["mykey"] = algoValue

	delta = testApp(t, source, ep)
	require.Empty(t, delta.GlobalDelta)
	require.Empty(t, delta.LocalDeltas)
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
int 0
byte 0x414c474f
app_global_get_ex
bnz error
int 0
byte 0x414c474f41
app_global_get_ex
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
	ledger.newApp(txn.Txn.Sender, 100, makeSchemas(0, 0, 0, 0))

	delta := testApp(t, source, ep)
	require.Len(t, delta.GlobalDelta, 2)
	require.Empty(t, delta.LocalDeltas)

	ledger.reset()
	delete(ledger.applications[100].GlobalState, "ALGOA")
	delete(ledger.applications[100].GlobalState, "ALGO")

	algoValue := basics.TealValue{Type: basics.TealUintType, Uint: 0x77}
	ledger.applications[100].GlobalState["ALGO"] = algoValue

	// check delete existing
	source = `byte 0x414c474f   // key "ALGO"
app_global_del
int 1
byte 0x414c474f
app_global_get_ex
==  // two zeros
`
	ep.Txn.Txn.ForeignApps = []basics.AppIndex{txn.Txn.ApplicationID}
	delta = testApp(t, source, ep)
	require.Len(t, delta.GlobalDelta, 1)
	vd := delta.GlobalDelta["ALGO"]
	require.Equal(t, basics.DeleteAction, vd.Action)
	require.Equal(t, uint64(0), vd.Uint)
	require.Equal(t, "", vd.Bytes)
	require.Equal(t, 0, len(delta.LocalDeltas))

	ledger.reset()
	delete(ledger.applications[100].GlobalState, "ALGOA")
	delete(ledger.applications[100].GlobalState, "ALGO")

	ledger.applications[100].GlobalState["ALGO"] = algoValue

	// check delete and write non-existing
	source = `byte 0x414c474f41   // key "ALGOA"
app_global_del
int 0
byte 0x414c474f41
app_global_get_ex
==  // two zeros
byte 0x414c474f41
int 0x78
app_global_put
`
	delta = testApp(t, source, ep)
	require.Len(t, delta.GlobalDelta, 1)
	vd = delta.GlobalDelta["ALGOA"]
	require.Equal(t, basics.SetUintAction, vd.Action)
	require.Equal(t, uint64(0x78), vd.Uint)
	require.Equal(t, "", vd.Bytes)
	require.Empty(t, delta.LocalDeltas)

	ledger.reset()
	delete(ledger.applications[100].GlobalState, "ALGOA")
	delete(ledger.applications[100].GlobalState, "ALGO")

	ledger.applications[100].GlobalState["ALGO"] = algoValue

	// check delete and write existing
	source = `byte 0x414c474f   // key "ALGO"
app_global_del
byte 0x414c474f
int 0x78
app_global_put
int 1
`
	delta = testApp(t, source, ep)
	require.Len(t, delta.GlobalDelta, 1)
	vd = delta.GlobalDelta["ALGO"]
	require.Equal(t, basics.SetUintAction, vd.Action)
	require.Empty(t, delta.LocalDeltas)

	ledger.reset()
	delete(ledger.applications[100].GlobalState, "ALGOA")
	delete(ledger.applications[100].GlobalState, "ALGO")

	ledger.applications[100].GlobalState["ALGO"] = algoValue

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
	delta = testApp(t, source, ep)
	require.Len(t, delta.GlobalDelta, 1)
	vd = delta.GlobalDelta["ALGO"]
	require.Equal(t, basics.DeleteAction, vd.Action)
	require.Empty(t, delta.LocalDeltas)

	ledger.reset()
	delete(ledger.applications[100].GlobalState, "ALGOA")
	delete(ledger.applications[100].GlobalState, "ALGO")

	ledger.applications[100].GlobalState["ALGO"] = algoValue

	// check delete, write, delete non-existing
	source = `byte 0x414c474f41   // key "ALGOA"
app_global_del
byte 0x414c474f41
int 0x78
app_global_put
byte 0x414c474f41
app_global_del
int 1
`
	delta = testApp(t, source, ep)
	require.Len(t, delta.GlobalDelta, 1)
	require.Len(t, delta.LocalDeltas, 0)
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
app_local_get_ex
bnz error
int 1
int 100
byte 0x414c474f41
app_local_get_ex
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
	ledger.newApp(txn.Txn.Sender, 100, makeSchemas(0, 0, 0, 0))
	ledger.balances[txn.Txn.Receiver] = makeBalanceRecord(txn.Txn.Receiver, 1)
	ledger.balances[txn.Txn.Receiver].locals[100] = make(basics.TealKeyValue)

	sb := strings.Builder{}
	ep.Trace = &sb

	ops, err := AssembleStringWithVersion(source, AssemblerMaxVersion)
	require.NoError(t, err)
	cost, err := CheckStateful(ops.Program, ep)
	require.NoError(t, err)
	require.True(t, cost < 1000)
	pass, err := EvalStateful(ops.Program, ep)
	if !pass {
		t.Log(hex.EncodeToString(ops.Program))
		t.Log(sb.String())
	}
	require.NoError(t, err)
	require.True(t, pass)
	delta, err := ledger.GetDelta(&ep.Txn.Txn)
	require.NoError(t, err)
	require.Equal(t, 0, len(delta.GlobalDelta))
	require.Equal(t, 2, len(delta.LocalDeltas))

	ledger.reset()
	delete(ledger.balances[txn.Txn.Sender].locals[100], "ALGOA")
	delete(ledger.balances[txn.Txn.Sender].locals[100], "ALGO")
	delete(ledger.balances[txn.Txn.Receiver].locals[100], "ALGOA")
	delete(ledger.balances[txn.Txn.Receiver].locals[100], "ALGO")

	algoValue := basics.TealValue{Type: basics.TealUintType, Uint: 0x77}
	ledger.balances[txn.Txn.Sender].locals[100]["ALGO"] = algoValue

	// check delete existing
	source = `int 0  // account
byte 0x414c474f      // key "ALGO"
app_local_del
int 0
int 100
byte 0x414c474f
app_local_get_ex
==  // two zeros
`

	ops, err = AssembleStringWithVersion(source, AssemblerMaxVersion)
	require.NoError(t, err)
	cost, err = CheckStateful(ops.Program, ep)
	require.NoError(t, err)
	require.True(t, cost < 1000)
	pass, err = EvalStateful(ops.Program, ep)
	require.NoError(t, err)
	require.True(t, pass)
	delta, err = ledger.GetDelta(&ep.Txn.Txn)
	require.NoError(t, err)
	require.Equal(t, 0, len(delta.GlobalDelta))
	require.Equal(t, 1, len(delta.LocalDeltas))
	vd := delta.LocalDeltas[0]["ALGO"]
	require.Equal(t, basics.DeleteAction, vd.Action)
	require.Equal(t, uint64(0), vd.Uint)
	require.Equal(t, "", vd.Bytes)

	ledger.reset()
	delete(ledger.balances[txn.Txn.Sender].locals[100], "ALGOA")
	delete(ledger.balances[txn.Txn.Sender].locals[100], "ALGO")

	ledger.balances[txn.Txn.Sender].locals[100]["ALGO"] = algoValue

	// check delete and write non-existing
	source = `int 0  // account
byte 0x414c474f41    // key "ALGOA"
app_local_del
int 0
int 0
byte 0x414c474f41
app_local_get_ex
==  // two zeros
int 0
byte 0x414c474f41
int 0x78
app_local_put
`
	ops, err = AssembleStringWithVersion(source, AssemblerMaxVersion)
	require.NoError(t, err)
	cost, err = CheckStateful(ops.Program, ep)
	require.NoError(t, err)
	require.True(t, cost < 1000)
	pass, err = EvalStateful(ops.Program, ep)
	require.NoError(t, err)
	require.True(t, pass)
	delta, err = ledger.GetDelta(&ep.Txn.Txn)
	require.NoError(t, err)
	require.Equal(t, 0, len(delta.GlobalDelta))
	require.Equal(t, 1, len(delta.LocalDeltas))
	vd = delta.LocalDeltas[0]["ALGOA"]
	require.Equal(t, basics.SetUintAction, vd.Action)
	require.Equal(t, uint64(0x78), vd.Uint)
	require.Equal(t, "", vd.Bytes)

	ledger.reset()
	delete(ledger.balances[txn.Txn.Sender].locals[100], "ALGOA")
	delete(ledger.balances[txn.Txn.Sender].locals[100], "ALGO")

	ledger.balances[txn.Txn.Sender].locals[100]["ALGO"] = algoValue

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
	ops, err = AssembleStringWithVersion(source, AssemblerMaxVersion)
	require.NoError(t, err)
	cost, err = CheckStateful(ops.Program, ep)
	require.NoError(t, err)
	require.True(t, cost < 1000)
	pass, err = EvalStateful(ops.Program, ep)
	require.NoError(t, err)
	require.True(t, pass)
	delta, err = ledger.GetDelta(&ep.Txn.Txn)
	require.NoError(t, err)
	require.Equal(t, 0, len(delta.GlobalDelta))
	require.Equal(t, 1, len(delta.LocalDeltas))
	vd = delta.LocalDeltas[0]["ALGO"]
	require.Equal(t, basics.SetUintAction, vd.Action)
	require.Equal(t, uint64(0x78), vd.Uint)
	require.Equal(t, "", vd.Bytes)

	ledger.reset()
	delete(ledger.balances[txn.Txn.Sender].locals[100], "ALGOA")
	delete(ledger.balances[txn.Txn.Sender].locals[100], "ALGO")

	ledger.balances[txn.Txn.Sender].locals[100]["ALGO"] = algoValue

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
	ops, err = AssembleStringWithVersion(source, AssemblerMaxVersion)
	require.NoError(t, err)
	cost, err = CheckStateful(ops.Program, ep)
	require.NoError(t, err)
	require.True(t, cost < 1000)
	pass, err = EvalStateful(ops.Program, ep)
	require.NoError(t, err)
	require.True(t, pass)
	delta, err = ledger.GetDelta(&ep.Txn.Txn)
	require.NoError(t, err)
	require.Equal(t, 0, len(delta.GlobalDelta))
	require.Equal(t, 1, len(delta.LocalDeltas))
	vd = delta.LocalDeltas[0]["ALGO"]
	require.Equal(t, basics.DeleteAction, vd.Action)
	require.Equal(t, uint64(0), vd.Uint)
	require.Equal(t, "", vd.Bytes)

	ledger.reset()
	delete(ledger.balances[txn.Txn.Sender].locals[100], "ALGOA")
	delete(ledger.balances[txn.Txn.Sender].locals[100], "ALGO")

	ledger.balances[txn.Txn.Sender].locals[100]["ALGO"] = algoValue

	// check delete, write, delete non-existing
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
	ops, err = AssembleStringWithVersion(source, AssemblerMaxVersion)
	require.NoError(t, err)
	cost, err = CheckStateful(ops.Program, ep)
	require.NoError(t, err)
	require.True(t, cost < 1000)
	pass, err = EvalStateful(ops.Program, ep)
	require.NoError(t, err)
	require.True(t, pass)
	delta, err = ledger.GetDelta(&ep.Txn.Txn)
	require.NoError(t, err)
	require.Equal(t, 0, len(delta.GlobalDelta))
	require.Equal(t, 1, len(delta.LocalDeltas))
	require.Equal(t, 1, len(delta.LocalDeltas[0]))
}

func TestEnumFieldErrors(t *testing.T) {
	ep := defaultEvalParams(nil, nil)

	source := `txn Amount`
	origTxnType := TxnFieldTypes[Amount]
	TxnFieldTypes[Amount] = StackBytes
	defer func() {
		TxnFieldTypes[Amount] = origTxnType
	}()

	ops, err := AssembleStringWithVersion(source, AssemblerMaxVersion)
	require.NoError(t, err)
	_, err = Eval(ops.Program, ep)
	require.Error(t, err)
	require.Contains(t, err.Error(), "Amount expected field type is []byte but got uint64")
	_, err = EvalStateful(ops.Program, ep)
	require.Error(t, err)
	require.Contains(t, err.Error(), "Amount expected field type is []byte but got uint64")

	source = `global MinTxnFee`
	origGlobalType := GlobalFieldTypes[MinTxnFee]
	GlobalFieldTypes[MinTxnFee] = StackBytes
	defer func() {
		GlobalFieldTypes[MinTxnFee] = origGlobalType
	}()

	ops, err = AssembleStringWithVersion(source, AssemblerMaxVersion)
	require.NoError(t, err)
	_, err = Eval(ops.Program, ep)
	require.Error(t, err)
	require.Contains(t, err.Error(), "MinTxnFee expected field type is []byte but got uint64")
	_, err = EvalStateful(ops.Program, ep)
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
	ledger.newAsset(txn.Txn.Sender, 55, params)

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

	ops, err = AssembleStringWithVersion(source, AssemblerMaxVersion)
	require.NoError(t, err)
	_, err = EvalStateful(ops.Program, ep)
	require.Error(t, err)
	require.Contains(t, err.Error(), "AssetBalance expected field type is []byte but got uint64")

	source = `int 0
asset_params_get AssetTotal
pop
`
	origAssetTotalType := AssetParamsFieldTypes[AssetTotal]
	AssetParamsFieldTypes[AssetTotal] = StackBytes
	defer func() {
		AssetParamsFieldTypes[AssetTotal] = origAssetTotalType
	}()

	ops, err = AssembleStringWithVersion(source, AssemblerMaxVersion)
	require.NoError(t, err)
	_, err = EvalStateful(ops.Program, ep)
	require.Error(t, err)
	require.Contains(t, err.Error(), "AssetTotal expected field type is []byte but got uint64")
}

func TestReturnTypes(t *testing.T) {
	// Ensure all opcodes return values they supposed to according to the OpSpecs table
	t.Parallel()
	typeToArg := map[StackType]string{
		StackUint64: "int 1\n",
		StackAny:    "int 1\n",
		StackBytes:  "byte 0x33343536\n",
	}
	ep := defaultEvalParams(nil, nil)
	txn := makeSampleTxn()
	txgroup := makeSampleTxnGroup(txn)
	ep.Txn = &txn
	ep.TxnGroup = txgroup
	ep.Txn.Txn.ApplicationID = 1
	ep.Txn.Txn.ForeignApps = []basics.AppIndex{txn.Txn.ApplicationID}
	ep.Txn.Txn.ForeignAssets = []basics.AssetIndex{basics.AssetIndex(1), basics.AssetIndex(1)}
	txn.Lsig.Args = [][]byte{
		[]byte("aoeu"),
		[]byte("aoeu"),
		[]byte("aoeu2"),
		[]byte("aoeu3"),
	}
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
	ledger.newAsset(txn.Txn.Sender, 1, params)
	ledger.newApp(txn.Txn.Sender, 1, makeSchemas(0, 0, 0, 0))
	ledger.balances[txn.Txn.Receiver] = makeBalanceRecord(txn.Txn.Receiver, 1)
	ledger.balances[txn.Txn.Receiver].locals[1] = make(basics.TealKeyValue)
	key, err := hex.DecodeString("33343536")
	require.NoError(t, err)
	algoValue := basics.TealValue{Type: basics.TealUintType, Uint: 0x77}
	ledger.balances[txn.Txn.Receiver].locals[1][string(key)] = algoValue

	ep.Ledger = ledger

	specialCmd := map[string]string{
		"txn":               "txn Sender",
		"txna":              "txna ApplicationArgs 0",
		"gtxn":              "gtxn 0 Sender",
		"gtxna":             "gtxna 0 ApplicationArgs 0",
		"global":            "global MinTxnFee",
		"arg":               "arg 0",
		"load":              "load 0",
		"store":             "store 0",
		"dig":               "dig 0",
		"intc":              "intcblock 0; intc 0",
		"intc_0":            "intcblock 0; intc_0",
		"intc_1":            "intcblock 0 0; intc_1",
		"intc_2":            "intcblock 0 0 0; intc_2",
		"intc_3":            "intcblock 0 0 0 0; intc_3",
		"bytec":             "bytecblock 0x32; bytec 0",
		"bytec_0":           "bytecblock 0x32; bytec_0",
		"bytec_1":           "bytecblock 0x32 0x33; bytec_1",
		"bytec_2":           "bytecblock 0x32 0x33 0x34; bytec_2",
		"bytec_3":           "bytecblock 0x32 0x33 0x34 0x35; bytec_3",
		"substring":         "substring 0 2",
		"ed25519verify":     "pop; pop; pop; int 1", // ignore
		"asset_params_get":  "asset_params_get AssetTotal",
		"asset_holding_get": "asset_holding_get AssetBalance",
		"stxn":              "stxn Sender",
		"stxna":             "stxna ApplicationArgs 0",
		"pushint":           "pushint 7272",
		"pushbytes":         `pushbytes "jojogoodgorilla"`,
	}

	byName := opsByName[LogicVersion]
	for _, m := range []runMode{runModeSignature, runModeApplication} {
		t.Run(fmt.Sprintf("m=%s", m.String()), func(t *testing.T) {
			for name, spec := range byName {
				if len(spec.Returns) == 0 || (m&spec.Modes) == 0 {
					continue
				}
				var sb strings.Builder
				sb.Grow(64)
				for _, t := range spec.Args {
					sb.WriteString(typeToArg[t])
				}
				if cmd, ok := specialCmd[name]; ok {
					sb.WriteString(cmd + "\n")
				} else {
					sb.WriteString(name + "\n")
				}
				source := sb.String()
				ops := testProg(t, source, AssemblerMaxVersion)

				var cx evalContext
				cx.EvalParams = ep
				cx.runModeFlags = m

				eval(ops.Program, &cx)

				require.Equal(
					t,
					len(spec.Returns), len(cx.stack),
					fmt.Sprintf("%s expected to return %d values but stack has %d", spec.Name, len(spec.Returns), len(cx.stack)),
				)
				for i := 0; i < len(spec.Returns); i++ {
					sp := len(cx.stack) - 1 - i
					stackType := cx.stack[sp].argType()
					retType := spec.Returns[i]
					require.True(
						t, typecheck(retType, stackType),
						fmt.Sprintf("%s expected to return %s but actual is %s", spec.Name, retType.String(), stackType.String()),
					)
				}
			}
		})
	}
}

func TestRound(t *testing.T) {
	source := `global Round
int 1
>=
`
	ledger := makeTestLedger(
		map[basics.Address]uint64{},
	)
	ops, err := AssembleStringWithVersion(source, AssemblerMaxVersion)
	require.NoError(t, err)

	ep := defaultEvalParams(nil, nil)
	_, err = CheckStateful(ops.Program, ep)
	require.NoError(t, err)
	_, err = EvalStateful(ops.Program, ep)
	require.Error(t, err)
	require.Contains(t, err.Error(), "ledger not available")

	pass, err := Eval(ops.Program, ep)
	require.Error(t, err)
	require.Contains(t, err.Error(), "not allowed in current mode")
	require.False(t, pass)

	ep.Ledger = ledger
	pass, err = EvalStateful(ops.Program, ep)
	require.NoError(t, err)
	require.True(t, pass)
}

func TestLatestTimestamp(t *testing.T) {
	source := `global LatestTimestamp
int 1
>=
`
	ledger := makeTestLedger(
		map[basics.Address]uint64{},
	)
	ops, err := AssembleStringWithVersion(source, AssemblerMaxVersion)
	require.NoError(t, err)

	ep := defaultEvalParams(nil, nil)
	_, err = CheckStateful(ops.Program, ep)
	require.NoError(t, err)
	_, err = EvalStateful(ops.Program, ep)
	require.Error(t, err)
	require.Contains(t, err.Error(), "ledger not available")

	pass, err := Eval(ops.Program, ep)
	require.Error(t, err)
	require.Contains(t, err.Error(), "not allowed in current mode")
	require.False(t, pass)

	ep.Ledger = ledger
	pass, err = EvalStateful(ops.Program, ep)
	require.NoError(t, err)
	require.True(t, pass)
}

func TestCurrentApplicationID(t *testing.T) {
	source := `global CurrentApplicationID
int 42
==
`
	ledger := makeTestLedger(
		map[basics.Address]uint64{},
	)
	ledger.appID = basics.AppIndex(42)
	ops, err := AssembleStringWithVersion(source, AssemblerMaxVersion)
	require.NoError(t, err)

	ep := defaultEvalParams(nil, nil)
	_, err = CheckStateful(ops.Program, ep)
	require.NoError(t, err)
	_, err = EvalStateful(ops.Program, ep)
	require.Error(t, err)
	require.Contains(t, err.Error(), "ledger not available")

	pass, err := Eval(ops.Program, ep)
	require.Error(t, err)
	require.Contains(t, err.Error(), "not allowed in current mode")
	require.False(t, pass)

	ep.Ledger = ledger
	pass, err = EvalStateful(ops.Program, ep)
	require.NoError(t, err)
	require.True(t, pass)
}
