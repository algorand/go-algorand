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
// so we need to carry the creator around with the params,
type appParams struct {
	basics.AppParams
	Creator basics.Address
}

type testLedger struct {
	balances          map[basics.Address]balanceRecord
	applications      map[basics.AppIndex]appParams
	assets            map[basics.AssetIndex]basics.AssetParams
	trackedCreatables map[int]basics.CreatableIndex
	appID             basics.AppIndex
	creatorAddr       basics.Address
	mods              map[basics.AppIndex]map[string]basics.ValueDelta
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
	l.trackedCreatables = make(map[int]basics.CreatableIndex)
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

	// Base MinBalance + GlobalStateSchema.MinBalance + ExtraProgramPages MinBalance for each created application
	for _, params := range l.applications {
		if params.Creator == addr {
			min = basics.AddSaturate(min, proto.AppFlatParamsMinBalance)
			min = basics.AddSaturate(min, params.GlobalStateSchema.MinBalance(proto).Raw)
			min = basics.AddSaturate(min, basics.MulSaturate(proto.AppFlatParamsMinBalance, uint64(params.ExtraProgramPages)))
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

func (l *testLedger) GetLocal(addr basics.Address, appIdx basics.AppIndex, key string, accountIdx uint64) (basics.TealValue, bool, error) {
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

func (l *testLedger) SetLocal(addr basics.Address, key string, value basics.TealValue, accountIdx uint64) error {
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

func (l *testLedger) DelLocal(addr basics.Address, key string, accountIdx uint64) error {
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

func (l *testLedger) setTrackedCreatable(groupIdx int, cl basics.CreatableLocator) {
	l.trackedCreatables[groupIdx] = cl.Index
}

func (l *testLedger) GetCreatableID(groupIdx int) basics.CreatableIndex {
	return l.trackedCreatables[groupIdx]
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

func (l *testLedger) SetLog(value basics.TealValue) error {
	return nil
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
		check  func([]byte, EvalParams) error
	}
	tests := map[runMode]desc{
		runModeSignature: {
			source: opcodesRunModeAny + opcodesRunModeSignature,
			eval:   func(program []byte, ep EvalParams) (bool, error) { return Eval(program, ep) },
			check:  func(program []byte, ep EvalParams) error { return Check(program, ep) },
		},
		runModeApplication: {
			source: opcodesRunModeAny + opcodesRunModeApplication,
			eval:   func(program []byte, ep EvalParams) (bool, error) { return EvalStateful(program, ep) },
			check:  func(program []byte, ep EvalParams) error { return CheckStateful(program, ep) },
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
			ep.Txn.Txn.ForeignAssets = []basics.AssetIndex{5} // needed since v4

			err := test.check(ops.Program, ep)
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
			err = test.check(ops.Program, ep)
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
		err = CheckStateful(ops.Program, ep)
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
		err := Check(ops.Program, ep)
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

func testStateful(t *testing.T, source string, ver uint64, ledger LedgerForLogic) (bool, error) {
	ops := testProg(t, source, ver)

	txn := makeSampleTxn()
	ep := defaultEvalParams(nil, &txn)
	ep.TxnGroup = makeSampleTxnGroup(txn)
	_, err := EvalStateful(ops.Program, ep)
	require.Error(t, err)
	require.Contains(t, err.Error(), "ledger not available")

	ep.Ledger = ledger
	return EvalStateful(ops.Program, ep)
}

func TestBalance(t *testing.T) {
	t.Parallel()

	text := "int 2; balance; int 177; =="
	tl := makeTestLedger(
		map[basics.Address]uint64{
			makeSampleTxn().Txn.Receiver: 177,
		},
	)
	_, err := testStateful(t, text, AssemblerMaxVersion, tl)
	require.Error(t, err)
	require.Contains(t, err.Error(), "invalid Account reference")

	text = `int 1; balance; int 177; ==`
	pass, err := testStateful(t, text, AssemblerMaxVersion, tl)
	require.NoError(t, err)
	require.True(t, pass)

	text = `txn Accounts 1; balance; int 177; ==;`
	// won't assemble in old version teal
	testProg(t, text, directRefEnabledVersion-1, expect{2, "balance arg 0 wanted type uint64..."})
	// but legal after that
	pass, err = testStateful(t, text, directRefEnabledVersion, tl)
	require.NoError(t, err)
	require.True(t, pass)

	text = "int 0; balance; int 13; =="
	var addr basics.Address
	copy(addr[:], []byte("aoeuiaoeuiaoeuiaoeuiaoeuiaoeui02"))
	tl = makeTestLedger(
		map[basics.Address]uint64{
			addr: 13,
		},
	)
	pass, err = testStateful(t, text, AssemblerMaxVersion, tl)
	require.Error(t, err)
	require.Contains(t, err.Error(), "failed to fetch balance")
	require.False(t, pass)

	tl = makeTestLedger(
		map[basics.Address]uint64{
			makeSampleTxn().Txn.Sender: 13,
		},
	)
	pass, err = testStateful(t, text, AssemblerMaxVersion, tl)
	require.NoError(t, err)
	require.True(t, pass)
}

func testApp(t *testing.T, program string, ep EvalParams, problems ...string) basics.EvalDelta {
	ops := testProg(t, program, ep.Proto.LogicSigVersion)
	err := CheckStateful(ops.Program, ep)
	require.NoError(t, err)

	// we only use this to test stateful apps.  While, I suppose
	// it's *legal* to have an app with no stateful ops, this
	// convenience routine can assume it, and check it.
	pass, err := Eval(ops.Program, ep)
	require.Error(t, err)
	require.Contains(t, err.Error(), "not allowed in current mode")
	require.False(t, pass)

	sb := &strings.Builder{}
	ep.Trace = sb
	pass, err = EvalStateful(ops.Program, ep)
	if len(problems) == 0 {
		require.NoError(t, err, sb.String())
		require.True(t, pass, sb.String())
		delta, err := ep.Ledger.GetDelta(&ep.Txn.Txn)
		require.NoError(t, err)
		return delta
	}

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
	// Sender makes an asset, min balance goes up
	ledger.newAsset(txn.Txn.Sender, 7, basics.AssetParams{Total: 1000})
	testApp(t, "int 0; min_balance; int 2002; ==", ep)
	schemas := makeSchemas(1, 2, 3, 4)
	ledger.newApp(txn.Txn.Sender, 77, schemas)
	// create + optin + 10 schema base + 4 ints + 6 bytes (local
	// and global count b/c newApp opts the creator in)
	minb := 2*1002 + 10*1003 + 4*1004 + 6*1005
	testApp(t, fmt.Sprintf("int 0; min_balance; int %d; ==", 2002+minb), ep)
	// request extra program pages, min balance increase
	app := ledger.applications[77]
	app.ExtraProgramPages = 2
	ledger.applications[77] = app
	minb += 2 * 1002
	testApp(t, fmt.Sprintf("int 0; min_balance; int %d; ==", 2002+minb), ep)

	testApp(t, "int 1; min_balance; int 1001; ==", ep) // 1 == Accounts[0]
	testProg(t, "txn Accounts 1; min_balance; int 1001; ==", directRefEnabledVersion-1,
		expect{2, "min_balance arg 0 wanted type uint64..."})
	testProg(t, "txn Accounts 1; min_balance; int 1001; ==", directRefEnabledVersion)
	testApp(t, "txn Accounts 1; min_balance; int 1001; ==", ep) // 1 == Accounts[0]
	// Receiver opts in
	ledger.setHolding(txn.Txn.Receiver, 7, 1, true)
	testApp(t, "int 1; min_balance; int 2002; ==", ep) // 1 == Accounts[0]

	testApp(t, "int 2; min_balance; int 1001; ==", ep, "invalid Account reference 2")

}

func TestAppCheckOptedIn(t *testing.T) {
	t.Parallel()

	txn := makeSampleTxn()
	txgroup := makeSampleTxnGroup(txn)
	now := defaultEvalParams(nil, nil)
	now.Txn = &txn
	now.TxnGroup = txgroup
	pre := defaultEvalParamsWithVersion(nil, nil, directRefEnabledVersion-1)
	pre.Txn = &txn
	pre.TxnGroup = txgroup
	testApp(t, "int 2; int 100; app_opted_in; int 1; ==", now, "ledger not available")

	ledger := makeTestLedger(
		map[basics.Address]uint64{
			txn.Txn.Receiver: 1,
			txn.Txn.Sender:   1,
		},
	)
	now.Ledger = ledger
	pre.Ledger = ledger
	testApp(t, "int 2; int 100; app_opted_in; int 1; ==", now, "invalid Account reference")

	// Receiver is not opted in
	testApp(t, "int 1; int 100; app_opted_in; int 0; ==", now)
	//testApp(t, "int 1; int 3; app_opted_in; int 0; ==", now)
	//testApp(t, "int 1; int 3; app_opted_in; int 0; ==", pre) // not an indirect reference though: app 3

	// Sender is not opted in
	testApp(t, "int 0; int 100; app_opted_in; int 0; ==", now)

	// Receiver opted in
	ledger.newApp(txn.Txn.Receiver, 100, makeSchemas(0, 0, 0, 0))
	testApp(t, "int 1; int 100; app_opted_in; int 1; ==", now)
	testApp(t, "int 1; int 2; app_opted_in; int 1; ==", now)
	testApp(t, "int 1; int 2; app_opted_in; int 0; ==", pre) // in pre, int 2 is an actual app id
	testApp(t, "byte \"aoeuiaoeuiaoeuiaoeuiaoeuiaoeui01\"; int 2; app_opted_in; int 1; ==", now)
	testProg(t, "byte \"aoeuiaoeuiaoeuiaoeuiaoeuiaoeui01\"; int 2; app_opted_in; int 1; ==", directRefEnabledVersion-1,
		expect{3, "app_opted_in arg 0 wanted type uint64..."})

	// Sender opted in
	ledger.newApp(txn.Txn.Sender, 100, makeSchemas(0, 0, 0, 0))
	testApp(t, "int 0; int 100; app_opted_in; int 1; ==", now)
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
	now := defaultEvalParams(nil, nil)
	now.Txn = &txn
	now.TxnGroup = txgroup
	pre := defaultEvalParamsWithVersion(nil, nil, directRefEnabledVersion-1)
	pre.Txn = &txn
	pre.TxnGroup = txgroup

	testApp(t, text, now, "ledger not available")

	ledger := makeTestLedger(
		map[basics.Address]uint64{
			txn.Txn.Receiver: 1,
		},
	)
	now.Ledger = ledger
	pre.Ledger = ledger
	testApp(t, text, now, "invalid Account reference")

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

	testApp(t, text, now, "no app for account")

	// Make a different app (not 100)
	ledger.newApp(txn.Txn.Receiver, 9999, makeSchemas(0, 0, 0, 0))
	testApp(t, text, now, "no app for account")

	// create the app and check the value from ApplicationArgs[0] (protocol.PaymentTx) does not exist
	ledger.newApp(txn.Txn.Receiver, 100, makeSchemas(0, 0, 0, 0))
	testApp(t, text, now)

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

	testApp(t, text, now)
	testApp(t, strings.Replace(text, "int 1  // account idx", "byte \"aoeuiaoeuiaoeuiaoeuiaoeuiaoeui01\"", -1), now)
	testProg(t, strings.Replace(text, "int 1  // account idx", "byte \"aoeuiaoeuiaoeuiaoeuiaoeuiaoeui01\"", -1), directRefEnabledVersion-1,
		expect{4, "app_local_get_ex arg 0 wanted type uint64..."})
	testApp(t, strings.Replace(text, "int 100 // app id", "int 2", -1), now)
	// Next we're testing if the use of the current app's id works
	// as a direct reference. The error is because the sender
	// account is not opted into 123.
	ledger.appID = basics.AppIndex(123)
	testApp(t, strings.Replace(text, "int 100 // app id", "int 123", -1), now, "no app for account")
	testApp(t, strings.Replace(text, "int 100 // app id", "int 2", -1), pre, "no app for account")
	testApp(t, strings.Replace(text, "int 100 // app id", "int 9", -1), now, "invalid App reference 9")
	testApp(t, strings.Replace(text, "int 1  // account idx", "byte \"aoeuiaoeuiaoeuiaoeuiaoeuiaoeui00\"", -1), now,
		"no such address")

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
	testApp(t, text, now)
	testApp(t, strings.Replace(text, "int 0  // account idx", "byte \"aoeuiaoeuiaoeuiaoeuiaoeuiaoeui00\"", -1), now)
	testApp(t, strings.Replace(text, "int 0  // account idx", "byte \"aoeuiaoeuiaoeuiaoeuiaoeuiaoeui02\"", -1), now,
		"invalid Account reference")

	// check reading state of other app
	ledger.newApp(txn.Txn.Sender, 56, makeSchemas(0, 0, 0, 0))
	ledger.newApp(txn.Txn.Sender, 100, makeSchemas(0, 0, 0, 0))
	text = `int 0  // account idx
int 56 // app id
txn ApplicationArgs 0
app_local_get_ex
bnz exist
err
exist:
byte 0x414c474f
==`

	ledger.balances[txn.Txn.Sender].locals[56][string(protocol.PaymentTx)] = basics.TealValue{Type: basics.TealBytesType, Bytes: "ALGO"}
	testApp(t, text, now)

	// check app_local_get
	text = `int 0  // account idx
txn ApplicationArgs 0
app_local_get
byte 0x414c474f
==`

	ledger.balances[txn.Txn.Sender].locals[100][string(protocol.PaymentTx)] = basics.TealValue{Type: basics.TealBytesType, Bytes: "ALGO"}
	testApp(t, text, now)
	testApp(t, strings.Replace(text, "int 0  // account idx", "byte \"aoeuiaoeuiaoeuiaoeuiaoeuiaoeui00\"", -1), now)
	testProg(t, strings.Replace(text, "int 0  // account idx", "byte \"aoeuiaoeuiaoeuiaoeuiaoeuiaoeui00\"", -1), directRefEnabledVersion-1,
		expect{3, "app_local_get arg 0 wanted type uint64..."})
	testApp(t, strings.Replace(text, "int 0  // account idx", "byte \"aoeuiaoeuiaoeuiaoeuiaoeuiaoeui01\"", -1), now)
	testApp(t, strings.Replace(text, "int 0  // account idx", "byte \"aoeuiaoeuiaoeuiaoeuiaoeuiaoeui02\"", -1), now,
		"invalid Account reference")

	// check app_local_get default value
	text = `int 0  // account idx
byte 0x414c474f
app_local_get
int 0
==`

	ledger.balances[txn.Txn.Sender].locals[100][string(protocol.PaymentTx)] = basics.TealValue{Type: basics.TealBytesType, Bytes: "ALGO"}
	testApp(t, text, now)
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
	txn := makeSampleTxn()
	txgroup := makeSampleTxnGroup(txn)
	now := defaultEvalParams(nil, nil)
	now.Txn = &txn
	now.TxnGroup = txgroup
	pre := defaultEvalParamsWithVersion(nil, nil, directRefEnabledVersion-1)
	pre.Txn = &txn
	pre.TxnGroup = txgroup

	testApp(t, text, now, "ledger not available")

	ledger := makeTestLedger(
		map[basics.Address]uint64{
			txn.Txn.Sender: 1,
		},
	)
	now.Ledger = ledger
	pre.Ledger = ledger

	now.Txn.Txn.ApplicationID = 100
	now.Txn.Txn.ForeignApps = []basics.AppIndex{now.Txn.Txn.ApplicationID}
	testApp(t, text, now, "no such app")

	// create the app and check the value from ApplicationArgs[0] (protocol.PaymentTx) does not exist
	ledger.newApp(txn.Txn.Sender, 100, makeSchemas(0, 0, 0, 1))

	testApp(t, text, now, "err opcode")

	ledger.applications[100].GlobalState[string(protocol.PaymentTx)] = basics.TealValue{Type: basics.TealBytesType, Bytes: "ALGO"}

	testApp(t, text, now)

	// check error on invalid app index for app_global_get_ex
	text = "int 2; txn ApplicationArgs 0; app_global_get_ex"
	testApp(t, text, now, "invalid App reference 2")
	// check that actual app id ok instead of indirect reference
	text = "int 100; txn ApplicationArgs 0; app_global_get_ex; int 1; ==; assert; byte 0x414c474f; =="
	testApp(t, text, now)
	testApp(t, text, pre, "invalid App reference 100") // but not in old teal

	// check app_global_get default value
	text = "byte 0x414c474f55; app_global_get; int 0; =="

	ledger.balances[txn.Txn.Sender].locals[100][string(protocol.PaymentTx)] = basics.TealValue{Type: basics.TealBytesType, Bytes: "ALGO"}
	testApp(t, text, now)

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
	now.Txn.Txn.ApplicationID = 0
	now.Txn.Txn.ForeignApps = []basics.AppIndex{100}
	testApp(t, text, now)

	// Direct reference to the current app also works
	ledger.appID = basics.AppIndex(100)
	now.Txn.Txn.ForeignApps = []basics.AppIndex{}
	testApp(t, strings.Replace(text, "int 1  // ForeignApps index", "int 100", -1), now)
	testApp(t, strings.Replace(text, "int 1  // ForeignApps index", "global CurrentApplicationID", -1), now)
}

const assetsTestProgram = `int 0//account
int 55
asset_holding_get AssetBalance
!
bnz error
int 123
==
int 0//account
int 55
asset_holding_get AssetFrozen
!
bnz error
int 1
==
&&
int 0//params
asset_params_get AssetTotal
!
bnz error
int 1000
==
&&
int 0//params
asset_params_get AssetDecimals
!
bnz error
int 2
==
&&
int 0//params
asset_params_get AssetDefaultFrozen
!
bnz error
int 0
==
&&
int 0//params
asset_params_get AssetUnitName
!
bnz error
byte 0x414c474f
==
&&
int 0//params
asset_params_get AssetName
!
bnz error
len
int 0
==
&&
int 0//params
asset_params_get AssetURL
!
bnz error
txna ApplicationArgs 0
==
&&
int 0//params
asset_params_get AssetMetadataHash
!
bnz error
byte 0x0000000000000000000000000000000000000000000000000000000000000000
==
&&
int 0//params
asset_params_get AssetManager
!
bnz error
txna Accounts 0
==
&&
int 0//params
asset_params_get AssetReserve
!
bnz error
txna Accounts 1
==
&&
int 0//params
asset_params_get AssetFreeze
!
bnz error
txna Accounts 1
==
&&
int 0//params
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

	txn := makeSampleTxn()
	pre := defaultEvalParamsWithVersion(nil, &txn, directRefEnabledVersion-1)
	now := defaultEvalParams(nil, &txn)
	ledger := makeTestLedger(
		map[basics.Address]uint64{
			txn.Txn.Sender: 1,
		},
	)
	pre.Ledger = ledger
	now.Ledger = ledger

	// bear in mind: the sample transaction has ForeignAccounts{55,77}
	testApp(t, "int 5; int 55; asset_holding_get AssetBalance", now, "invalid Account reference 5")
	// was legal to get balance on a non-ForeignAsset
	testApp(t, "int 0; int 54; asset_holding_get AssetBalance; ==", pre)
	// but not since directRefEnabledVersion
	testApp(t, "int 0; int 54; asset_holding_get AssetBalance", now, "invalid Asset reference 54")

	// it wasn't legal to use a direct ref for account
	testProg(t, `byte "aoeuiaoeuiaoeuiaoeuiaoeuiaoeui00"; int 54; asset_holding_get AssetBalance`,
		directRefEnabledVersion-1, expect{3, "asset_holding_get arg 0 wanted type uint64..."})
	// but it is now (empty asset yields 0,0 on stack)
	testApp(t, `byte "aoeuiaoeuiaoeuiaoeuiaoeuiaoeui00"; int 55; asset_holding_get AssetBalance; ==`, now)
	// This is receiver, who is in Assets array
	testApp(t, `byte "aoeuiaoeuiaoeuiaoeuiaoeuiaoeui01"; int 55; asset_holding_get AssetBalance; ==`, now)
	// But this is not in Assets, so illegal
	testApp(t, `byte "aoeuiaoeuiaoeuiaoeuiaoeuiaoeui02"; int 55; asset_holding_get AssetBalance; ==`, now, "invalid")

	// for params get, presence in ForeignAssets has always be required
	testApp(t, "int 5; asset_params_get AssetTotal", pre, "invalid Asset reference 5")
	testApp(t, "int 5; asset_params_get AssetTotal", now, "invalid Asset reference 5")

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
	// For consistency you can now use an indirect ref in holding_get
	// (recall ForeignAssets[0] = 55, which has balance 123)
	testApp(t, "int 0; int 0; asset_holding_get AssetBalance; int 1; ==; assert; int 123; ==", now)
	// but previous code would still try to read ASA 0
	testApp(t, "int 0; int 0; asset_holding_get AssetBalance; int 0; ==; assert; int 0; ==", pre)

	testApp(t, assetsTestProgram, now)

	// In current versions, can swap out the account index for the account
	testApp(t, strings.Replace(assetsTestProgram, "int 0//account", "byte \"aoeuiaoeuiaoeuiaoeuiaoeuiaoeui00\"", -1), now)
	// Or an asset index for the asset id
	testApp(t, strings.Replace(assetsTestProgram, "int 0//params", "int 55", -1), now)
	// Or an index for the asset id
	testApp(t, strings.Replace(assetsTestProgram, "int 55", "int 0", -1), now)

	// but old code cannot
	testProg(t, strings.Replace(assetsTestProgram, "int 0//account", "byte \"aoeuiaoeuiaoeuiaoeuiaoeuiaoeui00\"", -1), directRefEnabledVersion-1, expect{3, "asset_holding_get arg 0 wanted type uint64..."})
	testApp(t, strings.Replace(assetsTestProgram, "int 0//params", "int 55", -1), pre, "invalid Asset ref")
	testApp(t, strings.Replace(assetsTestProgram, "int 55", "int 0", -1), pre, "err opcode")

	// check holdings bool value
	source := `intcblock 0 55 1
intc_0  // 0, account idx (txn.Sender)
intc_1  // 55
asset_holding_get AssetFrozen
!
bnz error
intc_0 // 0
==
bnz ok
error:
err
ok:
intc_2 // 1
`
	ledger.setHolding(txn.Txn.Sender, 55, 123, false)
	testApp(t, source, now)

	// check holdings invalid offsets
	ops := testProg(t, source, AssemblerMaxVersion)
	require.Equal(t, OpsByName[now.Proto.LogicSigVersion]["asset_holding_get"].Opcode, ops.Program[8])
	ops.Program[9] = 0x02
	_, err := EvalStateful(ops.Program, now)
	require.Error(t, err)
	require.Contains(t, err.Error(), "invalid asset holding field 2")

	// check holdings bool value
	source = `intcblock 0 1
intc_0
asset_params_get AssetDefaultFrozen
!
bnz error
intc_1
==
bnz ok
error:
err
ok:
intc_1
`
	params.DefaultFrozen = true
	ledger.newAsset(txn.Txn.Sender, 55, params)
	testApp(t, source, now)
	// check holdings invalid offsets
	ops = testProg(t, source, AssemblerMaxVersion)
	require.Equal(t, OpsByName[now.Proto.LogicSigVersion]["asset_params_get"].Opcode, ops.Program[6])
	ops.Program[7] = 0x20
	_, err = EvalStateful(ops.Program, now)
	require.Error(t, err)
	require.Contains(t, err.Error(), "invalid asset params field 32")

	// check empty string
	source = `intcblock 0 1
intc_0  // foreign asset idx (txn.ForeignAssets[0])
asset_params_get AssetURL
!
bnz error
len
intc_0
==
bnz ok
error:
err
ok:
intc_1
`
	params.URL = ""
	ledger.newAsset(txn.Txn.Sender, 55, params)
	testApp(t, source, now)

	source = `intcblock 1 9
intc_0  // foreign asset idx (txn.ForeignAssets[1])
asset_params_get AssetURL
!
bnz error
len
intc_1
==
bnz ok
error:
err
ok:
intc_0
`
	params.URL = "foobarbaz"
	ledger.newAsset(txn.Txn.Sender, 77, params)
	testApp(t, source, now)

	source = `intcblock 0 1
intc_0
asset_params_get AssetURL
!
bnz error
intc_0
==
bnz ok
error:
err
ok:
intc_1
`
	params.URL = ""
	ledger.newAsset(txn.Txn.Sender, 55, params)
	testApp(t, source, now, "cannot compare ([]byte to uint64)")
}

func TestAppLocalReadWriteDeleteErrors(t *testing.T) {
	t.Parallel()

	sourceRead := `intcblock 0 100 0x77 1
bytecblock 0x414c474f 0x414c474f41
intc_0                    // 0, account idx (txn.Sender)
intc_1                    // 100, app id
bytec_0                   // key "ALGO"
app_local_get_ex
!
bnz error
intc_2                    // 0x77
==
intc_0                    // 0
intc_1                    // 100
bytec_1                   // ALGOA
app_local_get_ex
!
bnz error
intc_3                    // 1
==
&&
bnz ok
error:
err
ok:
intc_3                    // 1
`
	sourceWrite := `intcblock 0 100 1
bytecblock 0x414c474f
intc_0                     // 0, account idx (txn.Sender)
bytec_0                    // key "ALGO"
intc_1                     // 100
app_local_put
intc_2                     // 1
`
	sourceDelete := `intcblock 0 100
bytecblock 0x414c474f
intc_0                       // account idx
bytec_0                      // key "ALGO"
app_local_del
intc_1
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
			err = CheckStateful(ops.Program, ep)
			require.NoError(t, err)
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
			require.Equal(t, OpsByName[0]["intc_0"].Opcode, saved)
			ops.Program[firstCmdOffset] = OpsByName[0]["intc_1"].Opcode
			_, err = EvalStateful(ops.Program, ep)
			require.Error(t, err)
			require.Contains(t, err.Error(), "invalid Account reference 100")

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
	err = CheckStateful(ops.Program, ep)
	require.NoError(t, err)
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
	err = CheckStateful(ops.Program, ep)
	require.NoError(t, err)
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
	err = CheckStateful(ops.Program, ep)
	require.NoError(t, err)
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
	err = CheckStateful(ops.Program, ep)
	require.NoError(t, err)
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
	err = CheckStateful(ops.Program, ep)
	require.NoError(t, err)
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

func TestBlankKey(t *testing.T) {
	t.Parallel()
	source := `
byte ""
app_global_get
int 0
==
assert

byte ""
int 7
app_global_put

byte ""
app_global_get
int 7
==
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
	source := `int 0 // sender
byte 0x414c474f       // key "ALGO"
int 0x77              // value
app_local_put
int 1
byte 0x414c474f41     // key "ALGOA"
byte 0x414c474f
app_local_put
int 0 // sender
byte 0x414c474f
app_local_del
int 1
byte 0x414c474f41
app_local_del
int 0 // sender
int 0 // app
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

	testApp(t, source, ep)
	delta, err := ledger.GetDelta(&ep.Txn.Txn)
	require.NoError(t, err)
	require.Equal(t, 0, len(delta.GlobalDelta))
	require.Equal(t, 2, len(delta.LocalDeltas))

	ledger.reset()
	// test that app_local_put and _app_local_del can use byte addresses
	testApp(t, strings.Replace(source, "int 0 // sender", "byte \"aoeuiaoeuiaoeuiaoeuiaoeuiaoeui00\"", -1), ep)
	// But won't compile in old teal
	testProg(t, strings.Replace(source, "int 0 // sender", "byte \"aoeuiaoeuiaoeuiaoeuiaoeuiaoeui00\"", -1), directRefEnabledVersion-1,
		expect{4, "app_local_put arg 0 wanted..."}, expect{11, "app_local_del arg 0 wanted..."})

	delta, err = ledger.GetDelta(&ep.Txn.Txn)
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

	testApp(t, source, ep)
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
	testApp(t, source, ep)
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
	testApp(t, source, ep)
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
	testApp(t, source, ep)
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
	testApp(t, source, ep)
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
	txn.Txn.Type = protocol.ApplicationCallTx
	txgroup := makeSampleTxnGroup(txn)
	ep.Txn = &txn
	ep.TxnGroup = txgroup
	ep.Txn.Txn.ApplicationID = 1
	ep.Txn.Txn.ForeignApps = []basics.AppIndex{txn.Txn.ApplicationID}
	ep.Txn.Txn.ForeignAssets = []basics.AssetIndex{basics.AssetIndex(1), basics.AssetIndex(1)}
	ep.GroupIndex = 1
	ep.PastSideEffects = MakePastSideEffects(len(txgroup))
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
	ledger.setTrackedCreatable(0, basics.CreatableLocator{Index: 1})
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
		"gload":             "gload 0 0",
		"gloads":            "gloads 0",
		"gaid":              "gaid 0",
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
		"gtxns":             "gtxns Sender",
		"gtxnsa":            "gtxnsa ApplicationArgs 0",
		"pushint":           "pushint 7272",
		"pushbytes":         `pushbytes "jojogoodgorilla"`,
	}

	byName := OpsByName[LogicVersion]
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
	err = CheckStateful(ops.Program, ep)
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
	err = CheckStateful(ops.Program, ep)
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
	err = CheckStateful(ops.Program, ep)
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
