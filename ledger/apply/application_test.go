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

package apply

import (
	"fmt"
	"math/rand"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/transactions"
	"github.com/algorand/go-algorand/protocol"
)

func TestApplicationCallFieldsEmpty(t *testing.T) {
	a := require.New(t)

	ac := transactions.ApplicationCallTxnFields{}
	a.True(ac.Empty())

	ac.ApplicationID = 1
	a.False(ac.Empty())

	ac.ApplicationID = 0
	ac.OnCompletion = 1
	a.False(ac.Empty())

	ac.OnCompletion = 0
	ac.ApplicationArgs = make([][]byte, 1)
	a.False(ac.Empty())

	ac.ApplicationArgs = nil
	ac.Accounts = make([]basics.Address, 1)
	a.False(ac.Empty())

	ac.Accounts = nil
	ac.ForeignApps = make([]basics.AppIndex, 1)
	a.False(ac.Empty())

	ac.ForeignApps = nil
	ac.LocalStateSchema = basics.StateSchema{NumUint: 1}
	a.False(ac.Empty())

	ac.LocalStateSchema = basics.StateSchema{}
	ac.GlobalStateSchema = basics.StateSchema{NumUint: 1}
	a.False(ac.Empty())

	ac.GlobalStateSchema = basics.StateSchema{}
	ac.ApprovalProgram = []byte{1}
	a.False(ac.Empty())

	ac.ApprovalProgram = []byte{}
	a.False(ac.Empty())

	ac.ApprovalProgram = nil
	ac.ClearStateProgram = []byte{1}
	a.False(ac.Empty())

	ac.ClearStateProgram = []byte{}
	a.False(ac.Empty())

	ac.ClearStateProgram = nil
	a.True(ac.Empty())
}

func getRandomAddress(a *require.Assertions) basics.Address {
	const rl = 16
	b := make([]byte, rl)
	n, err := rand.Read(b)
	a.NoError(err)
	a.Equal(rl, n)

	address := crypto.Hash(b)
	return basics.Address(address)
}

type testBalances struct {
	appCreators map[basics.AppIndex]basics.Address
	balances    map[basics.Address]basics.AccountData
	proto       config.ConsensusParams

	put             int // Put calls counter
	putWith         int // PutWithCreatable calls counter
	putBalances     map[basics.Address]basics.AccountData
	putWithBalances map[basics.Address]basics.AccountData
	putWithNew      []basics.CreatableLocator
	putWithDel      []basics.CreatableLocator
}

type testBalancesPass struct {
	testBalances
}

const appIdxError basics.AppIndex = 0x11223344
const appIdxOk basics.AppIndex = 1

func (b *testBalances) Get(addr basics.Address, withPendingRewards bool) (basics.BalanceRecord, error) {
	ad, ok := b.balances[addr]
	if !ok {
		return basics.BalanceRecord{}, fmt.Errorf("mock balance not found")
	}
	return basics.BalanceRecord{Addr: addr, AccountData: ad}, nil
}

func (b *testBalances) Put(record basics.BalanceRecord) error {
	b.put++
	if b.putBalances == nil {
		b.putBalances = make(map[basics.Address]basics.AccountData)
	}
	b.putBalances[record.Addr] = record.AccountData
	return nil
}

func (b *testBalances) PutWithCreatable(record basics.BalanceRecord, newCreatable *basics.CreatableLocator, deletedCreatable *basics.CreatableLocator) error {
	b.putWith++
	if b.putWithBalances == nil {
		b.putWithBalances = make(map[basics.Address]basics.AccountData)
	}
	b.putWithBalances[record.Addr] = record.AccountData
	if newCreatable != nil {
		b.putWithNew = append(b.putWithNew, *newCreatable)
	}
	if deletedCreatable != nil {
		b.putWithDel = append(b.putWithDel, *deletedCreatable)
	}
	return nil
}

func (b *testBalances) GetCreator(cidx basics.CreatableIndex, ctype basics.CreatableType) (basics.Address, bool, error) {
	if ctype == basics.AppCreatable {
		aidx := basics.AppIndex(cidx)
		if aidx == appIdxError { // magic for test
			return basics.Address{}, false, fmt.Errorf("mock synthetic error")
		}

		creator, ok := b.appCreators[aidx]
		return creator, ok, nil
	}
	return basics.Address{}, false, nil
}

func (b *testBalances) Move(src, dst basics.Address, amount basics.MicroAlgos, srcRewards *basics.MicroAlgos, dstRewards *basics.MicroAlgos) error {
	return nil
}

func (b *testBalancesPass) Get(addr basics.Address, withPendingRewards bool) (basics.BalanceRecord, error) {
	ad, ok := b.balances[addr]
	if !ok {
		return basics.BalanceRecord{}, fmt.Errorf("mock balance not found")
	}
	return basics.BalanceRecord{Addr: addr, AccountData: ad}, nil
}

func (b *testBalancesPass) Put(record basics.BalanceRecord) error {
	if b.balances == nil {
		b.balances = make(map[basics.Address]basics.AccountData)
	}
	b.balances[record.Addr] = record.AccountData
	return nil
}

func (b *testBalancesPass) PutWithCreatable(record basics.BalanceRecord, newCreatable *basics.CreatableLocator, deletedCreatable *basics.CreatableLocator) error {
	if b.balances == nil {
		b.balances = make(map[basics.Address]basics.AccountData)
	}
	b.balances[record.Addr] = record.AccountData
	return nil
}

func (b *testBalances) ConsensusParams() config.ConsensusParams {
	return b.proto
}

// ResetWrites clears side effects of Put/PutWithCreatable
func (b *testBalances) ResetWrites() {
	b.put = 0
	b.putWith = 0
	b.putBalances = nil
	b.putWithBalances = nil
	b.putWithNew = []basics.CreatableLocator{}
	b.putWithDel = []basics.CreatableLocator{}
}

func (b *testBalances) SetProto(name protocol.ConsensusVersion) {
	b.proto = config.Consensus[name]
}

type testEvaluator struct {
	pass   bool
	delta  basics.EvalDelta
	appIdx basics.AppIndex
}

// Eval for tests that fail on program version > 10 and returns pass/delta from its own state rather than running the program
func (e *testEvaluator) Eval(program []byte) (pass bool, stateDelta basics.EvalDelta, err error) {
	if len(program) < 1 || program[0] > 10 {
		return false, basics.EvalDelta{}, fmt.Errorf("mock eval error")
	}
	return e.pass, e.delta, nil
}

// Check for tests that fail on program version > 10 and returns program len as cost
func (e *testEvaluator) Check(program []byte) (cost int, err error) {
	if len(program) < 1 || program[0] > 10 {
		return 0, fmt.Errorf("mock check error")
	}
	return len(program), nil
}

func (e *testEvaluator) InitLedger(balances Balances, appIdx basics.AppIndex, schemas basics.StateSchemas) error {
	e.appIdx = appIdx
	return nil
}

func TestAppCallApplyDelta(t *testing.T) {
	a := require.New(t)

	var tkv basics.TealKeyValue
	var sd basics.StateDelta
	err := applyStateDelta(tkv, sd)
	a.Error(err)
	a.Contains(err.Error(), "cannot apply delta to nil TealKeyValue")

	tkv = basics.TealKeyValue{}
	err = applyStateDelta(tkv, sd)
	a.NoError(err)
	a.True(len(tkv) == 0)

	sd = basics.StateDelta{
		"test": basics.ValueDelta{
			Action: basics.DeltaAction(10),
			Uint:   0,
		},
	}

	err = applyStateDelta(tkv, sd)
	a.Error(err)
	a.Contains(err.Error(), "unknown delta action")

	sd = basics.StateDelta{
		"test": basics.ValueDelta{
			Action: basics.SetUintAction,
			Uint:   1,
		},
	}
	err = applyStateDelta(tkv, sd)
	a.NoError(err)
	a.True(len(tkv) == 1)
	a.Equal(uint64(1), tkv["test"].Uint)
	a.Equal(basics.TealUintType, tkv["test"].Type)

	sd = basics.StateDelta{
		"test": basics.ValueDelta{
			Action: basics.DeleteAction,
		},
	}
	err = applyStateDelta(tkv, sd)
	a.NoError(err)
	a.True(len(tkv) == 0)

	// nil bytes
	sd = basics.StateDelta{
		"test": basics.ValueDelta{
			Action: basics.SetBytesAction,
		},
	}
	err = applyStateDelta(tkv, sd)
	a.NoError(err)
	a.True(len(tkv) == 1)
	a.Equal(basics.TealBytesType, tkv["test"].Type)
	a.Equal("", tkv["test"].Bytes)
	a.Equal(uint64(0), tkv["test"].Uint)

	// check illformed update
	sd = basics.StateDelta{
		"test": basics.ValueDelta{
			Action: basics.SetBytesAction,
			Uint:   1,
		},
	}
	err = applyStateDelta(tkv, sd)
	a.NoError(err)
	a.True(len(tkv) == 1)
	a.Equal(basics.TealBytesType, tkv["test"].Type)
	a.Equal("", tkv["test"].Bytes)
	a.Equal(uint64(0), tkv["test"].Uint)
}

func TestAppCallCloneEmpty(t *testing.T) {
	a := require.New(t)

	var ls map[basics.AppIndex]basics.AppLocalState
	cls := cloneAppLocalStates(ls)
	a.Equal(0, len(cls))

	var ap map[basics.AppIndex]basics.AppParams
	cap := cloneAppParams(ap)
	a.Equal(0, len(cap))
}

func TestAppCallGetParam(t *testing.T) {
	a := require.New(t)

	var b testBalances
	_, _, _, err := getAppParams(&b, appIdxError)
	a.Error(err)

	_, _, exist, err := getAppParams(&b, appIdxOk)
	a.NoError(err)
	a.False(exist)

	creator := getRandomAddress(a)
	addr := getRandomAddress(a)
	b.appCreators = map[basics.AppIndex]basics.Address{appIdxOk: creator}
	b.balances = map[basics.Address]basics.AccountData{addr: {}}
	_, _, exist, err = getAppParams(&b, appIdxOk)
	a.Error(err)
	a.True(exist)

	b.balances[creator] = basics.AccountData{
		AppParams: map[basics.AppIndex]basics.AppParams{},
	}
	_, _, exist, err = getAppParams(&b, appIdxOk)
	a.Error(err)
	a.True(exist)

	b.balances[creator] = basics.AccountData{
		AppParams: map[basics.AppIndex]basics.AppParams{
			appIdxOk: {},
		},
	}
	params, cr, exist, err := getAppParams(&b, appIdxOk)
	a.NoError(err)
	a.True(exist)
	a.Equal(creator, cr)
	a.Equal(basics.AppParams{}, params)
}

func TestAppCallAddressByIndex(t *testing.T) {
	a := require.New(t)

	sender := getRandomAddress(a)
	var ac transactions.ApplicationCallTxnFields
	addr, err := ac.AddressByIndex(0, sender)
	a.NoError(err)
	a.Equal(sender, addr)

	addr, err = ac.AddressByIndex(1, sender)
	a.Error(err)
	a.Contains(err.Error(), "cannot load account[1]")
	a.Equal(0, len(ac.Accounts))

	acc0 := getRandomAddress(a)
	ac.Accounts = []basics.Address{acc0}
	addr, err = ac.AddressByIndex(1, sender)
	a.NoError(err)
	a.Equal(acc0, addr)

	addr, err = ac.AddressByIndex(2, sender)
	a.Error(err)
	a.Contains(err.Error(), "cannot load account[2]")
}

func TestAppCallCheckPrograms(t *testing.T) {
	a := require.New(t)

	var ac transactions.ApplicationCallTxnFields
	var steva testEvaluator

	err := checkPrograms(&ac, &steva, 1)
	a.Error(err)
	a.Contains(err.Error(), "check failed on ApprovalProgram")

	program := []byte{2, 0x20, 1, 1, 0x22} // version, intcb, int 1
	ac.ApprovalProgram = program
	err = checkPrograms(&ac, &steva, 1)
	a.Error(err)
	a.Contains(err.Error(), "ApprovalProgram too resource intensive")

	err = checkPrograms(&ac, &steva, 10)
	a.Error(err)
	a.Contains(err.Error(), "check failed on ClearStateProgram")

	ac.ClearStateProgram = append(ac.ClearStateProgram, program...)
	ac.ClearStateProgram = append(ac.ClearStateProgram, program...)
	ac.ClearStateProgram = append(ac.ClearStateProgram, program...)
	err = checkPrograms(&ac, &steva, 10)
	a.Error(err)
	a.Contains(err.Error(), "ClearStateProgram too resource intensive")

	ac.ClearStateProgram = program
	err = checkPrograms(&ac, &steva, 10)
	a.NoError(err)
}

func TestAppCallApplyGlobalStateDeltas(t *testing.T) {
	a := require.New(t)

	var creator basics.Address
	var sender basics.Address
	var ac transactions.ApplicationCallTxnFields
	var ed basics.EvalDelta
	var params basics.AppParams
	var appIdx basics.AppIndex
	var b testBalances

	// check empty input
	err := applyEvalDelta(&ac, ed, params, creator, sender, &b, appIdx)
	a.NoError(err)
	a.Equal(0, b.put)
	a.Equal(0, b.putWith)

	err = applyEvalDelta(&ac, ed, params, creator, sender, &b, appIdx)
	a.NoError(err)
	a.Equal(0, b.put)
	a.Equal(0, b.putWith)

	ed.GlobalDelta = make(basics.StateDelta)
	ed.GlobalDelta["uint"] = basics.ValueDelta{Action: basics.SetUintAction, Uint: 1}

	// check global on unsupported proto
	b.SetProto(protocol.ConsensusV23)
	err = applyEvalDelta(&ac, ed, params, creator, sender, &b, appIdx)
	a.Error(err)
	a.True(isApplyError(err))
	a.Equal(0, b.put)
	a.Equal(0, b.putWith)

	err = applyEvalDelta(&ac, ed, params, creator, sender, &b, appIdx)
	a.Error(err)
	a.Contains(err.Error(), "cannot apply GlobalState delta")
	a.Equal(0, b.put)
	a.Equal(0, b.putWith)

	// check global on supported proto
	b.SetProto(protocol.ConsensusFuture)
	err = applyEvalDelta(&ac, ed, params, creator, sender, &b, appIdx)
	a.Error(err)
	a.True(isApplyError(err))
	a.Equal(0, b.put)
	a.Equal(0, b.putWith)

	err = applyEvalDelta(&ac, ed, params, creator, sender, &b, appIdx)
	a.Error(err)
	a.Contains(err.Error(), fmt.Sprintf("GlobalState for app %d would use too much space", appIdx))
	a.Equal(0, b.put)
	a.Equal(0, b.putWith)

	// check Action=Delete delta on empty params
	ed.GlobalDelta["uint"] = basics.ValueDelta{Action: basics.DeleteAction}
	err = applyEvalDelta(&ac, ed, params, creator, sender, &b, appIdx)
	a.Error(err)
	a.Contains(err.Error(), "balance not found")
	a.Equal(0, b.put)
	a.Equal(0, b.putWith)

	// simulate balances.GetCreator and balances.Get get out of sync
	// creator received from balances.GetCreator and has app params
	// and its balances.Get record is out of sync/not initialized
	// ensure even if AppParams were allocated they are empty
	creator = getRandomAddress(a)
	b.balances = make(map[basics.Address]basics.AccountData)
	b.balances[creator] = basics.AccountData{}
	err = applyEvalDelta(&ac, ed, params, creator, sender, &b, appIdx)
	a.NoError(err)
	a.Equal(1, b.put)
	a.Equal(0, b.putWith)
	pad, ok := b.putBalances[creator]
	a.True(ok)
	// There is a side effect: Action=Delete bypasses all default checks and
	// forces AppParams (empty before) to have an entry for appIdx
	ap, ok := pad.AppParams[appIdx]
	a.True(ok)
	a.Equal(0, len(ap.GlobalState))
	// ensure AppParams with pre-allocated fields is stored as empty AppParams{}
	enc := protocol.Encode(&ap)
	emp := protocol.Encode(&basics.AppParams{})
	a.Equal(len(emp), len(enc))
	// ensure original balance record in the mock was not changed
	// this ensure proper cloning and any in-intended in-memory modifications
	a.Equal(basics.AccountData{}, b.balances[creator])

	b.ResetWrites()

	// now check errors with non-default values
	b.SetProto(protocol.ConsensusV23)
	ed.GlobalDelta["uint"] = basics.ValueDelta{Action: basics.SetUintAction, Uint: 1}
	err = applyEvalDelta(&ac, ed, params, creator, sender, &b, appIdx)
	a.Error(err)
	a.True(isApplyError(err))
	a.Equal(0, b.put)
	a.Equal(0, b.putWith)
	a.Equal(basics.AccountData{}, b.balances[creator])

	err = applyEvalDelta(&ac, ed, params, creator, sender, &b, appIdx)
	a.Error(err)
	a.Contains(err.Error(), "cannot apply GlobalState delta")
	a.Equal(0, b.put)
	a.Equal(0, b.putWith)
	a.Equal(basics.AccountData{}, b.balances[creator])

	b.SetProto(protocol.ConsensusFuture)
	err = applyEvalDelta(&ac, ed, params, creator, sender, &b, appIdx)
	a.Error(err)
	a.Contains(err.Error(), fmt.Sprintf("GlobalState for app %d would use too much space: store integer count", appIdx))
	a.Equal(0, b.put)
	a.Equal(0, b.putWith)
	a.Equal(basics.AccountData{}, b.balances[creator])

	// try illformed delta
	params.GlobalStateSchema = basics.StateSchema{NumUint: 1}
	ed.GlobalDelta["bytes"] = basics.ValueDelta{Action: basics.SetBytesAction, Uint: 1}
	err = applyEvalDelta(&ac, ed, params, creator, sender, &b, appIdx)
	a.Error(err)
	a.Contains(err.Error(), fmt.Sprintf("GlobalState for app %d would use too much space: store bytes count", appIdx))
	a.Equal(0, b.put)
	a.Equal(0, b.putWith)
	a.Equal(basics.AccountData{}, b.balances[creator])

	// check a happy case
	params.GlobalStateSchema = basics.StateSchema{NumUint: 1, NumByteSlice: 1}
	br := basics.AccountData{AppParams: map[basics.AppIndex]basics.AppParams{appIdx: params}}
	cp := basics.AccountData{AppParams: map[basics.AppIndex]basics.AppParams{appIdx: params}}
	b.balances[creator] = cp
	err = applyEvalDelta(&ac, ed, params, creator, sender, &b, appIdx)
	a.NoError(err)
	a.Equal(1, b.put)
	pad, ok = b.putBalances[creator]
	a.True(ok)
	ap, ok = pad.AppParams[appIdx]
	a.True(ok)
	a.Equal(2, len(ap.GlobalState))
	a.Equal(basics.TealBytesType, ap.GlobalState["bytes"].Type)
	a.Equal(basics.TealUintType, ap.GlobalState["uint"].Type)
	a.Equal(uint64(0), ap.GlobalState["bytes"].Uint)
	a.Equal(uint64(1), ap.GlobalState["uint"].Uint)
	a.Equal("", ap.GlobalState["bytes"].Bytes)
	a.Equal("", ap.GlobalState["uint"].Bytes)
	a.Equal(br, b.balances[creator])
}

func TestAppCallApplyLocalsStateDeltas(t *testing.T) {
	a := require.New(t)

	var creator basics.Address = getRandomAddress(a)
	var sender basics.Address = getRandomAddress(a)
	var ac transactions.ApplicationCallTxnFields
	var ed basics.EvalDelta
	var params basics.AppParams
	var appIdx basics.AppIndex
	var b testBalances

	b.balances = make(map[basics.Address]basics.AccountData)
	ed.LocalDeltas = make(map[uint64]basics.StateDelta)

	err := applyEvalDelta(&ac, ed, params, creator, sender, &b, appIdx)
	a.NoError(err)
	a.Equal(0, b.put)
	a.Equal(0, b.putWith)

	err = applyEvalDelta(&ac, ed, params, creator, sender, &b, appIdx)
	a.NoError(err)
	a.Equal(0, b.put)
	a.Equal(0, b.putWith)

	ed.LocalDeltas[1] = basics.StateDelta{}

	// non-existing account
	err = applyEvalDelta(&ac, ed, params, creator, sender, &b, appIdx)
	a.Error(err)

	err = applyEvalDelta(&ac, ed, params, creator, sender, &b, appIdx)
	a.Error(err)

	// empty delta
	ac.Accounts = append(ac.Accounts, sender, sender)
	err = applyEvalDelta(&ac, ed, params, creator, sender, &b, appIdx)
	a.Error(err)
	a.Equal(0, b.put)
	a.Equal(0, b.putWith)

	// test duplicates in accounts
	b.SetProto(protocol.ConsensusFuture)
	ed.LocalDeltas[0] = basics.StateDelta{"uint": basics.ValueDelta{Action: basics.DeleteAction}}
	ed.LocalDeltas[1] = basics.StateDelta{"bytes": basics.ValueDelta{Action: basics.DeleteAction}}
	b.balances[sender] = basics.AccountData{}
	err = applyEvalDelta(&ac, ed, params, creator, sender, &b, appIdx)
	a.Error(err)
	a.True(isApplyError(err))
	a.Equal(0, b.put)
	a.Equal(0, b.putWith)
	a.Equal(basics.AccountData{}, b.balances[sender])
	// not opted in
	err = applyEvalDelta(&ac, ed, params, creator, sender, &b, appIdx)
	a.Error(err)
	a.Contains(err.Error(), "acct has not opted in to app")
	a.Equal(0, b.put)
	a.Equal(0, b.putWith)
	// ensure original balance record in the mock was not changed
	// this ensure proper cloning and any in-intended in-memory modifications
	a.Equal(basics.AccountData{}, b.balances[sender])

	states := map[basics.AppIndex]basics.AppLocalState{appIdx: {}, 1: {}}
	cp := map[basics.AppIndex]basics.AppLocalState{appIdx: {}, 1: {}}
	b.balances[sender] = basics.AccountData{
		AppLocalStates: cp,
	}
	err = applyEvalDelta(&ac, ed, params, creator, sender, &b, appIdx)
	a.Error(err)
	a.Contains(err.Error(), "duplicate LocalState delta")
	a.Equal(0, b.put)
	a.Equal(0, b.putWith)
	// ensure no changes in original balance record
	a.Equal(basics.AccountData{AppLocalStates: states}, b.balances[sender])

	// test valid deltas and accounts
	ac.Accounts = nil
	states = map[basics.AppIndex]basics.AppLocalState{appIdx: {}}
	b.balances[sender] = basics.AccountData{AppLocalStates: states}
	ed.LocalDeltas[0] = basics.StateDelta{
		"uint":  basics.ValueDelta{Action: basics.SetUintAction, Uint: 1},
		"bytes": basics.ValueDelta{Action: basics.SetBytesAction, Bytes: "value"},
	}
	delete(ed.LocalDeltas, 1)
	err = applyEvalDelta(&ac, ed, params, creator, sender, &b, appIdx)
	a.Error(err)
	a.Contains(err.Error(), "would use too much space")
	a.Equal(0, b.put)
	a.Equal(0, b.putWith)
	a.Equal(basics.AccountData{AppLocalStates: states}, b.balances[sender])

	// happy case
	states = map[basics.AppIndex]basics.AppLocalState{appIdx: {
		Schema: basics.StateSchema{NumUint: 1, NumByteSlice: 1},
	}}
	cp = map[basics.AppIndex]basics.AppLocalState{appIdx: {
		Schema: basics.StateSchema{NumUint: 1, NumByteSlice: 1},
	}}
	b.balances[sender] = basics.AccountData{AppLocalStates: cp}
	err = applyEvalDelta(&ac, ed, params, creator, sender, &b, appIdx)
	a.NoError(err)
	a.Equal(1, b.put)
	a.Equal(0, b.putWith)
	a.Equal(basics.AccountData{AppLocalStates: states}, b.balances[sender])
	a.Equal(basics.TealUintType, b.putBalances[sender].AppLocalStates[appIdx].KeyValue["uint"].Type)
	a.Equal(basics.TealBytesType, b.putBalances[sender].AppLocalStates[appIdx].KeyValue["bytes"].Type)
	a.Equal(uint64(1), b.putBalances[sender].AppLocalStates[appIdx].KeyValue["uint"].Uint)
	a.Equal("value", b.putBalances[sender].AppLocalStates[appIdx].KeyValue["bytes"].Bytes)
}

func TestAppCallCreate(t *testing.T) {
	a := require.New(t)

	var b testBalances
	var txnCounter uint64 = 1
	ac := transactions.ApplicationCallTxnFields{}
	creator := getRandomAddress(a)
	// no balance record
	appIdx, err := createApplication(&ac, &b, creator, txnCounter)
	a.Error(err)
	a.Equal(basics.AppIndex(0), appIdx)

	b.balances = make(map[basics.Address]basics.AccountData)
	b.balances[creator] = basics.AccountData{}
	appIdx, err = createApplication(&ac, &b, creator, txnCounter)
	a.Error(err)
	a.Contains(err.Error(), "max created apps per acct is")

	b.SetProto(protocol.ConsensusFuture)
	ac.ApprovalProgram = []byte{1}
	ac.ClearStateProgram = []byte{2}
	ac.LocalStateSchema = basics.StateSchema{NumUint: 1}
	ac.GlobalStateSchema = basics.StateSchema{NumByteSlice: 1}
	appIdx, err = createApplication(&ac, &b, creator, txnCounter)
	a.NoError(err)
	a.Equal(txnCounter+1, uint64(appIdx))
	a.Equal(0, b.put)
	a.Equal(1, b.putWith)
	nbr, ok := b.putBalances[creator]
	a.False(ok)
	nbr, ok = b.putWithBalances[creator]
	a.True(ok)
	params, ok := nbr.AppParams[appIdx]
	a.True(ok)
	a.Equal(ac.ApprovalProgram, params.ApprovalProgram)
	a.Equal(ac.ClearStateProgram, params.ClearStateProgram)
	a.Equal(ac.LocalStateSchema, params.LocalStateSchema)
	a.Equal(ac.GlobalStateSchema, params.GlobalStateSchema)
	a.True(len(b.putWithNew) > 0)
}

// TestAppCallApplyCreate carefully tracks and validates balance record updates
func TestAppCallApplyCreate(t *testing.T) {
	a := require.New(t)

	creator := getRandomAddress(a)
	sender := creator
	ac := transactions.ApplicationCallTxnFields{
		ApplicationID:     0,
		ApprovalProgram:   []byte{1},
		ClearStateProgram: []byte{1},
	}
	h := transactions.Header{
		Sender: sender,
	}
	var steva testEvaluator
	var txnCounter uint64 = 1
	var b testBalances

	err := ApplicationCall(ac, h, &b, nil, txnCounter, &steva)
	a.Error(err)
	a.Contains(err.Error(), "cannot use empty ApplyData")
	a.Equal(0, b.put)
	a.Equal(0, b.putWith)

	b.balances = make(map[basics.Address]basics.AccountData)
	b.balances[creator] = basics.AccountData{}
	var ad *transactions.ApplyData = &transactions.ApplyData{}

	err = ApplicationCall(ac, h, &b, ad, txnCounter, &steva)
	a.Error(err)
	a.Contains(err.Error(), "max created apps per acct is 0")
	a.Equal(0, b.put)
	a.Equal(0, b.putWith)

	b.SetProto(protocol.ConsensusFuture)

	// this test will succeed in creating the app, but then fail
	// because the mock balances doesn't update the creators table
	// so it will think the app doesn't exist
	err = ApplicationCall(ac, h, &b, ad, txnCounter, &steva)
	a.Error(err)
	a.Contains(err.Error(), "applications that do not exist")
	a.Equal(0, b.put)
	a.Equal(1, b.putWith)

	createdAppIdx := basics.AppIndex(txnCounter + 1)
	b.appCreators = map[basics.AppIndex]basics.Address{createdAppIdx: creator}

	// save the created app info to the side
	saved := b.putWithBalances[creator]

	b.ResetWrites()

	// now looking up the creator will succeed, but we reset writes, so
	// they won't have the app params
	err = ApplicationCall(ac, h, &b, ad, txnCounter, &steva)
	a.Error(err)
	a.Contains(err.Error(), fmt.Sprintf("app %d not found in account", createdAppIdx))
	a.Equal(0, b.put)
	a.Equal(1, b.putWith)

	b.ResetWrites()

	// now we give the creator the app params again
	cp := basics.AccountData{}
	cp.AppParams = cloneAppParams(saved.AppParams)
	cp.AppLocalStates = cloneAppLocalStates(saved.AppLocalStates)
	b.balances[creator] = cp
	err = ApplicationCall(ac, h, &b, ad, txnCounter, &steva)
	a.Error(err)
	a.Contains(err.Error(), "transaction rejected by ApprovalProgram")
	a.Equal(uint64(steva.appIdx), txnCounter+1)
	a.Equal(0, b.put)
	a.Equal(1, b.putWith)
	// ensure original balance record in the mock was not changed
	// this ensure proper cloning and any in-intended in-memory modifications
	//
	// known artefact of cloning AppLocalState even with empty update, nil map vs empty map
	saved.AppLocalStates = map[basics.AppIndex]basics.AppLocalState{}
	a.Equal(saved, b.balances[creator])
	saved = b.putWithBalances[creator]

	b.ResetWrites()

	cp = basics.AccountData{}
	cp.AppParams = cloneAppParams(saved.AppParams)
	cp.AppLocalStates = cloneAppLocalStates(saved.AppLocalStates)

	steva.pass = true
	gd := map[string]basics.ValueDelta{"uint": {Action: basics.DeltaAction(4), Uint: 1}}
	steva.delta = basics.EvalDelta{GlobalDelta: gd}
	err = ApplicationCall(ac, h, &b, ad, txnCounter, &steva)
	a.Error(err)
	a.Contains(err.Error(), "cannot apply GlobalState delta")
	a.Equal(uint64(steva.appIdx), txnCounter+1)
	a.Equal(0, b.put)
	a.Equal(1, b.putWith)
	a.Equal(basics.EvalDelta{}, ad.EvalDelta)
	a.Equal(saved, b.balances[creator])
	saved = b.putWithBalances[creator]

	b.ResetWrites()

	cp = basics.AccountData{}
	cp.AppParams = cloneAppParams(saved.AppParams)
	cp.AppLocalStates = cloneAppLocalStates(saved.AppLocalStates)

	gd = map[string]basics.ValueDelta{"uint": {Action: basics.SetUintAction, Uint: 1}}
	steva.delta = basics.EvalDelta{GlobalDelta: gd}
	ac.GlobalStateSchema = basics.StateSchema{NumUint: 1}
	err = ApplicationCall(ac, h, &b, ad, txnCounter, &steva)
	a.Error(err)
	a.Contains(err.Error(), "too much space: store integer")
	a.Equal(uint64(steva.appIdx), txnCounter+1)
	a.Equal(0, b.put)
	a.Equal(1, b.putWith)
	a.Equal(saved, b.balances[creator])
	saved = b.putWithBalances[creator]

	b.ResetWrites()

	cp = basics.AccountData{}
	cp.AppParams = cloneAppParams(saved.AppParams)
	cp.AppLocalStates = cloneAppLocalStates(saved.AppLocalStates)
	cp.TotalAppSchema = saved.TotalAppSchema
	b.balances[creator] = cp

	err = ApplicationCall(ac, h, &b, ad, txnCounter, &steva)
	a.NoError(err)
	appIdx := steva.appIdx
	a.Equal(uint64(appIdx), txnCounter+1)
	a.Equal(1, b.put)
	a.Equal(1, b.putWith)
	a.Equal(saved, b.balances[creator])
	br := b.putBalances[creator]
	a.Equal([]byte{1}, br.AppParams[appIdx].ApprovalProgram)
	a.Equal([]byte{1}, br.AppParams[appIdx].ClearStateProgram)
	a.Equal(basics.TealKeyValue{"uint": basics.TealValue{Type: basics.TealUintType, Uint: 1}}, br.AppParams[appIdx].GlobalState)
	a.Equal(basics.StateSchema{NumUint: 1}, br.AppParams[appIdx].GlobalStateSchema)
	a.Equal(basics.StateSchema{}, br.AppParams[appIdx].LocalStateSchema)
	a.Equal(basics.StateSchema{NumUint: 1}, br.TotalAppSchema)
	br = b.putWithBalances[creator]
	a.Equal([]byte{1}, br.AppParams[appIdx].ApprovalProgram)
	a.Equal([]byte{1}, br.AppParams[appIdx].ClearStateProgram)
	a.Equal(basics.TealKeyValue(nil), br.AppParams[appIdx].GlobalState)
	a.Equal(basics.StateSchema{NumUint: 1}, br.AppParams[appIdx].GlobalStateSchema)
	a.Equal(basics.StateSchema{}, br.AppParams[appIdx].LocalStateSchema)
}

// TestAppCallApplyCreateOptIn checks balance record fields without tracking substages
func TestAppCallApplyCreateOptIn(t *testing.T) {
	a := require.New(t)

	creator := getRandomAddress(a)
	sender := creator
	ac := transactions.ApplicationCallTxnFields{
		ApplicationID:     0,
		ApprovalProgram:   []byte{1},
		ClearStateProgram: []byte{1},
		GlobalStateSchema: basics.StateSchema{NumUint: 1},
		LocalStateSchema:  basics.StateSchema{NumByteSlice: 2},
		OnCompletion:      transactions.OptInOC,
	}
	h := transactions.Header{
		Sender: sender,
	}
	var steva testEvaluator
	var txnCounter uint64 = 1
	appIdx := basics.AppIndex(txnCounter + 1)
	var ad *transactions.ApplyData = &transactions.ApplyData{}
	var b testBalancesPass

	b.balances = make(map[basics.Address]basics.AccountData)
	b.balances[creator] = basics.AccountData{}
	b.SetProto(protocol.ConsensusFuture)
	b.appCreators = map[basics.AppIndex]basics.Address{appIdx: creator}

	steva.pass = true
	gd := map[string]basics.ValueDelta{"uint": {Action: basics.SetUintAction, Uint: 1}}
	steva.delta = basics.EvalDelta{GlobalDelta: gd}

	err := ApplicationCall(ac, h, &b, ad, txnCounter, &steva)
	a.NoError(err)
	a.Equal(steva.appIdx, appIdx)
	br := b.balances[creator]
	a.Equal([]byte{1}, br.AppParams[appIdx].ApprovalProgram)
	a.Equal([]byte{1}, br.AppParams[appIdx].ClearStateProgram)
	a.Equal(basics.TealKeyValue{"uint": basics.TealValue{Type: basics.TealUintType, Uint: 1}}, br.AppParams[appIdx].GlobalState)
	a.Equal(basics.StateSchema{NumUint: 1}, br.AppParams[appIdx].GlobalStateSchema)
	a.Equal(basics.StateSchema{NumByteSlice: 2}, br.AppParams[appIdx].LocalStateSchema)
	a.Equal(basics.StateSchema{NumByteSlice: 2}, br.AppLocalStates[appIdx].Schema)
	a.Equal(basics.StateSchema{NumUint: 1, NumByteSlice: 2}, br.TotalAppSchema)
}

func TestAppCallOptIn(t *testing.T) {
	a := require.New(t)

	sender := getRandomAddress(a)

	var txnCounter uint64 = 1
	appIdx := basics.AppIndex(txnCounter + 1)
	var b testBalances
	ad := basics.AccountData{}
	b.balances = map[basics.Address]basics.AccountData{sender: ad}

	var params basics.AppParams

	err := applyOptIn(&b, sender, appIdx, params)
	a.Error(err)
	a.Contains(err.Error(), "cannot opt in app")
	a.Equal(0, b.put)
	a.Equal(0, b.putWith)

	b.SetProto(protocol.ConsensusFuture)
	err = applyOptIn(&b, sender, appIdx, params)
	a.NoError(err)
	a.Equal(1, b.put)
	a.Equal(0, b.putWith)
	br := b.putBalances[sender]
	a.Equal(basics.AccountData{AppLocalStates: map[basics.AppIndex]basics.AppLocalState{appIdx: {}}}, br)

	b.ResetWrites()

	ad.AppLocalStates = make(map[basics.AppIndex]basics.AppLocalState)
	ad.AppLocalStates[appIdx] = basics.AppLocalState{}
	b.balances = map[basics.Address]basics.AccountData{sender: ad}
	err = applyOptIn(&b, sender, appIdx, params)
	a.Error(err)
	a.Contains(err.Error(), "has already opted in to app")
	a.Equal(0, b.put)
	a.Equal(0, b.putWith)

	b.ResetWrites()

	delete(ad.AppLocalStates, appIdx)
	ad.AppLocalStates[appIdx+1] = basics.AppLocalState{}
	b.balances = map[basics.Address]basics.AccountData{sender: ad}
	err = applyOptIn(&b, sender, appIdx, params)
	a.NoError(err)
	a.Equal(1, b.put)
	a.Equal(0, b.putWith)

	b.ResetWrites()

	ad.AppLocalStates[appIdx+1] = basics.AppLocalState{
		Schema: basics.StateSchema{NumByteSlice: 1},
	}
	ad.TotalAppSchema = basics.StateSchema{NumByteSlice: 1}
	params.LocalStateSchema = basics.StateSchema{NumUint: 1}
	b.balances = map[basics.Address]basics.AccountData{sender: ad}
	err = applyOptIn(&b, sender, appIdx, params)
	a.NoError(err)
	a.Equal(1, b.put)
	a.Equal(0, b.putWith)
	br = b.putBalances[sender]
	a.Equal(
		basics.AccountData{
			AppLocalStates: map[basics.AppIndex]basics.AppLocalState{
				appIdx:     {Schema: basics.StateSchema{NumUint: 1}},
				appIdx + 1: {Schema: basics.StateSchema{NumByteSlice: 1}},
			},
			TotalAppSchema: basics.StateSchema{NumUint: 1, NumByteSlice: 1},
		},
		br,
	)
}

func TestAppCallClearState(t *testing.T) {
	a := require.New(t)

	creator := getRandomAddress(a)
	sender := getRandomAddress(a)
	ac := transactions.ApplicationCallTxnFields{}
	var steva testEvaluator
	var txnCounter uint64 = 1
	appIdx := basics.AppIndex(txnCounter + 1)
	var b testBalances

	ad := &transactions.ApplyData{}
	b.appCreators = make(map[basics.AppIndex]basics.Address)
	b.balances = make(map[basics.Address]basics.AccountData, 2)
	b.SetProto(protocol.ConsensusFuture)

	// check app not exist and not opted in
	b.balances[sender] = basics.AccountData{}
	err := applyClearState(&ac, &b, sender, appIdx, ad, &steva)
	a.Error(err)
	a.Contains(err.Error(), "not currently opted in")
	a.Equal(0, b.put)
	a.Equal(0, b.putWith)

	// check non-existing app with empty opt-in
	b.balances[sender] = basics.AccountData{
		AppLocalStates: map[basics.AppIndex]basics.AppLocalState{appIdx: {}},
	}
	err = applyClearState(&ac, &b, sender, appIdx, ad, &steva)
	a.NoError(err)
	a.Equal(1, b.put)
	a.Equal(0, b.putWith)
	br := b.putBalances[sender]
	a.Equal(0, len(br.AppLocalStates))
	a.Equal(basics.StateSchema{}, br.TotalAppSchema)
	// check original balance record not changed
	br = b.balances[sender]
	a.Equal(map[basics.AppIndex]basics.AppLocalState{appIdx: {}}, br.AppLocalStates)

	b.ResetWrites()

	// check non-existing app with non-empty opt-in
	b.balances[sender] = basics.AccountData{
		AppLocalStates: map[basics.AppIndex]basics.AppLocalState{
			appIdx: {Schema: basics.StateSchema{NumUint: 10}},
		},
	}
	err = applyClearState(&ac, &b, sender, appIdx, ad, &steva)
	a.NoError(err)
	a.Equal(1, b.put)
	a.Equal(0, b.putWith)
	br = b.putBalances[sender]
	a.Equal(0, len(br.AppLocalStates))
	a.Equal(basics.StateSchema{}, br.TotalAppSchema)
	a.Equal(basics.EvalDelta{}, ad.EvalDelta)

	b.ResetWrites()

	// check existing application with failing ClearStateProgram
	b.balances[creator] = basics.AccountData{
		AppParams: map[basics.AppIndex]basics.AppParams{
			appIdx: {
				ClearStateProgram: []byte{1},
				StateSchemas: basics.StateSchemas{
					GlobalStateSchema: basics.StateSchema{NumUint: 1},
				},
			},
		},
	}
	b.appCreators[appIdx] = creator

	// one put: to opt out
	steva.pass = false
	gd := map[string]basics.ValueDelta{"uint": {Action: basics.SetUintAction, Uint: 1}}
	steva.delta = basics.EvalDelta{GlobalDelta: gd}
	err = applyClearState(&ac, &b, sender, appIdx, ad, &steva)
	a.NoError(err)
	a.Equal(1, b.put)
	a.Equal(0, b.putWith)
	br = b.putBalances[sender]
	a.Equal(0, len(br.AppLocalStates))
	a.Equal(basics.StateSchema{}, br.TotalAppSchema)
	a.Equal(basics.EvalDelta{}, ad.EvalDelta)

	b.ResetWrites()

	// check existing application with successful ClearStateProgram. two
	// puts: one to write global state, one to opt out
	steva.pass = true
	err = applyClearState(&ac, &b, sender, appIdx, ad, &steva)
	a.NoError(err)
	a.Equal(2, b.put)
	a.Equal(0, b.putWith)
	a.Equal(0, len(br.AppLocalStates))
	a.Equal(basics.StateSchema{}, br.TotalAppSchema)
	a.Equal(basics.EvalDelta{GlobalDelta: gd}, ad.EvalDelta)
}

func TestAppCallApplyCloseOut(t *testing.T) {
	a := require.New(t)

	creator := getRandomAddress(a)
	sender := getRandomAddress(a)
	var txnCounter uint64 = 1
	appIdx := basics.AppIndex(txnCounter + 1)

	ac := transactions.ApplicationCallTxnFields{
		ApplicationID: appIdx,
		OnCompletion:  transactions.CloseOutOC,
	}
	params := basics.AppParams{
		ApprovalProgram: []byte{1},
		StateSchemas: basics.StateSchemas{
			GlobalStateSchema: basics.StateSchema{NumUint: 1},
		},
	}
	h := transactions.Header{
		Sender: sender,
	}
	var steva testEvaluator
	var ad *transactions.ApplyData = &transactions.ApplyData{}
	var b testBalances

	b.balances = make(map[basics.Address]basics.AccountData)
	cbr := basics.AccountData{
		AppParams: map[basics.AppIndex]basics.AppParams{appIdx: params},
	}
	cp := basics.AccountData{
		AppParams: map[basics.AppIndex]basics.AppParams{appIdx: params},
	}
	b.balances[creator] = cp
	b.appCreators = map[basics.AppIndex]basics.Address{appIdx: creator}

	b.SetProto(protocol.ConsensusFuture)

	steva.pass = false
	err := ApplicationCall(ac, h, &b, ad, txnCounter, &steva)
	a.Error(err)
	a.Contains(err.Error(), "transaction rejected by ApprovalProgram")
	a.Equal(steva.appIdx, appIdx)
	a.Equal(0, b.put)
	a.Equal(0, b.putWith)
	br := b.balances[creator]
	a.Equal(cbr, br)
	a.Equal(basics.EvalDelta{}, ad.EvalDelta)

	// check closing on empty sender's balance record
	steva.pass = true
	b.balances[sender] = basics.AccountData{}
	err = ApplicationCall(ac, h, &b, ad, txnCounter, &steva)
	a.Error(err)
	a.Contains(err.Error(), "is not opted in to app")
	a.Equal(0, b.put)
	a.Equal(0, b.putWith)
	br = b.balances[creator]
	a.Equal(cbr, br)
	a.Equal(basics.EvalDelta{}, ad.EvalDelta)

	b.ResetWrites()

	// check a happy case
	gd := map[string]basics.ValueDelta{"uint": {Action: basics.SetUintAction, Uint: 1}}
	steva.delta = basics.EvalDelta{GlobalDelta: gd}
	b.balances[sender] = basics.AccountData{
		AppLocalStates: map[basics.AppIndex]basics.AppLocalState{appIdx: {}},
	}
	err = ApplicationCall(ac, h, &b, ad, txnCounter, &steva)
	a.NoError(err)
	a.Equal(2, b.put)
	a.Equal(0, b.putWith)
	br = b.putBalances[creator]
	a.NotEqual(cbr, br)
	a.Equal(basics.TealKeyValue{"uint": basics.TealValue{Type: basics.TealUintType, Uint: 1}}, br.AppParams[appIdx].GlobalState)
	br = b.putBalances[sender]
	a.Equal(0, len(br.AppLocalStates))
	a.Equal(basics.EvalDelta{GlobalDelta: gd}, ad.EvalDelta)
	a.Equal(basics.StateSchema{NumUint: 0}, br.TotalAppSchema)
}

func TestAppCallApplyUpdate(t *testing.T) {
	a := require.New(t)

	creator := getRandomAddress(a)
	sender := getRandomAddress(a)
	var txnCounter uint64 = 1
	appIdx := basics.AppIndex(txnCounter + 1)

	ac := transactions.ApplicationCallTxnFields{
		ApplicationID:     appIdx,
		OnCompletion:      transactions.UpdateApplicationOC,
		ApprovalProgram:   []byte{2},
		ClearStateProgram: []byte{3},
	}
	params := basics.AppParams{
		ApprovalProgram: []byte{1},
		StateSchemas: basics.StateSchemas{
			GlobalStateSchema: basics.StateSchema{NumUint: 1},
		},
	}
	h := transactions.Header{
		Sender: sender,
	}
	var steva testEvaluator
	var ad *transactions.ApplyData = &transactions.ApplyData{}
	var b testBalances

	b.balances = make(map[basics.Address]basics.AccountData)
	cbr := basics.AccountData{
		AppParams: map[basics.AppIndex]basics.AppParams{appIdx: params},
	}
	cp := basics.AccountData{
		AppParams: map[basics.AppIndex]basics.AppParams{appIdx: params},
	}
	b.balances[creator] = cp
	b.appCreators = map[basics.AppIndex]basics.Address{appIdx: creator}

	b.SetProto(protocol.ConsensusFuture)

	steva.pass = false
	err := ApplicationCall(ac, h, &b, ad, txnCounter, &steva)
	a.Error(err)
	a.Contains(err.Error(), "transaction rejected by ApprovalProgram")
	a.Equal(steva.appIdx, appIdx)
	a.Equal(0, b.put)
	a.Equal(0, b.putWith)
	br := b.balances[creator]
	a.Equal(cbr, br)
	a.Equal(basics.EvalDelta{}, ad.EvalDelta)

	// check updating on empty sender's balance record - happy case
	steva.pass = true
	b.balances[sender] = basics.AccountData{}
	err = ApplicationCall(ac, h, &b, ad, txnCounter, &steva)
	a.NoError(err)
	a.Equal(1, b.put)
	a.Equal(0, b.putWith)
	br = b.balances[creator]
	a.Equal(cbr, br)
	br = b.putBalances[creator]
	a.Equal([]byte{2}, br.AppParams[appIdx].ApprovalProgram)
	a.Equal([]byte{3}, br.AppParams[appIdx].ClearStateProgram)
	a.Equal(basics.EvalDelta{}, ad.EvalDelta)
}

func TestAppCallApplyDelete(t *testing.T) {
	a := require.New(t)

	creator := getRandomAddress(a)
	sender := getRandomAddress(a)
	var txnCounter uint64 = 1
	appIdx := basics.AppIndex(txnCounter + 1)

	ac := transactions.ApplicationCallTxnFields{
		ApplicationID: appIdx,
		OnCompletion:  transactions.DeleteApplicationOC,
	}
	params := basics.AppParams{
		ApprovalProgram: []byte{1},
		StateSchemas: basics.StateSchemas{
			GlobalStateSchema: basics.StateSchema{NumUint: 1},
		},
	}
	h := transactions.Header{
		Sender: sender,
	}
	var steva testEvaluator
	var ad *transactions.ApplyData = &transactions.ApplyData{}
	var b testBalances

	b.balances = make(map[basics.Address]basics.AccountData)
	cbr := basics.AccountData{
		AppParams: map[basics.AppIndex]basics.AppParams{appIdx: params},
	}
	cp := basics.AccountData{
		AppParams: map[basics.AppIndex]basics.AppParams{appIdx: params},
	}
	b.balances[creator] = cp
	b.appCreators = map[basics.AppIndex]basics.Address{appIdx: creator}

	b.SetProto(protocol.ConsensusFuture)

	steva.pass = false
	err := ApplicationCall(ac, h, &b, ad, txnCounter, &steva)
	a.Error(err)
	a.Contains(err.Error(), "transaction rejected by ApprovalProgram")
	a.Equal(steva.appIdx, appIdx)
	a.Equal(0, b.put)
	a.Equal(0, b.putWith)
	br := b.balances[creator]
	a.Equal(cbr, br)
	a.Equal(basics.EvalDelta{}, ad.EvalDelta)

	// check deletion on empty balance record - happy case
	steva.pass = true
	b.balances[sender] = basics.AccountData{}
	err = ApplicationCall(ac, h, &b, ad, txnCounter, &steva)
	a.NoError(err)
	a.Equal(0, b.put)
	a.Equal(1, b.putWith)
	br = b.balances[creator]
	a.Equal(cbr, br)
	br = b.putBalances[creator]
	a.Equal(basics.AppParams{}, br.AppParams[appIdx])
	a.Equal(basics.StateSchema{}, br.TotalAppSchema)
	a.Equal(basics.EvalDelta{}, ad.EvalDelta)
}

func TestAppCallApplyCreateClearState(t *testing.T) {
	a := require.New(t)

	creator := getRandomAddress(a)
	sender := creator
	ac := transactions.ApplicationCallTxnFields{
		ApplicationID:     0,
		ApprovalProgram:   []byte{1},
		ClearStateProgram: []byte{2},
		GlobalStateSchema: basics.StateSchema{NumUint: 1},
		OnCompletion:      transactions.ClearStateOC,
	}
	h := transactions.Header{
		Sender: sender,
	}
	var steva testEvaluator
	var txnCounter uint64 = 1
	appIdx := basics.AppIndex(txnCounter + 1)
	var ad *transactions.ApplyData = &transactions.ApplyData{}
	var b testBalancesPass

	b.balances = make(map[basics.Address]basics.AccountData)
	b.balances[creator] = basics.AccountData{}
	b.SetProto(protocol.ConsensusFuture)
	b.appCreators = map[basics.AppIndex]basics.Address{appIdx: creator}

	steva.pass = true
	gd := map[string]basics.ValueDelta{"uint": {Action: basics.SetUintAction, Uint: 1}}
	steva.delta = basics.EvalDelta{GlobalDelta: gd}

	// check creation on empty balance record
	err := ApplicationCall(ac, h, &b, ad, txnCounter, &steva)
	a.Error(err)
	a.Contains(err.Error(), "not currently opted in")
	a.Equal(steva.appIdx, appIdx)
	a.Equal(basics.EvalDelta{}, ad.EvalDelta)
	br := b.balances[creator]
	a.Equal([]byte{1}, br.AppParams[appIdx].ApprovalProgram)
	a.Equal([]byte{2}, br.AppParams[appIdx].ClearStateProgram)
	a.Equal(basics.StateSchema{NumUint: 1}, br.AppParams[appIdx].GlobalStateSchema)
	a.Equal(basics.StateSchema{}, br.AppParams[appIdx].LocalStateSchema)
	a.Equal(basics.StateSchema{NumUint: 1}, br.TotalAppSchema)
	a.Equal(basics.TealKeyValue(nil), br.AppParams[appIdx].GlobalState)
}

func TestAppCallApplyCreateDelete(t *testing.T) {
	a := require.New(t)

	creator := getRandomAddress(a)
	sender := creator
	ac := transactions.ApplicationCallTxnFields{
		ApplicationID:     0,
		ApprovalProgram:   []byte{1},
		ClearStateProgram: []byte{1},
		GlobalStateSchema: basics.StateSchema{NumUint: 1},
		OnCompletion:      transactions.DeleteApplicationOC,
	}
	h := transactions.Header{
		Sender: sender,
	}
	var steva testEvaluator
	var txnCounter uint64 = 1
	appIdx := basics.AppIndex(txnCounter + 1)
	var ad *transactions.ApplyData = &transactions.ApplyData{}
	var b testBalancesPass

	b.balances = make(map[basics.Address]basics.AccountData)
	b.balances[creator] = basics.AccountData{}
	b.SetProto(protocol.ConsensusFuture)
	b.appCreators = map[basics.AppIndex]basics.Address{appIdx: creator}

	steva.pass = true
	gd := map[string]basics.ValueDelta{"uint": {Action: basics.SetUintAction, Uint: 1}}
	steva.delta = basics.EvalDelta{GlobalDelta: gd}

	// check creation on empty balance record
	err := ApplicationCall(ac, h, &b, ad, txnCounter, &steva)
	a.NoError(err)
	a.Equal(steva.appIdx, appIdx)
	a.Equal(basics.EvalDelta{GlobalDelta: gd}, ad.EvalDelta)
	br := b.balances[creator]
	a.Equal(basics.AppParams{}, br.AppParams[appIdx])
}
