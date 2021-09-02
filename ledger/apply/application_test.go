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
	"github.com/algorand/go-algorand/data/transactions/logic"
	"github.com/algorand/go-algorand/ledger/ledgercore"
	"github.com/algorand/go-algorand/protocol"
	"github.com/algorand/go-algorand/test/partitiontest"
)

func TestApplicationCallFieldsEmpty(t *testing.T) {
	partitiontest.PartitionTest(t)

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

	ac.ExtraProgramPages = 0
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

	put               int // Put calls counter
	putBalances       map[basics.Address]basics.AccountData
	createdCreatables []basics.CreatableLocator
	deletedCreatables []basics.CreatableLocator
	allocatedAppIdx   basics.AppIndex
	deAllocatedAppIdx basics.AppIndex

	// logic evaluator control
	pass  bool
	delta transactions.EvalDelta
	err   error
}

type testBalancesPass struct {
	testBalances
}

const appIdxError basics.AppIndex = 0x11223344
const appIdxOk basics.AppIndex = 1

func (b *testBalances) Get(addr basics.Address, withPendingRewards bool) (basics.AccountData, error) {
	if b.putBalances != nil {
		ad, ok := b.putBalances[addr]
		if ok {
			return ad, nil
		}
	}
	ad, ok := b.balances[addr]
	if !ok {
		return basics.AccountData{}, fmt.Errorf("mock balance not found")
	}
	return ad, nil
}

func (b *testBalances) Put(addr basics.Address, ad basics.AccountData) error {
	b.put++
	if b.putBalances == nil {
		b.putBalances = make(map[basics.Address]basics.AccountData)
	}
	b.putBalances[addr] = ad
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

func (b *testBalances) ConsensusParams() config.ConsensusParams {
	return b.proto
}

func (b *testBalances) AllocateApp(addr basics.Address, aidx basics.AppIndex, global bool, space basics.StateSchema) error {
	b.allocatedAppIdx = aidx

	if global {
		locator := basics.CreatableLocator{
			Type:    basics.AppCreatable,
			Creator: addr,
			Index:   basics.CreatableIndex(aidx),
		}
		b.createdCreatables = append(b.createdCreatables, locator)
	}

	return nil
}

func (b *testBalances) DeallocateApp(addr basics.Address, aidx basics.AppIndex, global bool) error {
	b.deAllocatedAppIdx = aidx

	if global {
		locator := basics.CreatableLocator{
			Type:    basics.AppCreatable,
			Creator: addr,
			Index:   basics.CreatableIndex(aidx),
		}
		b.deletedCreatables = append(b.deletedCreatables, locator)
	}

	return nil
}

func (b *testBalances) AllocateAsset(addr basics.Address, index basics.AssetIndex, global bool) error {
	if global {
		locator := basics.CreatableLocator{
			Type:    basics.AppCreatable,
			Creator: addr,
			Index:   basics.CreatableIndex(index),
		}
		b.createdCreatables = append(b.createdCreatables, locator)
	}

	return nil
}

func (b *testBalances) DeallocateAsset(addr basics.Address, index basics.AssetIndex, global bool) error {
	if global {
		locator := basics.CreatableLocator{
			Type:    basics.AppCreatable,
			Creator: addr,
			Index:   basics.CreatableIndex(index),
		}
		b.deletedCreatables = append(b.deletedCreatables, locator)
	}

	return nil
}

func (b *testBalances) StatefulEval(params logic.EvalParams, aidx basics.AppIndex, program []byte) (passed bool, evalDelta transactions.EvalDelta, err error) {
	return b.pass, b.delta, b.err
}

func (b *testBalancesPass) Get(addr basics.Address, withPendingRewards bool) (basics.AccountData, error) {
	ad, ok := b.balances[addr]
	if !ok {
		return basics.AccountData{}, fmt.Errorf("mock balance not found")
	}
	return ad, nil
}

func (b *testBalancesPass) Put(addr basics.Address, ad basics.AccountData) error {
	if b.balances == nil {
		b.balances = make(map[basics.Address]basics.AccountData)
	}
	b.balances[addr] = ad
	return nil
}

func (b *testBalancesPass) ConsensusParams() config.ConsensusParams {
	return b.proto
}

func (b *testBalancesPass) Allocate(addr basics.Address, aidx basics.AppIndex, global bool, space basics.StateSchema) error {
	b.allocatedAppIdx = aidx
	return nil
}

func (b *testBalancesPass) Deallocate(addr basics.Address, aidx basics.AppIndex, global bool) error {
	return nil
}

func (b *testBalancesPass) StatefulEval(params logic.EvalParams, aidx basics.AppIndex, program []byte) (passed bool, evalDelta transactions.EvalDelta, err error) {
	return true, b.delta, nil
}

// ResetWrites clears side effects of Put.
func (b *testBalances) ResetWrites() {
	b.put = 0
	b.putBalances = nil
	b.createdCreatables = []basics.CreatableLocator{}
	b.deletedCreatables = []basics.CreatableLocator{}
	b.allocatedAppIdx = 0
}

func (b *testBalances) SetProto(name protocol.ConsensusVersion) {
	b.proto = config.Consensus[name]
}

func (b *testBalances) SetParams(params config.ConsensusParams) {
	b.proto = params
}

type testEvaluator struct {
	pass   bool
	delta  transactions.EvalDelta
	appIdx basics.AppIndex
}

// Eval for tests that fail on program version > 10 and returns pass/delta from its own state rather than running the program
func (e *testEvaluator) Eval(program []byte) (pass bool, stateDelta transactions.EvalDelta, err error) {
	if len(program) < 1 || program[0] > 10 {
		return false, transactions.EvalDelta{}, fmt.Errorf("mock eval error")
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

func TestAppCallCloneEmpty(t *testing.T) {
	partitiontest.PartitionTest(t)

	a := require.New(t)

	var ls map[basics.AppIndex]basics.AppLocalState
	cls := cloneAppLocalStates(ls)
	a.Equal(0, len(cls))

	var ap map[basics.AppIndex]basics.AppParams
	cap := cloneAppParams(ap)
	a.Equal(0, len(cap))
}

func TestAppCallGetParam(t *testing.T) {
	partitiontest.PartitionTest(t)

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
	partitiontest.PartitionTest(t)

	a := require.New(t)

	sender := getRandomAddress(a)
	var ac transactions.ApplicationCallTxnFields
	addr, err := ac.AddressByIndex(0, sender)
	a.NoError(err)
	a.Equal(sender, addr)

	addr, err = ac.AddressByIndex(1, sender)
	a.Error(err)
	a.Contains(err.Error(), "invalid Account reference 1")
	a.Equal(0, len(ac.Accounts))

	acc0 := getRandomAddress(a)
	ac.Accounts = []basics.Address{acc0}
	addr, err = ac.AddressByIndex(1, sender)
	a.NoError(err)
	a.Equal(acc0, addr)

	addr, err = ac.AddressByIndex(2, sender)
	a.Error(err)
	a.Contains(err.Error(), "invalid Account reference 2")
}

func TestAppCallCheckPrograms(t *testing.T) {
	partitiontest.PartitionTest(t)

	a := require.New(t)

	var ac transactions.ApplicationCallTxnFields
	var ep logic.EvalParams
	// This check is for static costs. v26 is last with static cost checking
	proto := config.Consensus[protocol.ConsensusV26]
	ep.Proto = &proto

	proto.MaxAppProgramCost = 1
	err := checkPrograms(&ac, &ep)
	a.Error(err)
	a.Contains(err.Error(), "check failed on ApprovalProgram")

	program := []byte{2, 0x20, 1, 1, 0x22} // version, intcb, int 1
	ac.ApprovalProgram = program
	ac.ClearStateProgram = program

	err = checkPrograms(&ac, &ep)
	a.Error(err)
	a.Contains(err.Error(), "check failed on ApprovalProgram")

	proto.MaxAppProgramCost = 10
	err = checkPrograms(&ac, &ep)
	a.NoError(err)

	ac.ClearStateProgram = append(ac.ClearStateProgram, program...)
	ac.ClearStateProgram = append(ac.ClearStateProgram, program...)
	ac.ClearStateProgram = append(ac.ClearStateProgram, program...)
	err = checkPrograms(&ac, &ep)
	a.Error(err)
	a.Contains(err.Error(), "check failed on ClearStateProgram")

	ac.ClearStateProgram = program
	err = checkPrograms(&ac, &ep)
	a.NoError(err)
}

func TestAppCallCreate(t *testing.T) {
	partitiontest.PartitionTest(t)

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
	a.Equal(1, b.put)
	nbr, ok := b.putBalances[creator]
	a.True(ok)
	params, ok := nbr.AppParams[appIdx]
	a.True(ok)
	a.Equal(ac.ApprovalProgram, params.ApprovalProgram)
	a.Equal(ac.ClearStateProgram, params.ClearStateProgram)
	a.Equal(ac.LocalStateSchema, params.LocalStateSchema)
	a.Equal(ac.GlobalStateSchema, params.GlobalStateSchema)
	a.Equal(1, len(b.createdCreatables))
}

// TestAppCallApplyCreate carefully tracks and validates balance record updates
func TestAppCallApplyCreate(t *testing.T) {
	partitiontest.PartitionTest(t)

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
	var ep logic.EvalParams
	var txnCounter uint64 = 1
	var b testBalances

	err := ApplicationCall(ac, h, &b, nil, &ep, txnCounter)
	a.Error(err)
	a.Contains(err.Error(), "ApplicationCall cannot have nil ApplyData")
	a.Equal(0, b.put)

	b.balances = make(map[basics.Address]basics.AccountData)
	b.balances[creator] = basics.AccountData{}
	var ad *transactions.ApplyData = &transactions.ApplyData{}

	err = ApplicationCall(ac, h, &b, ad, &ep, txnCounter)
	a.Error(err)
	a.Contains(err.Error(), "max created apps per acct is 0")
	a.Equal(0, b.put)

	b.SetProto(protocol.ConsensusFuture)
	proto := b.ConsensusParams()
	ep.Proto = &proto

	// this test will succeed in creating the app, but then fail
	// because the mock balances doesn't update the creators table
	// so it will think the app doesn't exist
	err = ApplicationCall(ac, h, &b, ad, &ep, txnCounter)
	a.Error(err)
	a.Contains(err.Error(), "applications that do not exist")
	a.Equal(1, b.put)

	appIdx := basics.AppIndex(txnCounter + 1)
	b.appCreators = map[basics.AppIndex]basics.Address{appIdx: creator}

	// save the created app info to the side
	saved := b.putBalances[creator]

	b.ResetWrites()

	// now we give the creator the app params again
	cp := basics.AccountData{}
	cp.AppParams = cloneAppParams(saved.AppParams)
	cp.AppLocalStates = cloneAppLocalStates(saved.AppLocalStates)
	b.balances[creator] = cp
	err = ApplicationCall(ac, h, &b, ad, &ep, txnCounter)
	a.Error(err)
	a.Contains(err.Error(), "transaction rejected by ApprovalProgram")
	a.Equal(uint64(b.allocatedAppIdx), txnCounter+1)
	a.Equal(1, b.put)
	// ensure original balance record in the mock was not changed
	// this ensure proper cloning and any in-intended in-memory modifications
	//
	// known artefact of cloning AppLocalState even with empty update, nil map vs empty map
	saved.AppLocalStates = map[basics.AppIndex]basics.AppLocalState{}
	a.Equal(saved, b.balances[creator])
	saved = b.putBalances[creator]

	b.ResetWrites()

	b.pass = true
	cp = basics.AccountData{}
	cp.AppParams = cloneAppParams(saved.AppParams)
	cp.AppLocalStates = cloneAppLocalStates(saved.AppLocalStates)
	cp.TotalAppSchema = saved.TotalAppSchema
	b.balances[creator] = cp

	ac.GlobalStateSchema = basics.StateSchema{NumUint: 1}
	err = ApplicationCall(ac, h, &b, ad, &ep, txnCounter)
	a.NoError(err)
	a.Equal(appIdx, b.allocatedAppIdx)
	a.Equal(1, b.put)
	a.Equal(saved, b.balances[creator])
	br := b.putBalances[creator]
	a.Equal([]byte{1}, br.AppParams[appIdx].ApprovalProgram)
	a.Equal([]byte{1}, br.AppParams[appIdx].ClearStateProgram)
	a.Equal(basics.TealKeyValue(nil), br.AppParams[appIdx].GlobalState)
	a.Equal(basics.StateSchema{NumUint: 1}, br.AppParams[appIdx].GlobalStateSchema)
	a.Equal(basics.StateSchema{}, br.AppParams[appIdx].LocalStateSchema)
	a.Equal(basics.StateSchema{NumUint: 1}, br.TotalAppSchema)
	a.Equal(basics.StateSchema{}, br.AppParams[appIdx].LocalStateSchema)

	ac.ExtraProgramPages = 1
	err = ApplicationCall(ac, h, &b, ad, &ep, txnCounter)
	a.NoError(err)
	br = b.putBalances[creator]
	a.Equal(uint32(1), br.AppParams[appIdx].ExtraProgramPages)
	a.Equal(uint32(1), br.TotalExtraAppPages)
}

// TestAppCallApplyCreateOptIn checks balance record fields without tracking substages
func TestAppCallApplyCreateOptIn(t *testing.T) {
	partitiontest.PartitionTest(t)

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
	var ep logic.EvalParams
	var txnCounter uint64 = 1
	appIdx := basics.AppIndex(txnCounter + 1)
	var ad *transactions.ApplyData = &transactions.ApplyData{}
	var b testBalancesPass

	b.balances = make(map[basics.Address]basics.AccountData)
	b.balances[creator] = basics.AccountData{}
	b.SetProto(protocol.ConsensusFuture)
	proto := b.ConsensusParams()
	ep.Proto = &proto
	b.appCreators = map[basics.AppIndex]basics.Address{appIdx: creator}

	gd := map[string]basics.ValueDelta{"uint": {Action: basics.SetUintAction, Uint: 1}}
	b.delta = transactions.EvalDelta{GlobalDelta: gd}

	err := ApplicationCall(ac, h, &b, ad, &ep, txnCounter)
	a.NoError(err)
	a.Equal(appIdx, b.allocatedAppIdx)
	br := b.balances[creator]
	a.Equal([]byte{1}, br.AppParams[appIdx].ApprovalProgram)
	a.Equal([]byte{1}, br.AppParams[appIdx].ClearStateProgram)
	a.Equal(basics.TealKeyValue(nil), br.AppParams[appIdx].GlobalState)
	a.Equal(basics.StateSchema{NumUint: 1}, br.AppParams[appIdx].GlobalStateSchema)
	a.Equal(basics.StateSchema{NumByteSlice: 2}, br.AppParams[appIdx].LocalStateSchema)
	a.Equal(basics.StateSchema{NumByteSlice: 2}, br.AppLocalStates[appIdx].Schema)
	a.Equal(basics.StateSchema{NumUint: 1, NumByteSlice: 2}, br.TotalAppSchema)
}

func TestAppCallOptIn(t *testing.T) {
	partitiontest.PartitionTest(t)

	a := require.New(t)

	sender := getRandomAddress(a)

	var txnCounter uint64 = 1
	appIdx := basics.AppIndex(txnCounter + 1)
	var b testBalances
	ad := basics.AccountData{}
	b.balances = map[basics.Address]basics.AccountData{sender: ad}

	var params basics.AppParams

	err := optInApplication(&b, sender, appIdx, params)
	a.Error(err)
	a.Contains(err.Error(), "cannot opt in app")
	a.Equal(0, b.put)

	b.SetProto(protocol.ConsensusFuture)
	err = optInApplication(&b, sender, appIdx, params)
	a.NoError(err)
	a.Equal(1, b.put)
	br := b.putBalances[sender]
	a.Equal(basics.AccountData{AppLocalStates: map[basics.AppIndex]basics.AppLocalState{appIdx: {}}}, br)

	b.ResetWrites()

	ad.AppLocalStates = make(map[basics.AppIndex]basics.AppLocalState)
	ad.AppLocalStates[appIdx] = basics.AppLocalState{}
	b.balances = map[basics.Address]basics.AccountData{sender: ad}
	err = optInApplication(&b, sender, appIdx, params)
	a.Error(err)
	a.Contains(err.Error(), "has already opted in to app")
	a.Equal(0, b.put)

	b.ResetWrites()

	delete(ad.AppLocalStates, appIdx)
	ad.AppLocalStates[appIdx+1] = basics.AppLocalState{}
	b.balances = map[basics.Address]basics.AccountData{sender: ad}
	err = optInApplication(&b, sender, appIdx, params)
	a.NoError(err)
	a.Equal(1, b.put)

	b.ResetWrites()

	ad.AppLocalStates[appIdx+1] = basics.AppLocalState{
		Schema: basics.StateSchema{NumByteSlice: 1},
	}
	ad.TotalAppSchema = basics.StateSchema{NumByteSlice: 1}
	params.LocalStateSchema = basics.StateSchema{NumUint: 1}
	b.balances = map[basics.Address]basics.AccountData{sender: ad}
	err = optInApplication(&b, sender, appIdx, params)
	a.NoError(err)
	a.Equal(1, b.put)
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

	// check max optins

	var optInCountTest = []struct {
		proto protocol.ConsensusVersion
	}{
		{protocol.ConsensusV29},
		{protocol.ConsensusFuture},
	}

	prevMaxAppsOptedIn := 0
	for _, test := range optInCountTest {
		cparams, ok := config.Consensus[test.proto]
		a.True(ok)
		a.Less(prevMaxAppsOptedIn, cparams.MaxAppsOptedIn)
		prevMaxAppsOptedIn = cparams.MaxAppsOptedIn

		b.SetParams(cparams)
		aparams := basics.AppParams{
			StateSchemas: basics.StateSchemas{
				LocalStateSchema: basics.StateSchema{NumUint: 1},
			},
		}
		sender = getRandomAddress(a)
		b.balances = map[basics.Address]basics.AccountData{sender: {}}
		var appIdx basics.AppIndex = appIdx
		for i := 0; i < cparams.MaxAppsOptedIn; i++ {
			appIdx = appIdx + basics.AppIndex(i)
			err = optInApplication(&b, sender, appIdx, aparams)
			a.NoError(err)
		}
		appIdx++
		err = optInApplication(&b, sender, appIdx, aparams)
		a.Error(err)
		a.Contains(err.Error(), "max opted-in apps per acct")
	}
}

func TestAppCallClearState(t *testing.T) {
	partitiontest.PartitionTest(t)

	a := require.New(t)

	creator := getRandomAddress(a)
	sender := getRandomAddress(a)
	var txnCounter uint64 = 1
	appIdx := basics.AppIndex(txnCounter + 1)
	var b testBalances
	var ep logic.EvalParams

	ad := &transactions.ApplyData{}
	b.appCreators = make(map[basics.AppIndex]basics.Address)
	b.balances = make(map[basics.Address]basics.AccountData, 2)
	b.SetProto(protocol.ConsensusFuture)
	proto := b.ConsensusParams()
	ep.Proto = &proto

	ac := transactions.ApplicationCallTxnFields{
		ApplicationID: appIdx,
		OnCompletion:  transactions.ClearStateOC,
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

	b.balances = make(map[basics.Address]basics.AccountData)
	cp := basics.AccountData{
		AppParams: map[basics.AppIndex]basics.AppParams{appIdx: params},
	}
	b.balances[creator] = cp
	b.appCreators = map[basics.AppIndex]basics.Address{appIdx: creator}

	b.pass = true
	// check app not exist and not opted in
	b.balances[sender] = basics.AccountData{}
	err := ApplicationCall(ac, h, &b, ad, &ep, txnCounter)
	a.Error(err)
	a.Contains(err.Error(), "is not currently opted in to app")
	a.Equal(0, b.put)

	// check non-existing app with empty opt-in
	b.balances[sender] = basics.AccountData{
		AppLocalStates: map[basics.AppIndex]basics.AppLocalState{appIdx: {}},
	}
	err = ApplicationCall(ac, h, &b, ad, &ep, txnCounter)
	a.NoError(err)
	a.Equal(1, b.put)
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
	err = ApplicationCall(ac, h, &b, ad, &ep, txnCounter)
	a.NoError(err)
	a.Equal(1, b.put)
	br = b.putBalances[sender]
	a.Equal(0, len(br.AppLocalStates))
	a.Equal(basics.StateSchema{}, br.TotalAppSchema)
	a.Equal(transactions.EvalDelta{}, ad.EvalDelta)

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
	b.pass = false
	b.delta = transactions.EvalDelta{GlobalDelta: nil}
	err = ApplicationCall(ac, h, &b, ad, &ep, txnCounter)
	a.NoError(err)
	a.Equal(1, b.put)
	br = b.putBalances[sender]
	a.Equal(0, len(br.AppLocalStates))
	a.Equal(basics.StateSchema{}, br.TotalAppSchema)
	a.Equal(basics.StateDelta(nil), ad.EvalDelta.GlobalDelta)

	b.ResetWrites()

	// check existing application with logic err ClearStateProgram.
	// one to opt out, one deallocate, no error from ApplicationCall
	b.pass = true
	b.delta = transactions.EvalDelta{GlobalDelta: nil}
	b.err = ledgercore.LogicEvalError{Err: fmt.Errorf("test error")}
	err = ApplicationCall(ac, h, &b, ad, &ep, txnCounter)
	a.NoError(err)
	a.Equal(1, b.put)
	br = b.putBalances[sender]
	a.Equal(0, len(br.AppLocalStates))
	a.Equal(basics.StateSchema{}, br.TotalAppSchema)
	a.Equal(basics.StateDelta(nil), ad.EvalDelta.GlobalDelta)

	b.ResetWrites()

	// check existing application with non-logic err ClearStateProgram.
	// ApplicationCall must fail
	b.pass = true
	b.delta = transactions.EvalDelta{GlobalDelta: nil}
	b.err = fmt.Errorf("test error")
	err = ApplicationCall(ac, h, &b, ad, &ep, txnCounter)
	a.Error(err)
	br = b.putBalances[sender]
	a.Equal(0, len(br.AppLocalStates))
	a.Equal(basics.StateSchema{}, br.TotalAppSchema)
	a.Equal(basics.StateDelta(nil), ad.EvalDelta.GlobalDelta)

	b.ResetWrites()

	// check existing application with successful ClearStateProgram.
	// one to opt out, one deallocate, no error from ApplicationCall
	b.pass = true
	b.err = nil
	gd := basics.StateDelta{"uint": {Action: basics.SetUintAction, Uint: 1}}
	b.delta = transactions.EvalDelta{GlobalDelta: gd}
	err = ApplicationCall(ac, h, &b, ad, &ep, txnCounter)
	a.NoError(err)
	a.Equal(1, b.put)
	a.Equal(appIdx, b.deAllocatedAppIdx)
	a.Equal(0, len(br.AppLocalStates))
	a.Equal(basics.StateSchema{}, br.TotalAppSchema)
	a.Equal(transactions.EvalDelta{GlobalDelta: gd}, ad.EvalDelta)

	b.ResetWrites()
	b.pass = true
	b.err = nil
	logs := []string{"a"}
	b.delta = transactions.EvalDelta{Logs: []string{"a"}}
	err = ApplicationCall(ac, h, &b, ad, &ep, txnCounter)
	a.NoError(err)
	a.Equal(transactions.EvalDelta{Logs: logs}, ad.EvalDelta)
}

func TestAppCallApplyCloseOut(t *testing.T) {
	partitiontest.PartitionTest(t)

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
	var ep logic.EvalParams
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
	proto := b.ConsensusParams()
	ep.Proto = &proto

	b.pass = false
	err := ApplicationCall(ac, h, &b, ad, &ep, txnCounter)
	a.Error(err)
	a.Contains(err.Error(), "transaction rejected by ApprovalProgram")
	a.Equal(0, b.put)
	br := b.balances[creator]
	a.Equal(cbr, br)
	a.Equal(transactions.EvalDelta{}, ad.EvalDelta)

	// check closing on empty sender's balance record
	b.pass = true
	b.balances[sender] = basics.AccountData{}
	err = ApplicationCall(ac, h, &b, ad, &ep, txnCounter)
	a.Error(err)
	a.Contains(err.Error(), "is not opted in to app")
	a.Equal(0, b.put)
	br = b.balances[creator]
	a.Equal(cbr, br)
	a.Equal(transactions.EvalDelta{}, ad.EvalDelta)

	b.ResetWrites()

	// check a happy case
	gd := map[string]basics.ValueDelta{"uint": {Action: basics.SetUintAction, Uint: 1}}
	b.delta = transactions.EvalDelta{GlobalDelta: gd}
	b.balances[sender] = basics.AccountData{
		AppLocalStates: map[basics.AppIndex]basics.AppLocalState{appIdx: {}},
	}
	err = ApplicationCall(ac, h, &b, ad, &ep, txnCounter)
	a.NoError(err)
	a.Equal(1, b.put)
	br = b.putBalances[creator]
	a.NotEqual(cbr, br)
	a.Equal(basics.TealKeyValue(nil), br.AppParams[appIdx].GlobalState)
	br = b.putBalances[sender]
	a.Equal(0, len(br.AppLocalStates))
	a.Equal(transactions.EvalDelta{GlobalDelta: gd}, ad.EvalDelta)
	a.Equal(basics.StateSchema{NumUint: 0}, br.TotalAppSchema)

	b.ResetWrites()
	logs := []string{"a"}
	b.delta = transactions.EvalDelta{Logs: []string{"a"}}
	b.balances[sender] = basics.AccountData{
		AppLocalStates: map[basics.AppIndex]basics.AppLocalState{appIdx: {}},
	}
	err = ApplicationCall(ac, h, &b, ad, &ep, txnCounter)
	a.NoError(err)
	a.Equal(transactions.EvalDelta{Logs: logs}, ad.EvalDelta)
}

func TestAppCallApplyUpdate(t *testing.T) {
	partitiontest.PartitionTest(t)

	a := require.New(t)

	creator := getRandomAddress(a)
	sender := getRandomAddress(a)
	var txnCounter uint64 = 1
	appIdx := basics.AppIndex(txnCounter + 1)

	ac := transactions.ApplicationCallTxnFields{
		ApplicationID:     appIdx,
		OnCompletion:      transactions.UpdateApplicationOC,
		ApprovalProgram:   []byte{2},
		ClearStateProgram: []byte{2},
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
	var ep logic.EvalParams
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

	b.SetProto(protocol.ConsensusV28)
	proto := b.ConsensusParams()
	ep.Proto = &proto

	b.pass = false
	err := ApplicationCall(ac, h, &b, ad, &ep, txnCounter)
	a.Error(err)
	a.Contains(err.Error(), "transaction rejected by ApprovalProgram")
	a.Equal(0, b.put)
	br := b.balances[creator]
	a.Equal(cbr, br)
	a.Equal(transactions.EvalDelta{}, ad.EvalDelta)

	// check updating on empty sender's balance record - happy case
	b.pass = true
	b.balances[sender] = basics.AccountData{}
	err = ApplicationCall(ac, h, &b, ad, &ep, txnCounter)
	a.NoError(err)
	a.Equal(1, b.put)
	br = b.balances[creator]
	a.Equal(cbr, br)
	br = b.putBalances[creator]
	a.Equal([]byte{2}, br.AppParams[appIdx].ApprovalProgram)
	a.Equal([]byte{2}, br.AppParams[appIdx].ClearStateProgram)
	a.Equal(transactions.EvalDelta{}, ad.EvalDelta)

	//check program len check happens in future consensus proto version
	b.SetProto(protocol.ConsensusFuture)
	proto = b.ConsensusParams()
	ep.Proto = &proto

	// check app program len
	params = basics.AppParams{
		ApprovalProgram: []byte{1},
		StateSchemas: basics.StateSchemas{
			GlobalStateSchema: basics.StateSchema{NumUint: 1},
		},
		ExtraProgramPages: 1,
	}
	h = transactions.Header{
		Sender: sender,
	}

	b.balances = make(map[basics.Address]basics.AccountData)
	cbr = basics.AccountData{
		AppParams: map[basics.AppIndex]basics.AppParams{appIdx: params},
	}
	cp = basics.AccountData{
		AppParams: map[basics.AppIndex]basics.AppParams{appIdx: params},
	}
	b.balances[creator] = cp
	b.appCreators = map[basics.AppIndex]basics.Address{appIdx: creator}

	logs := []string{"a"}
	b.delta = transactions.EvalDelta{Logs: []string{"a"}}
	err = ApplicationCall(ac, h, &b, ad, &ep, txnCounter)
	a.NoError(err)
	a.Equal(transactions.EvalDelta{Logs: logs}, ad.EvalDelta)

	// check extraProgramPages is used
	appr := make([]byte, 2*proto.MaxAppProgramLen+1)
	appr[0] = 4 // version 4

	var tests = []struct {
		name     string
		approval []byte
		clear    []byte
	}{
		{"approval", appr, []byte{2}},
		{"clear state", []byte{2}, appr},
	}
	for _, test := range tests {
		ac = transactions.ApplicationCallTxnFields{
			ApplicationID:     appIdx,
			OnCompletion:      transactions.UpdateApplicationOC,
			ApprovalProgram:   test.approval,
			ClearStateProgram: test.clear,
		}

		b.pass = true
		err = ApplicationCall(ac, h, &b, ad, &ep, txnCounter)
		a.Error(err)
		a.Contains(err.Error(), fmt.Sprintf("updateApplication %s program too long", test.name))
	}

	b.ResetWrites()
	// check extraProgramPages allows length of proto.MaxAppProgramLen + 1
	appr = make([]byte, proto.MaxAppProgramLen+1)
	appr[0] = 4
	ac = transactions.ApplicationCallTxnFields{
		ApplicationID:     appIdx,
		OnCompletion:      transactions.UpdateApplicationOC,
		ApprovalProgram:   appr,
		ClearStateProgram: []byte{2},
	}
	b.pass = true
	err = ApplicationCall(ac, h, &b, ad, &ep, txnCounter)
	a.NoError(err)

	// check extraProgramPages is used and long sum rejected
	ac = transactions.ApplicationCallTxnFields{
		ApplicationID:     appIdx,
		OnCompletion:      transactions.UpdateApplicationOC,
		ApprovalProgram:   appr,
		ClearStateProgram: appr,
	}
	b.pass = true
	err = ApplicationCall(ac, h, &b, ad, &ep, txnCounter)
	a.Error(err)
	a.Contains(err.Error(), "updateApplication app programs too long")

}

func TestAppCallApplyDelete(t *testing.T) {
	partitiontest.PartitionTest(t)

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
		ExtraProgramPages: 1,
	}
	h := transactions.Header{
		Sender: sender,
	}
	var ep logic.EvalParams
	var ad *transactions.ApplyData = &transactions.ApplyData{}
	var b testBalances

	b.balances = make(map[basics.Address]basics.AccountData)
	// cbr is to ensure the original balance record is not modified but copied when updated in apply
	cbr := basics.AccountData{
		AppParams:          map[basics.AppIndex]basics.AppParams{appIdx: params},
		TotalExtraAppPages: 1,
	}
	cp := basics.AccountData{
		AppParams:          map[basics.AppIndex]basics.AppParams{appIdx: params},
		TotalExtraAppPages: 1,
	}
	b.balances[creator] = cp
	b.appCreators = map[basics.AppIndex]basics.Address{appIdx: creator}

	// check if it fails nothing changes
	b.SetProto(protocol.ConsensusFuture)
	proto := b.ConsensusParams()
	ep.Proto = &proto

	b.pass = false
	err := ApplicationCall(ac, h, &b, ad, &ep, txnCounter)
	a.Error(err)
	a.Contains(err.Error(), "transaction rejected by ApprovalProgram")
	a.Equal(0, b.put)
	br := b.balances[creator]
	a.Equal(cbr, br)
	a.Equal(transactions.EvalDelta{}, ad.EvalDelta)

	// check calculation on ConsensusV28. TotalExtraAppPages does not change
	b.SetProto(protocol.ConsensusV28)
	proto = b.ConsensusParams()
	ep.Proto = &proto

	b.pass = true
	b.balances[sender] = basics.AccountData{}
	err = ApplicationCall(ac, h, &b, ad, &ep, txnCounter)
	a.NoError(err)
	a.Equal(appIdx, b.deAllocatedAppIdx)
	a.Equal(1, b.put)
	br = b.balances[creator]
	a.Equal(cbr, br)
	br = b.putBalances[creator]
	a.Equal(basics.AppParams{}, br.AppParams[appIdx])
	a.Equal(basics.StateSchema{}, br.TotalAppSchema)
	a.Equal(transactions.EvalDelta{}, ad.EvalDelta)
	a.Equal(uint32(1), br.TotalExtraAppPages)
	b.ResetWrites()

	b.SetProto(protocol.ConsensusFuture)
	proto = b.ConsensusParams()
	ep.Proto = &proto

	// check deletion
	for initTotalExtraPages := uint32(0); initTotalExtraPages < 3; initTotalExtraPages++ {
		cbr = basics.AccountData{
			AppParams:          map[basics.AppIndex]basics.AppParams{appIdx: params},
			TotalExtraAppPages: initTotalExtraPages,
		}
		cp := basics.AccountData{
			AppParams:          map[basics.AppIndex]basics.AppParams{appIdx: params},
			TotalExtraAppPages: initTotalExtraPages,
		}
		b.balances[creator] = cp
		b.pass = true
		b.balances[sender] = basics.AccountData{}
		err = ApplicationCall(ac, h, &b, ad, &ep, txnCounter)
		a.NoError(err)
		a.Equal(appIdx, b.deAllocatedAppIdx)
		a.Equal(1, b.put)
		br = b.balances[creator]
		a.Equal(cbr, br)
		br = b.putBalances[creator]
		a.Equal(basics.AppParams{}, br.AppParams[appIdx])
		a.Equal(basics.StateSchema{}, br.TotalAppSchema)
		a.Equal(transactions.EvalDelta{}, ad.EvalDelta)
		if initTotalExtraPages <= params.ExtraProgramPages {
			a.Equal(uint32(0), br.TotalExtraAppPages)
		} else {
			a.Equal(initTotalExtraPages-1, br.TotalExtraAppPages)
		}
		b.ResetWrites()
	}
	logs := []string{"a"}
	b.delta = transactions.EvalDelta{Logs: []string{"a"}}
	err = ApplicationCall(ac, h, &b, ad, &ep, txnCounter)
	a.NoError(err)
	a.Equal(transactions.EvalDelta{Logs: logs}, ad.EvalDelta)
}

func TestAppCallApplyCreateClearState(t *testing.T) {
	partitiontest.PartitionTest(t)

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
	var ep logic.EvalParams
	var txnCounter uint64 = 1
	appIdx := basics.AppIndex(txnCounter + 1)
	var ad *transactions.ApplyData = &transactions.ApplyData{}
	var b testBalancesPass

	b.balances = make(map[basics.Address]basics.AccountData)
	b.balances[creator] = basics.AccountData{}
	b.SetProto(protocol.ConsensusFuture)
	proto := b.ConsensusParams()
	ep.Proto = &proto

	b.appCreators = map[basics.AppIndex]basics.Address{appIdx: creator}

	b.pass = true
	gd := map[string]basics.ValueDelta{"uint": {Action: basics.SetUintAction, Uint: 1}}
	b.delta = transactions.EvalDelta{GlobalDelta: gd}

	// check creation on empty balance record
	err := ApplicationCall(ac, h, &b, ad, &ep, txnCounter)
	a.Error(err)
	a.Contains(err.Error(), "not currently opted in")
	a.Equal(appIdx, b.allocatedAppIdx)
	a.Equal(transactions.EvalDelta{}, ad.EvalDelta)
	br := b.balances[creator]
	a.Equal([]byte{1}, br.AppParams[appIdx].ApprovalProgram)
	a.Equal([]byte{2}, br.AppParams[appIdx].ClearStateProgram)
	a.Equal(basics.StateSchema{NumUint: 1}, br.AppParams[appIdx].GlobalStateSchema)
	a.Equal(basics.StateSchema{}, br.AppParams[appIdx].LocalStateSchema)
	a.Equal(basics.StateSchema{NumUint: 1}, br.TotalAppSchema)
	a.Equal(basics.TealKeyValue(nil), br.AppParams[appIdx].GlobalState)
}

func TestAppCallApplyCreateDelete(t *testing.T) {
	partitiontest.PartitionTest(t)

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
	var ep logic.EvalParams
	var txnCounter uint64 = 1
	appIdx := basics.AppIndex(txnCounter + 1)
	var ad *transactions.ApplyData = &transactions.ApplyData{}
	var b testBalancesPass

	b.balances = make(map[basics.Address]basics.AccountData)
	b.balances[creator] = basics.AccountData{}
	b.SetProto(protocol.ConsensusFuture)
	proto := b.ConsensusParams()
	ep.Proto = &proto

	b.appCreators = map[basics.AppIndex]basics.Address{appIdx: creator}

	b.pass = true
	gd := map[string]basics.ValueDelta{"uint": {Action: basics.SetUintAction, Uint: 1}}
	b.delta = transactions.EvalDelta{GlobalDelta: gd}

	// check creation on empty balance record
	err := ApplicationCall(ac, h, &b, ad, &ep, txnCounter)
	a.NoError(err)
	a.Equal(appIdx, b.allocatedAppIdx)
	a.Equal(transactions.EvalDelta{GlobalDelta: gd}, ad.EvalDelta)
	br := b.balances[creator]
	a.Equal(basics.AppParams{}, br.AppParams[appIdx])

	logs := []string{"a"}
	b.delta = transactions.EvalDelta{Logs: []string{"a"}}
	err = ApplicationCall(ac, h, &b, ad, &ep, txnCounter)
	a.NoError(err)
	a.Equal(transactions.EvalDelta{Logs: logs}, ad.EvalDelta)

}
