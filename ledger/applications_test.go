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

package ledger

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/transactions"
	"github.com/algorand/go-algorand/data/transactions/logic"
	"github.com/algorand/go-algorand/logging"
	"github.com/algorand/go-algorand/protocol"
)

func getRandomAddress(a *require.Assertions) basics.Address {
	const rl = 16
	b := make([]byte, rl)
	n, err := rand.Read(b)
	a.NoError(err)
	a.Equal(rl, n)

	address := crypto.Hash(b)
	return basics.Address(address)
}

type creatableLocator struct {
	cidx  basics.CreatableIndex
	ctype basics.CreatableType
}
type storeLocator struct {
	addr   basics.Address
	aidx   basics.AppIndex
	global bool
}
type mockCowForLogicLedger struct {
	rnd    basics.Round
	ts     int64
	cr     map[creatableLocator]basics.Address
	brs    map[basics.Address]basics.AccountData
	stores map[storeLocator]basics.TealKeyValue
}

func (c *mockCowForLogicLedger) Get(addr basics.Address, withPendingRewards bool) (basics.AccountData, error) {
	br, ok := c.brs[addr]
	if !ok {
		return basics.AccountData{}, fmt.Errorf("addr %s not in mock cow", addr.String())
	}
	return br, nil
}

func (c *mockCowForLogicLedger) GetCreator(cidx basics.CreatableIndex, ctype basics.CreatableType) (basics.Address, bool, error) {
	addr, found := c.cr[creatableLocator{cidx, ctype}]
	return addr, found, nil
}

func (c *mockCowForLogicLedger) GetKey(addr basics.Address, aidx basics.AppIndex, global bool, key string) (basics.TealValue, bool, error) {
	kv, ok := c.stores[storeLocator{addr, aidx, global}]
	if !ok {
		return basics.TealValue{}, false, fmt.Errorf("no store for (%s %d %v) in mock cow", addr.String(), aidx, global)
	}
	tv, found := kv[key]
	return tv, found, nil
}

func (c *mockCowForLogicLedger) BuildEvalDelta(aidx basics.AppIndex, txn *transactions.Transaction) (evalDelta basics.EvalDelta, err error) {
	return basics.EvalDelta{}, nil
}

func (c *mockCowForLogicLedger) SetKey(addr basics.Address, aidx basics.AppIndex, global bool, key string, value basics.TealValue) error {
	kv, ok := c.stores[storeLocator{addr, aidx, global}]
	if !ok {
		return fmt.Errorf("no store for (%s %d %v) in mock cow", addr.String(), aidx, global)
	}
	kv[key] = value
	c.stores[storeLocator{addr, aidx, global}] = kv
	return nil
}

func (c *mockCowForLogicLedger) DelKey(addr basics.Address, aidx basics.AppIndex, global bool, key string) error {
	kv, ok := c.stores[storeLocator{addr, aidx, global}]
	if !ok {
		return fmt.Errorf("no store for (%s %d %v) in mock cow", addr.String(), aidx, global)
	}
	delete(kv, key)
	c.stores[storeLocator{addr, aidx, global}] = kv
	return nil
}

func (c *mockCowForLogicLedger) round() basics.Round {
	return c.rnd
}

func (c *mockCowForLogicLedger) prevTimestamp() int64 {
	return c.ts
}

func (c *mockCowForLogicLedger) allocated(addr basics.Address, aidx basics.AppIndex, global bool) (bool, error) {
	_, found := c.stores[storeLocator{addr, aidx, global}]
	return found, nil
}

func newCowMock(creatables []modsData) *mockCowForLogicLedger {
	var m mockCowForLogicLedger
	m.cr = make(map[creatableLocator]basics.Address, len(creatables))
	for _, e := range creatables {
		m.cr[creatableLocator{e.cidx, e.ctype}] = e.addr
	}
	return &m
}

func TestLogicLedgerMake(t *testing.T) {
	a := require.New(t)

	_, err := newLogicLedger(nil, 0)
	a.Error(err)
	a.Contains(err.Error(), "cannot make logic ledger for app index 0")

	addr := getRandomAddress(a)
	aidx := basics.AppIndex(1)

	c := &mockCowForLogicLedger{}
	_, err = newLogicLedger(c, 0)
	a.Error(err)
	a.Contains(err.Error(), "cannot make logic ledger for app index 0")

	_, err = newLogicLedger(c, aidx)
	a.Error(err)
	a.Contains(err.Error(), fmt.Sprintf("app %d does not exist", aidx))

	c = newCowMock([]modsData{{addr, basics.CreatableIndex(aidx), basics.AppCreatable}})
	l, err := newLogicLedger(c, aidx)
	a.NoError(err)
	a.NotNil(l)
	a.Equal(aidx, l.aidx)
	a.Equal(c, l.cow)
}

func TestLogicLedgerBalances(t *testing.T) {
	a := require.New(t)

	addr := getRandomAddress(a)
	aidx := basics.AppIndex(1)
	c := newCowMock([]modsData{{addr, basics.CreatableIndex(aidx), basics.AppCreatable}})
	l, err := newLogicLedger(c, aidx)
	a.NoError(err)
	a.NotNil(l)

	addr1 := getRandomAddress(a)
	ble := basics.MicroAlgos{Raw: 100}
	c.brs = map[basics.Address]basics.AccountData{addr1: {MicroAlgos: ble}}
	bla, err := l.Balance(addr1)
	a.NoError(err)
	a.Equal(ble, bla)
}

func TestLogicLedgerGetters(t *testing.T) {
	a := require.New(t)

	addr := getRandomAddress(a)
	aidx := basics.AppIndex(1)
	c := newCowMock([]modsData{{addr, basics.CreatableIndex(aidx), basics.AppCreatable}})
	l, err := newLogicLedger(c, aidx)
	a.NoError(err)
	a.NotNil(l)

	round := basics.Round(1234)
	c.rnd = round
	ts := int64(11223344)
	c.ts = ts

	addr1 := getRandomAddress(a)
	c.stores = map[storeLocator]basics.TealKeyValue{{addr1, aidx, false}: {}}
	a.Equal(aidx, l.ApplicationID())
	a.Equal(round, l.Round())
	a.Equal(ts, l.LatestTimestamp())
	a.True(l.OptedIn(addr1, 0))
	a.True(l.OptedIn(addr1, aidx))
	a.False(l.OptedIn(addr, 0))
	a.False(l.OptedIn(addr, aidx))
}

func TestLogicLedgerAsset(t *testing.T) {
	a := require.New(t)

	addr := getRandomAddress(a)
	addr1 := getRandomAddress(a)
	aidx := basics.AppIndex(1)
	assetIdx := basics.AssetIndex(2)
	c := newCowMock([]modsData{
		{addr, basics.CreatableIndex(aidx), basics.AppCreatable},
		{addr1, basics.CreatableIndex(assetIdx), basics.AssetCreatable},
	})
	l, err := newLogicLedger(c, aidx)
	a.NoError(err)
	a.NotNil(l)

	_, err = l.AssetParams(basics.AssetIndex(aidx))
	a.Error(err)
	a.Contains(err.Error(), fmt.Sprintf("asset %d does not exist", aidx))

	c.brs = map[basics.Address]basics.AccountData{
		addr1: {AssetParams: map[basics.AssetIndex]basics.AssetParams{assetIdx: {Total: 1000}}},
	}
	ap, err := l.AssetParams(assetIdx)
	a.NoError(err)
	a.Equal(uint64(1000), ap.Total)

	_, err = l.AssetHolding(addr1, assetIdx)
	a.Error(err)
	a.Contains(err.Error(), "has not opted in to asset")

	c.brs = map[basics.Address]basics.AccountData{
		addr1: {
			AssetParams: map[basics.AssetIndex]basics.AssetParams{assetIdx: {Total: 1000}},
			Assets:      map[basics.AssetIndex]basics.AssetHolding{assetIdx: {Amount: 99}},
		},
	}

	ah, err := l.AssetHolding(addr1, assetIdx)
	a.NoError(err)
	a.Equal(uint64(99), ah.Amount)
}

func TestLogicLedgerGetKey(t *testing.T) {
	a := require.New(t)

	addr := getRandomAddress(a)
	addr1 := getRandomAddress(a)
	aidx := basics.AppIndex(1)
	assetIdx := basics.AssetIndex(2)
	c := newCowMock([]modsData{
		{addr, basics.CreatableIndex(aidx), basics.AppCreatable},
		{addr1, basics.CreatableIndex(assetIdx), basics.AssetCreatable},
	})
	l, err := newLogicLedger(c, aidx)
	a.NoError(err)
	a.NotNil(l)

	_, ok, err := l.GetGlobal(basics.AppIndex(assetIdx), "gkey")
	a.Error(err)
	a.False(ok)
	a.Contains(err.Error(), fmt.Sprintf("app %d does not exist", assetIdx))

	tv := basics.TealValue{Type: basics.TealUintType, Uint: 1}
	c.stores = map[storeLocator]basics.TealKeyValue{{addr, aidx + 1, true}: {"gkey": tv}}
	val, ok, err := l.GetGlobal(aidx, "gkey")
	a.Error(err)
	a.False(ok)
	a.Contains(err.Error(), fmt.Sprintf("no store for (%s %d %v) in mock cow", addr, aidx, true))

	c.stores = map[storeLocator]basics.TealKeyValue{{addr, aidx, true}: {"gkey": tv}}
	val, ok, err = l.GetGlobal(aidx, "gkey")
	a.NoError(err)
	a.True(ok)
	a.Equal(tv, val)

	// check local
	c.stores = map[storeLocator]basics.TealKeyValue{{addr, aidx, false}: {"lkey": tv}}
	val, ok, err = l.GetLocal(addr, aidx, "lkey")
	a.NoError(err)
	a.True(ok)
	a.Equal(tv, val)
}

func TestLogicLedgerSetKey(t *testing.T) {
	a := require.New(t)

	addr := getRandomAddress(a)
	aidx := basics.AppIndex(1)
	c := newCowMock([]modsData{
		{addr, basics.CreatableIndex(aidx), basics.AppCreatable},
	})
	l, err := newLogicLedger(c, aidx)
	a.NoError(err)
	a.NotNil(l)

	tv := basics.TealValue{Type: basics.TealUintType, Uint: 1}
	err = l.SetGlobal("gkey", tv)
	a.Error(err)
	a.Contains(err.Error(), fmt.Sprintf("no store for (%s %d %v) in mock cow", addr, aidx, true))

	tv2 := basics.TealValue{Type: basics.TealUintType, Uint: 2}
	c.stores = map[storeLocator]basics.TealKeyValue{{addr, aidx, true}: {"gkey": tv}}
	err = l.SetGlobal("gkey", tv2)
	a.NoError(err)

	// check local
	c.stores = map[storeLocator]basics.TealKeyValue{{addr, aidx, false}: {"lkey": tv}}
	err = l.SetLocal(addr, "lkey", tv2)
	a.NoError(err)
}

func TestLogicLedgerDelKey(t *testing.T) {
	a := require.New(t)

	addr := getRandomAddress(a)
	aidx := basics.AppIndex(1)
	c := newCowMock([]modsData{
		{addr, basics.CreatableIndex(aidx), basics.AppCreatable},
	})
	l, err := newLogicLedger(c, aidx)
	a.NoError(err)
	a.NotNil(l)

	err = l.DelGlobal("gkey")
	a.Error(err)
	a.Contains(err.Error(), fmt.Sprintf("no store for (%s %d %v) in mock cow", addr, aidx, true))

	tv := basics.TealValue{Type: basics.TealUintType, Uint: 1}
	c.stores = map[storeLocator]basics.TealKeyValue{{addr, aidx, true}: {"gkey": tv}}
	err = l.DelGlobal("gkey")
	a.NoError(err)

	addr1 := getRandomAddress(a)
	c.stores = map[storeLocator]basics.TealKeyValue{{addr1, aidx, false}: {"lkey": tv}}
	err = l.DelLocal(addr1, "lkey")
	a.NoError(err)
}

// test ensures that
// 1) app's GlobalState and local state's KeyValue are stored in the same way
// before and after application code refactoring
// 2) writing into empty (opted-in) local state's KeyValue works after reloading
// Hardcoded values are from commit 9a0b439 (pre app refactor commit)
func TestAppAccountDataStorage(t *testing.T) {
	a := require.New(t)
	source := `#pragma version 2
// do not write local key on opt in or on app create
txn ApplicationID
int 0
==
bnz success
txn OnCompletion
int NoOp
==
bnz writetostate
txn OnCompletion
int OptIn
==
bnz checkargs
int 0
return
checkargs:
// if no args the success
// otherwise write data
txn NumAppArgs
int 0
==
bnz success
// write local or global key depending on arg1
writetostate:
txna ApplicationArgs 0
byte "local"
==
bnz writelocal
txna ApplicationArgs 0
byte "global"
==
bnz writeglobal
int 0
return
writelocal:
int 0
byte "lk"
byte "local"
app_local_put
b success
writeglobal:
byte "gk"
byte "global"
app_global_put
success:
int 1
return`

	ops, err := logic.AssembleString(source)
	a.NoError(err)
	a.Greater(len(ops.Program), 1)
	program := ops.Program

	proto := config.Consensus[protocol.ConsensusCurrentVersion]
	genesisInitState, initKeys := testGenerateInitState(t, protocol.ConsensusCurrentVersion)

	creator, err := basics.UnmarshalChecksumAddress("3LN5DBFC2UTPD265LQDP3LMTLGZCQ5M3JV7XTVTGRH5CKSVNQVDFPN6FG4")
	a.NoError(err)
	userOptin, err := basics.UnmarshalChecksumAddress("6S6UMUQ4462XRGNON5GKBHW55RUJGJ5INIRDFVFD6KSPHGWGRKPC6RK2O4")
	a.NoError(err)
	userLocal, err := basics.UnmarshalChecksumAddress("UL5C6SRVLOROSB5FGAE6TY34VXPXVR7GNIELUB3DD5KTA4VT6JGOZ6WFAY")
	a.NoError(err)
	userLocal2, err := basics.UnmarshalChecksumAddress("XNOGOJECWDOMVENCDJHNMOYVV7PIVIJXRWTSZUA3GSKYTVXH3VVGOXP7CU")
	a.NoError(err)

	a.Contains(genesisInitState.Accounts, creator)
	a.Contains(genesisInitState.Accounts, userOptin)
	a.Contains(genesisInitState.Accounts, userLocal)
	a.Contains(genesisInitState.Accounts, userLocal2)

	expectedCreator, err := hex.DecodeString("84a4616c676fce009d2290a461707070810184a6617070726f76c45602200200012604056c6f63616c06676c6f62616c026c6b02676b3118221240003331192212400010311923124000022243311b221240001c361a00281240000a361a0029124000092243222a28664200032b29672343a6636c65617270c40102a46773636881a36e627304a46c73636881a36e627301a36f6e6c01a47473636881a36e627304")
	a.NoError(err)
	expectedUserOptIn, err := hex.DecodeString("84a4616c676fce00a02fd0a46170706c810181a46873636881a36e627301a36f6e6c01a47473636881a36e627301")
	a.NoError(err)
	expectedUserLocal, err := hex.DecodeString("84a4616c676fce00a33540a46170706c810182a46873636881a36e627301a3746b7681a26c6b82a27462a56c6f63616ca2747401a36f6e6c01a47473636881a36e627301")
	a.NoError(err)

	cfg := config.GetDefaultLocal()
	l, err := OpenLedger(logging.Base(), "TestAppAccountData", true, genesisInitState, cfg)
	a.NoError(err)
	defer l.Close()

	txHeader := transactions.Header{
		Sender:      creator,
		Fee:         basics.MicroAlgos{Raw: proto.MinTxnFee * 2},
		FirstValid:  l.Latest() + 1,
		LastValid:   l.Latest() + 10,
		GenesisID:   t.Name(),
		GenesisHash: genesisInitState.GenesisHash,
	}

	// create application
	approvalProgram := program
	clearStateProgram := []byte("\x02") // empty
	appCreateFields := transactions.ApplicationCallTxnFields{
		ApprovalProgram:   approvalProgram,
		ClearStateProgram: clearStateProgram,
		GlobalStateSchema: basics.StateSchema{NumByteSlice: 4},
		LocalStateSchema:  basics.StateSchema{NumByteSlice: 1},
	}
	appCreate := transactions.Transaction{
		Type:                     protocol.ApplicationCallTx,
		Header:                   txHeader,
		ApplicationCallTxnFields: appCreateFields,
	}
	err = l.appendUnvalidatedTx(t, genesisInitState.Accounts, initKeys, appCreate, transactions.ApplyData{})
	a.NoError(err)

	appIdx := basics.AppIndex(1) // first tnx => idx = 1

	// opt-in, do no write
	txHeader.Sender = userOptin
	appCallFields := transactions.ApplicationCallTxnFields{
		OnCompletion:  transactions.OptInOC,
		ApplicationID: appIdx,
	}
	appCall := transactions.Transaction{
		Type:                     protocol.ApplicationCallTx,
		Header:                   txHeader,
		ApplicationCallTxnFields: appCallFields,
	}
	err = l.appendUnvalidatedTx(t, genesisInitState.Accounts, initKeys, appCall, transactions.ApplyData{})
	a.NoError(err)

	// opt-in + write
	txHeader.Sender = userLocal
	appCall = transactions.Transaction{
		Type:                     protocol.ApplicationCallTx,
		Header:                   txHeader,
		ApplicationCallTxnFields: appCallFields,
	}
	err = l.appendUnvalidatedTx(t, genesisInitState.Accounts, initKeys, appCall, transactions.ApplyData{})
	a.NoError(err)

	// save data into DB and write into local state
	l.accts.accountsWriting.Add(1)
	l.accts.commitRound(3, 0, 0)
	l.reloadLedger()

	appCallFields = transactions.ApplicationCallTxnFields{
		OnCompletion:    0,
		ApplicationID:   appIdx,
		ApplicationArgs: [][]byte{[]byte("local")},
	}
	appCall = transactions.Transaction{
		Type:                     protocol.ApplicationCallTx,
		Header:                   txHeader,
		ApplicationCallTxnFields: appCallFields,
	}
	err = l.appendUnvalidatedTx(t, genesisInitState.Accounts, initKeys, appCall,
		transactions.ApplyData{EvalDelta: basics.EvalDelta{
			LocalDeltas: map[uint64]basics.StateDelta{0: {"lk": basics.ValueDelta{Action: basics.SetBytesAction, Bytes: "local"}}}},
		})
	a.NoError(err)

	// save data into DB
	l.accts.accountsWriting.Add(1)
	l.accts.commitRound(1, 3, 0)
	l.reloadLedger()

	// dump accounts
	var rowid int64
	var dbRound basics.Round
	var buf []byte
	err = l.accts.accountsq.lookupStmt.QueryRow(creator[:]).Scan(&rowid, &dbRound, &buf)
	a.NoError(err)
	a.Equal(expectedCreator, buf)

	err = l.accts.accountsq.lookupStmt.QueryRow(userOptin[:]).Scan(&rowid, &dbRound, &buf)
	a.NoError(err)
	a.Equal(expectedUserOptIn, buf)
	pad, err := l.accts.accountsq.lookup(userOptin)
	a.Nil(pad.accountData.AppLocalStates[appIdx].KeyValue)
	ad, err := l.Lookup(dbRound, userOptin)
	a.Nil(ad.AppLocalStates[appIdx].KeyValue)

	err = l.accts.accountsq.lookupStmt.QueryRow(userLocal[:]).Scan(&rowid, &dbRound, &buf)
	a.NoError(err)
	a.Equal(expectedUserLocal, buf)

	ad, err = l.Lookup(dbRound, userLocal)
	a.NoError(err)
	a.Equal("local", ad.AppLocalStates[appIdx].KeyValue["lk"].Bytes)

	// ensure writing into empty global state works as well
	l.reloadLedger()
	txHeader.Sender = creator
	appCallFields = transactions.ApplicationCallTxnFields{
		OnCompletion:    0,
		ApplicationID:   appIdx,
		ApplicationArgs: [][]byte{[]byte("global")},
	}
	appCall = transactions.Transaction{
		Type:                     protocol.ApplicationCallTx,
		Header:                   txHeader,
		ApplicationCallTxnFields: appCallFields,
	}
	err = l.appendUnvalidatedTx(t, genesisInitState.Accounts, initKeys, appCall,
		transactions.ApplyData{EvalDelta: basics.EvalDelta{
			GlobalDelta: basics.StateDelta{"gk": basics.ValueDelta{Action: basics.SetBytesAction, Bytes: "global"}}},
		})
	a.NoError(err)

	// opt-in + write by during opt-in
	txHeader.Sender = userLocal2
	appCallFields = transactions.ApplicationCallTxnFields{
		OnCompletion:    transactions.OptInOC,
		ApplicationID:   appIdx,
		ApplicationArgs: [][]byte{[]byte("local")},
	}
	appCall = transactions.Transaction{
		Type:                     protocol.ApplicationCallTx,
		Header:                   txHeader,
		ApplicationCallTxnFields: appCallFields,
	}
	err = l.appendUnvalidatedTx(t, genesisInitState.Accounts, initKeys, appCall,
		transactions.ApplyData{EvalDelta: basics.EvalDelta{
			LocalDeltas: map[uint64]basics.StateDelta{0: {"lk": basics.ValueDelta{Action: basics.SetBytesAction, Bytes: "local"}}}},
		})
	a.NoError(err)
}
