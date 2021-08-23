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

package logictest

import (
	"fmt"
	"math/rand"

	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/transactions"
	"github.com/algorand/go-algorand/protocol"
)

type balanceRecord struct {
	addr     basics.Address
	auth     basics.Address
	balance  uint64
	locals   map[basics.AppIndex]basics.TealKeyValue
	holdings map[basics.AssetIndex]basics.AssetHolding
	mods     map[basics.AppIndex]map[string]basics.ValueDelta
}

func makeBalanceRecord(addr basics.Address, balance uint64) balanceRecord {
	br := balanceRecord{
		addr:     addr,
		balance:  balance,
		locals:   make(map[basics.AppIndex]basics.TealKeyValue),
		holdings: make(map[basics.AssetIndex]basics.AssetHolding),
		mods:     make(map[basics.AppIndex]map[string]basics.ValueDelta),
	}
	return br
}

// In our test ledger, we don't store the creatables with their
// creators, so we need to carry the creator around with them.
type appParams struct {
	basics.AppParams
	Creator basics.Address
}

type asaParams struct {
	basics.AssetParams
	Creator basics.Address
}

// Ledger is a convenient mock ledger that is used by both
// data/transactions/logid and ledger/apply.  It can act as any of:
// LogicForLedger, mockCowForLogicLedger, or (eventually) Balances,
// making it a nice basis for many tests.
// By putting it here, it is publicly exported, but will not be
// imported by non-test code, so won't bloat binary.
type Ledger struct {
	balances          map[basics.Address]balanceRecord
	applications      map[basics.AppIndex]appParams
	assets            map[basics.AssetIndex]asaParams
	trackedCreatables map[int]basics.CreatableIndex
	appID             basics.AppIndex
	mods              map[basics.AppIndex]map[string]basics.ValueDelta
	rnd               basics.Round
	Logs              []transactions.LogItem // public because write-only in TEAL, tests need direct access
}

func MakeLedger(balances map[basics.Address]uint64) *Ledger {
	l := new(Ledger)
	l.balances = make(map[basics.Address]balanceRecord)
	for addr, balance := range balances {
		l.NewAccount(addr, balance)
	}
	l.applications = make(map[basics.AppIndex]appParams)
	l.assets = make(map[basics.AssetIndex]asaParams)
	l.trackedCreatables = make(map[int]basics.CreatableIndex)
	l.mods = make(map[basics.AppIndex]map[string]basics.ValueDelta)
	return l
}

func (l *Ledger) Reset() {
	l.mods = make(map[basics.AppIndex]map[string]basics.ValueDelta)
	for addr, br := range l.balances {
		br.mods = make(map[basics.AppIndex]map[string]basics.ValueDelta)
		l.balances[addr] = br
	}
}

func (l *Ledger) NewAccount(addr basics.Address, balance uint64) {
	l.balances[addr] = makeBalanceRecord(addr, balance)
}

func (l *Ledger) NewApp(creator basics.Address, appID basics.AppIndex, params basics.AppParams) {
	l.appID = appID
	params = params.Clone()
	if params.GlobalState == nil {
		params.GlobalState = make(basics.TealKeyValue)
	}
	l.applications[appID] = appParams{
		Creator:   creator,
		AppParams: params.Clone(),
	}
	br, ok := l.balances[creator]
	if !ok {
		br = makeBalanceRecord(creator, 0)
	}
	br.locals[appID] = make(map[string]basics.TealValue)
	l.balances[creator] = br
}

func (l *Ledger) NewAsset(creator basics.Address, assetID basics.AssetIndex, params basics.AssetParams) {
	l.assets[assetID] = asaParams{
		Creator:     creator,
		AssetParams: params,
	}
	br, ok := l.balances[creator]
	if !ok {
		br = makeBalanceRecord(creator, 0)
	}
	br.holdings[assetID] = basics.AssetHolding{Amount: params.Total, Frozen: params.DefaultFrozen}
	l.balances[creator] = br
}

func (l *Ledger) NewHolding(addr basics.Address, assetID uint64, amount uint64, frozen bool) {
	br, ok := l.balances[addr]
	if !ok {
		br = makeBalanceRecord(addr, 0)
	}
	br.holdings[basics.AssetIndex(assetID)] = basics.AssetHolding{Amount: amount, Frozen: frozen}
	l.balances[addr] = br
}

func (l *Ledger) NewLocals(addr basics.Address, appID uint64) {
	l.balances[addr].locals[basics.AppIndex(appID)] = basics.TealKeyValue{}
}

func (l *Ledger) NewLocal(addr basics.Address, appID uint64, key string, value basics.TealValue) {
	l.balances[addr].locals[basics.AppIndex(appID)][key] = value
}

func (l *Ledger) NoLocal(addr basics.Address, appID uint64, key string) {
	delete(l.balances[addr].locals[basics.AppIndex(appID)], key)
}

func (l *Ledger) NewGlobal(appID uint64, key string, value basics.TealValue) {
	l.applications[basics.AppIndex(appID)].GlobalState[key] = value
}

func (l *Ledger) NoGlobal(appID uint64, key string) {
	delete(l.applications[basics.AppIndex(appID)].GlobalState, key)
}

func (l *Ledger) Rekey(addr basics.Address, auth basics.Address) {
	if br, ok := l.balances[addr]; ok {
		br.auth = auth
		l.balances[addr] = br
	}
}

func (l *Ledger) Round() basics.Round {
	return l.round()
}

func (l *Ledger) LatestTimestamp() int64 {
	return int64(rand.Uint32() + 1)
}

func (l *Ledger) Balance(addr basics.Address) (amount basics.MicroAlgos, err error) {
	br, ok := l.balances[addr]
	if !ok {
		return basics.MicroAlgos{Raw: 0}, nil
	}
	return basics.MicroAlgos{Raw: br.balance}, nil
}

func (l *Ledger) MinBalance(addr basics.Address, proto *config.ConsensusParams) (amount basics.MicroAlgos, err error) {
	br, ok := l.balances[addr]
	if !ok {
		br = makeBalanceRecord(addr, 0)
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

func (l *Ledger) Authorizer(addr basics.Address) basics.Address {
	br, ok := l.balances[addr]
	if !ok {
		return addr // Not rekeyed if not present
	}
	if !br.auth.IsZero() {
		return br.auth
	}
	return br.addr
}

func (l *Ledger) GetGlobal(appIdx basics.AppIndex, key string) (basics.TealValue, bool, error) {
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

func (l *Ledger) SetGlobal(key string, value basics.TealValue) error {
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

func (l *Ledger) DelGlobal(key string) error {
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

func (l *Ledger) BalanceRecord(addr basics.Address) (balanceRecord, bool) {
	br, ok := l.balances[addr]
	return br, ok
}

func (l *Ledger) GetLocal(addr basics.Address, appIdx basics.AppIndex, key string, accountIdx uint64) (basics.TealValue, bool, error) {
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

func (l *Ledger) SetLocal(addr basics.Address, key string, value basics.TealValue, accountIdx uint64) error {
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

func (l *Ledger) DelLocal(addr basics.Address, key string, accountIdx uint64) error {
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

func (l *Ledger) OptedIn(addr basics.Address, appIdx basics.AppIndex) (bool, error) {
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

func (l *Ledger) SetTrackedCreatable(groupIdx int, cl basics.CreatableLocator) {
	l.trackedCreatables[groupIdx] = cl.Index
}

func (l *Ledger) GetCreatableID(groupIdx int) basics.CreatableIndex {
	return l.trackedCreatables[groupIdx]
}

func (l *Ledger) AssetHolding(addr basics.Address, assetID basics.AssetIndex) (basics.AssetHolding, error) {
	if br, ok := l.balances[addr]; ok {
		if asset, ok := br.holdings[assetID]; ok {
			return asset, nil
		}
		return basics.AssetHolding{}, fmt.Errorf("No asset for account")
	}
	return basics.AssetHolding{}, fmt.Errorf("no such address")
}

func (l *Ledger) AssetParams(assetID basics.AssetIndex) (basics.AssetParams, basics.Address, error) {
	if asset, ok := l.assets[assetID]; ok {
		return asset.AssetParams, asset.Creator, nil
	}
	return basics.AssetParams{}, basics.Address{}, fmt.Errorf("no such asset")
}

func (l *Ledger) AppParams(appID basics.AppIndex) (basics.AppParams, basics.Address, error) {
	if app, ok := l.applications[appID]; ok {
		return app.AppParams, app.Creator, nil
	}
	return basics.AppParams{}, basics.Address{}, fmt.Errorf("no such app")
}

func (l *Ledger) ApplicationID() basics.AppIndex {
	return l.appID
}

func (l *Ledger) CreatorAddress() basics.Address {
	_, addr, _ := l.AppParams(l.appID)
	return addr
}

func (l *Ledger) GetDelta(txn *transactions.Transaction) (evalDelta transactions.EvalDelta, err error) {
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
	evalDelta.Logs = l.Logs
	return
}

func (l *Ledger) move(from basics.Address, to basics.Address, amount uint64) error {
	fbr, ok := l.balances[from]
	if !ok {
		fbr = makeBalanceRecord(from, 0)
	}
	tbr, ok := l.balances[to]
	if !ok {
		tbr = makeBalanceRecord(to, 0)
	}
	if fbr.balance < amount {
		return fmt.Errorf("insufficient balance")
	}
	fbr.balance -= amount
	tbr.balance += amount
	// We do not check min balances yet. They are checked when txn is complete.
	l.balances[from] = fbr
	l.balances[to] = tbr
	return nil
}

func (l *Ledger) pay(from basics.Address, pay transactions.PaymentTxnFields) error {
	err := l.move(from, pay.Receiver, pay.Amount.Raw)
	if err != nil {
		return err
	}
	if !pay.CloseRemainderTo.IsZero() {
		sbr := l.balances[from]
		if len(sbr.holdings) > 0 {
			return fmt.Errorf("Sender (%s) has holdings.", from)
		}
		if len(sbr.locals) > 0 {
			return fmt.Errorf("Sender (%s) is opted in to apps.", from)
		}
		// Should also check app creations.
		// Need not check asa creations, as you can't opt out if you created.
		// (though this test ledger doesn't know that)
		remainder := sbr.balance
		if remainder > 0 {
			return l.move(from, pay.CloseRemainderTo, remainder)
		}
	}
	return nil
}

func (l *Ledger) axfer(from basics.Address, xfer transactions.AssetTransferTxnFields) error {
	to := xfer.AssetReceiver
	aid := xfer.XferAsset
	amount := xfer.AssetAmount
	close := xfer.AssetCloseTo

	fbr, ok := l.balances[from]
	if !ok {
		fbr = makeBalanceRecord(from, 0)
	}
	fholding, ok := fbr.holdings[aid]
	if !ok {
		if from == to && amount == 0 {
			// opt in
			if params, exists := l.assets[aid]; exists {
				fbr.holdings[aid] = basics.AssetHolding{
					Frozen: params.DefaultFrozen,
				}
				return nil
			}
			return fmt.Errorf("Asset (%d) does not exist", aid)
		}
		return fmt.Errorf("Sender (%s) not opted in to %d", from, aid)
	}
	if fholding.Frozen {
		return fmt.Errorf("Sender (%s) is frozen for %d", from, aid)
	}
	tbr, ok := l.balances[to]
	if !ok {
		tbr = makeBalanceRecord(to, 0)
	}
	tholding, ok := tbr.holdings[aid]
	if !ok && amount > 0 {
		return fmt.Errorf("AssetReceiver (%s) not opted in to %d", to, aid)
	}
	if fholding.Amount < amount {
		return fmt.Errorf("insufficient balance")
	}

	// Not just an optimization.
	//   amount >0 : allows axfer to not opted in account
	//   from != to : prevents overwriting the same balance record with only
	//                the second change, and ensures fholding remains correct
	//                for closeTo handling.
	if amount > 0 && from != to {
		fholding.Amount -= amount
		fbr.holdings[aid] = fholding
		l.balances[from] = fbr

		tholding.Amount += amount
		tbr.holdings[aid] = tholding
		l.balances[to] = tbr
	}

	if !close.IsZero() && fholding.Amount > 0 {
		cbr, ok := l.balances[close]
		if !ok {
			cbr = makeBalanceRecord(close, 0)
		}
		cholding, ok := cbr.holdings[aid]
		if !ok {
			return fmt.Errorf("AssetCloseTo (%s) not opted in to %d", to, aid)
		}

		// Opt out
		delete(fbr.holdings, aid)
		l.balances[from] = fbr

		cholding.Amount += fholding.Amount
		cbr.holdings[aid] = cholding
		l.balances[close] = cbr
	}

	return nil
}

/* It's gross to reimplement this here, rather than have a way to use
   a ledger that's backed by our mock, but uses the "real" code
   (cowRoundState which implements Balances), as a better test. To
   allow that, we need to move our mocks into separate packages so
   they can be combined in yet *another* package, and avoid circular
   imports. */

func (l *Ledger) Perform(txn *transactions.Transaction, spec transactions.SpecialAddresses) error {
	err := l.move(txn.Sender, spec.FeeSink, txn.Fee.Raw)
	if err != nil {
		return err
	}
	switch txn.Type {
	case protocol.PaymentTx:
		err = l.pay(txn.Sender, txn.PaymentTxnFields)
	case protocol.AssetTransferTx:
		err = l.axfer(txn.Sender, txn.AssetTransferTxnFields)
	default:
		err = fmt.Errorf("%s txn in AVM", txn.Type)
	}
	return err
}

// Get() through allocated() implement cowForLogicLedger, we can make
// a logicLedger with this inside.  That let's us to write tests and
// then poke around and see how the balance table inside is affected.

func (l *Ledger) Get(addr basics.Address, withPendingRewards bool) (basics.AccountData, error) {
	br, ok := l.balances[addr]
	if !ok {
		return basics.AccountData{}, fmt.Errorf("addr %s not in test.Ledger", addr.String())
	}
	return basics.AccountData{
		MicroAlgos:     basics.MicroAlgos{Raw: br.balance},
		AssetParams:    map[basics.AssetIndex]basics.AssetParams{},
		Assets:         map[basics.AssetIndex]basics.AssetHolding{},
		AppLocalStates: map[basics.AppIndex]basics.AppLocalState{},
		AppParams:      map[basics.AppIndex]basics.AppParams{},
	}, nil
}

// GetCreatableID was done for LedgerForLogic
// func (l *Ledger) GetCreatableID(groupIdx int) basics.CreatableIndex { }
func (l *Ledger) GetCreator(cidx basics.CreatableIndex, ctype basics.CreatableType) (basics.Address, bool, error) {
	if ctype == basics.AssetCreatable {
		params, found := l.assets[basics.AssetIndex(cidx)]
		return params.Creator, found, nil
	}
	if ctype == basics.AppCreatable {
		params, found := l.applications[basics.AppIndex(cidx)]
		return params.Creator, found, nil
	}
	return basics.Address{}, false, fmt.Errorf("%v %d is not in test.Ledger", ctype, cidx)
}

func (l *Ledger) SetKey(addr basics.Address, aidx basics.AppIndex, global bool, key string, value basics.TealValue, accountIdx uint64) error {
	if global {
		l.NewGlobal(uint64(aidx), key, value)
	} else {
		l.NewLocal(addr, uint64(aidx), key, value)
	}
	return nil
}
func (l *Ledger) DelKey(addr basics.Address, aidx basics.AppIndex, global bool, key string, accountIdx uint64) error {
	if global {
		l.NoGlobal(uint64(aidx), key)
	} else {
		l.NoLocal(addr, uint64(aidx), key)
	}
	return nil
}

func (l *Ledger) AppendLog(txn *transactions.Transaction, value string) error {

	appIdx, err := txn.IndexByAppID(l.appID)
	if err != nil {
		return err
	}
	_, ok := l.applications[l.appID]
	if !ok {
		return fmt.Errorf("no such app")
	}

	l.Logs = append(l.Logs, transactions.LogItem{ID: appIdx, Message: value})
	return nil
}

func (l *Ledger) round() basics.Round {
	if l.rnd == basics.Round(0) {
		l.rnd = basics.Round(rand.Uint32() + 1)
	}
	return l.rnd
}
