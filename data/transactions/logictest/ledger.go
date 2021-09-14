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

// Ledger is a convenient mock ledger that is used by
// data/transactions/logic It is in its own package so that it can be
// used by people developing teal code that need a fast testing setup,
// rather than running against a real network.  It also might be
// expanded to support the Balances interface so that we have fewer
// mocks doing similar things.  By putting it here, it is publicly
// exported, but will not be imported by non-test code, so won't bloat
// binary.
type Ledger struct {
	balances          map[basics.Address]balanceRecord
	applications      map[basics.AppIndex]appParams
	assets            map[basics.AssetIndex]asaParams
	trackedCreatables map[int]basics.CreatableIndex
	appID             basics.AppIndex
	mods              map[basics.AppIndex]map[string]basics.ValueDelta
	rnd               basics.Round
}

// MakeLedger constructs a Ledger with the given balances.
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

// Reset removes all of the mods created by previous AVM execution
func (l *Ledger) Reset() {
	l.mods = make(map[basics.AppIndex]map[string]basics.ValueDelta)
	for addr, br := range l.balances {
		br.mods = make(map[basics.AppIndex]map[string]basics.ValueDelta)
		l.balances[addr] = br
	}
}

// NewAccount adds a new account with a given balance to the Ledger.
func (l *Ledger) NewAccount(addr basics.Address, balance uint64) {
	l.balances[addr] = makeBalanceRecord(addr, balance)
}

// NewApp add a new AVM app to the Ledger, and arranges so that future
// executions will act as though they are that app.  It only sets up
// the id and schema, it inserts no code, since testing will want to
// try many different code sequences.
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

// NewAsset adds an asset with the given id and params to the ledger.
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

// freshID gets a new creatable ID that isn't in use
func (l *Ledger) freshID() uint64 {
	for try := l.appID + 1; true; try++ {
		if _, ok := l.assets[basics.AssetIndex(try)]; ok {
			continue
		}
		if _, ok := l.applications[basics.AppIndex(try)]; ok {
			continue
		}
		return uint64(try)
	}
	panic("wow")
}

// NewHolding sets the ASA balance of a given account.
func (l *Ledger) NewHolding(addr basics.Address, assetID uint64, amount uint64, frozen bool) {
	br, ok := l.balances[addr]
	if !ok {
		br = makeBalanceRecord(addr, 0)
	}
	br.holdings[basics.AssetIndex(assetID)] = basics.AssetHolding{Amount: amount, Frozen: frozen}
	l.balances[addr] = br
}

// NewLocals essentially "opts in" an address to an app id.
func (l *Ledger) NewLocals(addr basics.Address, appID uint64) {
	l.balances[addr].locals[basics.AppIndex(appID)] = basics.TealKeyValue{}
}

// NewLocal sets a local value of an app on an address
func (l *Ledger) NewLocal(addr basics.Address, appID uint64, key string, value basics.TealValue) {
	l.balances[addr].locals[basics.AppIndex(appID)][key] = value
}

// NoLocal removes a key from an address locals for an app.
func (l *Ledger) NoLocal(addr basics.Address, appID uint64, key string) {
	delete(l.balances[addr].locals[basics.AppIndex(appID)], key)
}

// NewGlobal sets a global value for an app
func (l *Ledger) NewGlobal(appID uint64, key string, value basics.TealValue) {
	l.applications[basics.AppIndex(appID)].GlobalState[key] = value
}

// NoGlobal removes a global key for an app
func (l *Ledger) NoGlobal(appID uint64, key string) {
	delete(l.applications[basics.AppIndex(appID)].GlobalState, key)
}

// Rekey sets the authAddr for an address.
func (l *Ledger) Rekey(addr basics.Address, auth basics.Address) {
	if br, ok := l.balances[addr]; ok {
		br.auth = auth
		l.balances[addr] = br
	}
}

// Round gives the current Round of the test ledger, which is random but consistent
func (l *Ledger) Round() basics.Round {
	return l.round()
}

// LatestTimestamp gives a uint64, chosen randomly.  It should
// probably increase monotonically, but no tests care yet.
func (l *Ledger) LatestTimestamp() int64 {
	return int64(rand.Uint32() + 1)
}

// Balance returns the value in an account, as MicroAlgos
func (l *Ledger) Balance(addr basics.Address) (amount basics.MicroAlgos, err error) {
	br, ok := l.balances[addr]
	if !ok {
		return basics.MicroAlgos{Raw: 0}, nil
	}
	return basics.MicroAlgos{Raw: br.balance}, nil
}

// MinBalance computes the MinBalance requirement for an account,
// under the given consensus parameters.
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

// Authorizer returns the address that must authorize txns from a
// given address.  It's either the address itself, or the value it has
// been rekeyed to.
func (l *Ledger) Authorizer(addr basics.Address) (basics.Address, error) {
	br, ok := l.balances[addr]
	if !ok {
		return addr, nil // Not rekeyed if not present
	}
	if !br.auth.IsZero() {
		return br.auth, nil
	}
	return br.addr, nil
}

// GetGlobal returns the current value of a global in an app, taking
// into account the mods created by earlier teal execution.
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

// SetGlobal "sets" a global, but only through the mods mechanism, so
// it can be removed with Reset()
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

// DelGlobal "deletes" a global, but only through the mods mechanism, so
// the deletion can be Reset()
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

// GetLocal returns the current value bound to a local key, taking
// into account mods caused by earlier executions.
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

// SetLocal "sets" the current value bound to a local key using the
// mods mechanism, so it can be Reset()
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

// DelLocal "deletes" the current value bound to a local key using the
// mods mechanism, so it can be Reset()
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

// OptedIn returns whether an Address has opted into the app (usually
// from NewLocals, but potentially from executing AVM inner
// transactions.
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

// SetTrackedCreatable remembers that the given cl "happened" in txn
// groupIdx of the group, for use by GetCreatableID.
func (l *Ledger) SetTrackedCreatable(groupIdx int, cl basics.CreatableLocator) {
	l.trackedCreatables[groupIdx] = cl.Index
}

// GetCreatableID returns the creatable constructed in a given transaction
// slot. For the test ledger, that's been set up by SetTrackedCreatable
func (l *Ledger) GetCreatableID(groupIdx int) basics.CreatableIndex {
	return l.trackedCreatables[groupIdx]
}

// AssetHolding gives the amount of an ASA held by an account, or
// error if the account is not opted into the asset.
func (l *Ledger) AssetHolding(addr basics.Address, assetID basics.AssetIndex) (basics.AssetHolding, error) {
	if br, ok := l.balances[addr]; ok {
		if asset, ok := br.holdings[assetID]; ok {
			return asset, nil
		}
		return basics.AssetHolding{}, fmt.Errorf("No asset for account")
	}
	return basics.AssetHolding{}, fmt.Errorf("no such address")
}

// AssetParams gives the parameters of an ASA if it exists
func (l *Ledger) AssetParams(assetID basics.AssetIndex) (basics.AssetParams, basics.Address, error) {
	if asset, ok := l.assets[assetID]; ok {
		return asset.AssetParams, asset.Creator, nil
	}
	return basics.AssetParams{}, basics.Address{}, fmt.Errorf("no such asset")
}

// AppParams gives the parameters of an App if it exists
func (l *Ledger) AppParams(appID basics.AppIndex) (basics.AppParams, basics.Address, error) {
	if app, ok := l.applications[appID]; ok {
		return app.AppParams, app.Creator, nil
	}
	return basics.AppParams{}, basics.Address{}, fmt.Errorf("no such app")
}

// ApplicationID gives ID of the "currently running" app.  For this
// test ledger, that is chosen explicitly.
func (l *Ledger) ApplicationID() basics.AppIndex {
	return l.appID
}

// CreatorAddress returns of the address that created the "currently running" app.
func (l *Ledger) CreatorAddress() basics.Address {
	_, addr, _ := l.AppParams(l.appID)
	return addr
}

// GetDelta translates the mods set by AVM execution into the standard
// format of an EvalDelta.
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
			return fmt.Errorf("unable to close, Sender (%s) has holdings", from)
		}
		if len(sbr.locals) > 0 {
			return fmt.Errorf("unable to close, Sender (%s) is opted in to apps", from)
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

func (l *Ledger) acfg(from basics.Address, cfg transactions.AssetConfigTxnFields) (transactions.ApplyData, error) {
	if cfg.ConfigAsset == 0 {
		aid := basics.AssetIndex(l.freshID())
		l.NewAsset(from, aid, cfg.AssetParams)
		return transactions.ApplyData{ConfigAsset: aid}, nil
	}
	// This is just a mock.  We don't check all the rules about
	// not setting fields that have been zeroed. Nor do we keep
	// anything from before.
	l.assets[cfg.ConfigAsset] = asaParams{
		Creator:     from,
		AssetParams: cfg.AssetParams,
	}
	return transactions.ApplyData{}, nil
}

func (l *Ledger) afrz(from basics.Address, frz transactions.AssetFreezeTxnFields) error {
	aid := frz.FreezeAsset
	params, ok := l.assets[aid]
	if !ok {
		return fmt.Errorf("Asset (%d) does not exist", aid)
	}
	if params.Freeze != from {
		return fmt.Errorf("Asset (%d) can not be frozen by %s", aid, from)
	}
	br, ok := l.balances[frz.FreezeAccount]
	if !ok {
		return fmt.Errorf("%s does not hold anything", from)
	}
	holding, ok := br.holdings[aid]
	if !ok {
		return fmt.Errorf("%s does not hold Asset (%d)", from, aid)
	}
	holding.Frozen = frz.AssetFrozen
	br.holdings[aid] = holding
	return nil
}

/* It's gross to reimplement this here, rather than have a way to use
   a ledger that's backed by our mock, but uses the "real" code
   (cowRoundState which implements Balances), as a better test. To
   allow that, we need to move our mocks into separate packages so
   they can be combined in yet *another* package, and avoid circular
   imports.

   This is currently unable to fill the ApplyData objects.  That would
   require a whole new level of code duplication.
*/

// Perform causes txn to "occur" against the ledger. The returned ad is empty.
func (l *Ledger) Perform(txn *transactions.Transaction, spec transactions.SpecialAddresses) (transactions.ApplyData, error) {
	var ad transactions.ApplyData

	err := l.move(txn.Sender, spec.FeeSink, txn.Fee.Raw)
	if err != nil {
		return ad, err
	}
	switch txn.Type {
	case protocol.PaymentTx:
		err = l.pay(txn.Sender, txn.PaymentTxnFields)
	case protocol.AssetTransferTx:
		err = l.axfer(txn.Sender, txn.AssetTransferTxnFields)
	case protocol.AssetConfigTx:
		ad, err = l.acfg(txn.Sender, txn.AssetConfigTxnFields)
	case protocol.AssetFreezeTx:
		err = l.afrz(txn.Sender, txn.AssetFreezeTxnFields)
	default:
		err = fmt.Errorf("%s txn in AVM", txn.Type)
	}
	return ad, err
}

// Get() through allocated() implement cowForLogicLedger, so we should
// be able to make logicLedger with this inside.  That let's us to
// write tests and then poke around and see how the balance table
// inside is affected.

// Get returns the AccountData of an address. This test ledger does
// not handle rewards, so the pening rewards flag is ignored.
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

// GetCreator returns the creator of the given creatable, an app or asa.
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

// SetKey creates a new key-value in {addr, aidx, global} storage
func (l *Ledger) SetKey(addr basics.Address, aidx basics.AppIndex, global bool, key string, value basics.TealValue, accountIdx uint64) error {
	if global {
		l.NewGlobal(uint64(aidx), key, value)
	} else {
		l.NewLocal(addr, uint64(aidx), key, value)
	}
	return nil
}

// DelKey removes a key from {addr, aidx, global} storage
func (l *Ledger) DelKey(addr basics.Address, aidx basics.AppIndex, global bool, key string, accountIdx uint64) error {
	if global {
		l.NoGlobal(uint64(aidx), key)
	} else {
		l.NoLocal(addr, uint64(aidx), key)
	}
	return nil
}

func (l *Ledger) round() basics.Round {
	if l.rnd == basics.Round(0) {
		l.rnd = basics.Round(rand.Uint32() + 1)
	}
	return l.rnd
}
