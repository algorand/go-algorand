// Copyright (C) 2019-2025 Algorand, Inc.
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

/* This Ledger implements LedgerForLogic for unit tests in the logic package. It
   does *not* carry the protocol around, so it does *not* enforce the various
   limits imposed there.  This helps ensure that the logic package itself
   enforces those limits, rather than rely on the ledger package. (Which should
   also do so, to be defensive.)

   This Ledger is not clever enough to have a good mechanism for making changes
   and rolling them back if the program that makes them fails. It just has a
   Reset() method that throws away all changes made by programs.  Generally,
   it's probably best to call Reset() after any error test, though you can keep
   testing if you take into account that changes made before the failure will
   take effect.
*/

import (
	"errors"
	"fmt"
	"math"
	"math/rand"

	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/bookkeeping"
	"github.com/algorand/go-algorand/data/committee"
	"github.com/algorand/go-algorand/data/transactions"
	"github.com/algorand/go-algorand/ledger/ledgercore"
	"github.com/algorand/go-algorand/protocol"
)

type balanceRecord struct {
	addr    basics.Address
	auth    basics.Address
	balance uint64
	voting  basics.VotingData

	proposed  basics.Round // The last round that this account proposed the accepted block
	heartbeat basics.Round // The last round that this account sent a heartbeat to show it was online.

	locals   map[basics.AppIndex]basics.TealKeyValue
	holdings map[basics.AssetIndex]basics.AssetHolding
	mods     map[basics.AppIndex]map[string]basics.ValueDelta
}

func newBalanceRecord(addr basics.Address, balance uint64) balanceRecord {
	return balanceRecord{
		addr:     addr,
		balance:  balance,
		locals:   make(map[basics.AppIndex]basics.TealKeyValue),
		holdings: make(map[basics.AssetIndex]basics.AssetHolding),
		mods:     make(map[basics.AppIndex]map[string]basics.ValueDelta),
	}
}

// In our test ledger, we don't store the creatables with their
// creators, so we need to carry the creator around with them.
type appParams struct {
	basics.AppParams
	Creator basics.Address

	boxes   map[string][]byte // will never contain a nil slice
	boxMods map[string][]byte // nil slice indicates a deletion
}

type asaParams struct {
	basics.AssetParams
	Creator basics.Address
}

// Ledger is a fake ledger that is "good enough" to reasonably test AVM programs.
type Ledger struct {
	balances     map[basics.Address]balanceRecord
	applications map[basics.AppIndex]appParams
	assets       map[basics.AssetIndex]asaParams
	mods         map[basics.AppIndex]map[string]basics.ValueDelta
	rnd          basics.Round
}

// NewLedger constructs a Ledger with the given balances.
func NewLedger(balances map[basics.Address]uint64) *Ledger {
	l := new(Ledger)
	l.balances = make(map[basics.Address]balanceRecord)
	for addr, balance := range balances {
		l.NewAccount(addr, balance)
	}
	l.applications = make(map[basics.AppIndex]appParams)
	l.assets = make(map[basics.AssetIndex]asaParams)
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
	for id, app := range l.applications {
		app.boxMods = nil
		l.applications[id] = app
	}
}

// NewAccount adds a new account with a given balance to the Ledger.
func (l *Ledger) NewAccount(addr basics.Address, balance uint64) {
	l.balances[addr] = newBalanceRecord(addr, balance)
}

// NewApp add a new AVM app to the Ledger.  In most uses, it only sets up the id
// and schema but no code, as testing will want to try many different code
// sequences.
func (l *Ledger) NewApp(creator basics.Address, appID basics.AppIndex, params basics.AppParams) {
	params = params.Clone()
	if params.GlobalState == nil {
		params.GlobalState = make(basics.TealKeyValue)
	}
	l.applications[appID] = appParams{
		Creator:   creator,
		AppParams: params,
	}
}

// NewAsset adds an asset with the given id and params to the ledger.
func (l *Ledger) NewAsset(creator basics.Address, assetID basics.AssetIndex, params basics.AssetParams) {
	l.assets[assetID] = asaParams{
		Creator:     creator,
		AssetParams: params,
	}
	br, ok := l.balances[creator]
	if !ok {
		br = newBalanceRecord(creator, 0)
	}
	br.holdings[assetID] = basics.AssetHolding{Amount: params.Total, Frozen: params.DefaultFrozen}
	l.balances[creator] = br
}

const firstTestID = 5000

// Counter implements LedgerForLogic, but it not really a txn counter, but is
// sufficient for the logic package.
func (l *Ledger) Counter() uint64 {
	for try := firstTestID; true; try++ {
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
func (l *Ledger) NewHolding(addr basics.Address, assetID basics.AssetIndex, amount uint64, frozen bool) {
	br, ok := l.balances[addr]
	if !ok {
		br = newBalanceRecord(addr, 0)
	}
	br.holdings[assetID] = basics.AssetHolding{Amount: amount, Frozen: frozen}
	l.balances[addr] = br
}

// NewLocals essentially "opts in" an address to an app id.
func (l *Ledger) NewLocals(addr basics.Address, appID basics.AppIndex) {
	if _, ok := l.balances[addr]; !ok {
		l.balances[addr] = newBalanceRecord(addr, 0)
	}
	l.balances[addr].locals[appID] = basics.TealKeyValue{}
}

// NewLocal sets a local value of an app on an address
func (l *Ledger) NewLocal(addr basics.Address, appID basics.AppIndex, key string, value basics.TealValue) {
	l.balances[addr].locals[appID][key] = value
}

// NoLocal removes a key from an address locals for an app.
func (l *Ledger) NoLocal(addr basics.Address, appID basics.AppIndex, key string) {
	delete(l.balances[addr].locals[appID], key)
}

// NewGlobal sets a global value for an app
func (l *Ledger) NewGlobal(appID basics.AppIndex, key string, value basics.TealValue) {
	l.applications[appID].GlobalState[key] = value
}

// NoGlobal removes a global key for an app
func (l *Ledger) NoGlobal(appID basics.AppIndex, key string) {
	delete(l.applications[appID].GlobalState, key)
}

// Rekey sets the authAddr for an address.
func (l *Ledger) Rekey(addr basics.Address, auth basics.Address) {
	if br, ok := l.balances[addr]; ok {
		br.auth = auth
		l.balances[addr] = br
	}
}

// LatestTimestamp gives a uint64, chosen randomly.  It should
// probably increase monotonically, but no tests care yet.
func (l *Ledger) PrevTimestamp() int64 {
	return int64(rand.Uint32() + 1)
}

// OnlineStake returns the online stake that applies to the latest round (so
// it's actually the online stake from 320 rounds ago)
func (l *Ledger) OnlineStake() (basics.MicroAlgos, error) {
	return basics.Algos(3333), nil
}

// BlockHdr returns the block header for the given round, if it is available
func (l *Ledger) BlockHdr(round basics.Round) (bookkeeping.BlockHeader, error) {
	hdr := bookkeeping.BlockHeader{}
	// Return a fake seed that is different for each round
	seed := committee.Seed{}
	seed[0] = byte(round)
	seed[1] = byte(round >> 8)
	seed[2] = byte(round >> 16)
	seed[3] = byte(round >> 24)
	seed[4] = byte(round >> 32)
	seed[5] = byte(round >> 40)
	seed[6] = byte(round >> 48)
	seed[7] = byte(round >> 56)
	hdr.Seed = seed
	hdr.TimeStamp = 100 + (9 * int64(round) / 2)
	return hdr, nil
	// perhaps should add an error when requesting old round for better testing
}

// AccountData returns a version of the account that is good enough for
// satisfying AVM needs. (balance, calc minbalance, and authaddr)
func (l *Ledger) AccountData(addr basics.Address) (ledgercore.AccountData, error) {
	br := l.balances[addr]
	// br may come back empty if addr doesn't exist.  That's fine for our needs.
	assets := make(map[basics.AssetIndex]basics.AssetParams)
	for a, p := range l.assets {
		if p.Creator == addr {
			assets[a] = p.AssetParams
		}
	}

	schemaTotal := basics.StateSchema{}
	pagesTotal := uint32(0)

	boxesTotal := 0
	boxBytesTotal := 0

	apps := make(map[basics.AppIndex]basics.AppParams)
	for a, p := range l.applications {
		if p.Creator == addr {
			apps[a] = p.AppParams
			schemaTotal = schemaTotal.AddSchema(p.GlobalStateSchema)
			pagesTotal += p.ExtraProgramPages
		}
		if a.Address() == addr {
			// We found the app that corresponds to this app account. Get box info from there.
			boxesTotal = len(p.boxes)
			for k, v := range p.boxes {
				boxBytesTotal += len(k) + len(v)
			}
			for k, v := range p.boxMods {
				base, ok := p.boxes[k]
				if ok {
					if v == nil {
						// deleted, so remove from totals
						boxesTotal--
						boxBytesTotal -= len(k) + len(base)
						continue
					}
					if len(v) != len(base) {
						panic(fmt.Sprintf("mismatch %v %v", v, base))
					}
					continue
				}
				// fresh box in mods, count it
				boxesTotal++
				boxBytesTotal += len(k) + len(v)
			}
		}
	}

	locals := map[basics.AppIndex]basics.AppLocalState{}
	for a := range br.locals {
		locals[a] = basics.AppLocalState{} // No need to fill in
		schemaTotal = schemaTotal.AddSchema(l.applications[a].LocalStateSchema)
	}

	return ledgercore.AccountData{
		AccountBaseData: ledgercore.AccountBaseData{
			MicroAlgos:          basics.MicroAlgos{Raw: br.balance},
			AuthAddr:            br.auth,
			TotalAppSchema:      schemaTotal,
			TotalExtraAppPages:  pagesTotal,
			TotalAppParams:      uint64(len(apps)),
			TotalAppLocalStates: uint64(len(locals)),
			TotalAssetParams:    uint64(len(assets)),
			TotalAssets:         uint64(len(br.holdings)),

			TotalBoxes:    uint64(boxesTotal),
			TotalBoxBytes: uint64(boxBytesTotal),

			LastProposed:  br.proposed,
			LastHeartbeat: br.heartbeat,
		},
		VotingData: br.voting,
	}, nil
}

// AgreementData is not a very high-fidelity fake. There's no time delay, it
// just returns the data that's in AccountData, reshaped into an
// OnlineAccountData.
func (l *Ledger) AgreementData(addr basics.Address) (basics.OnlineAccountData, error) {
	ad, err := l.AccountData(addr)
	if err != nil {
		return basics.OnlineAccountData{}, err
	}
	// You might imagine this conversion function exists. It does, but requires
	// rewards handling because OnlineAccountData should have rewards
	// paid. Here, we ignore that for simple tests.
	return basics.OnlineAccountData{
		MicroAlgosWithRewards: ad.MicroAlgos,
		// VotingData is not exposed to `voter_params_get`, the thinking is that
		// we don't want them used as "free" storage. And thus far, we don't
		// have compelling reasons to examine them in AVM.
		VotingData: basics.VotingData{
			VoteID:          ad.VoteID,
			SelectionID:     ad.SelectionID,
			StateProofID:    ad.StateProofID,
			VoteFirstValid:  ad.VoteFirstValid,
			VoteLastValid:   ad.VoteLastValid,
			VoteKeyDilution: ad.VoteKeyDilution,
		},
		IncentiveEligible: ad.IncentiveEligible,
	}, nil
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
	params, ok := l.applications[appIdx]
	if !ok {
		return basics.TealValue{}, false, fmt.Errorf("no app %d", appIdx)
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
func (l *Ledger) SetGlobal(appIdx basics.AppIndex, key string, value basics.TealValue) error {
	params, ok := l.applications[appIdx]
	if !ok {
		return fmt.Errorf("no app %d", appIdx)
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
func (l *Ledger) DelGlobal(appIdx basics.AppIndex, key string) error {
	params, ok := l.applications[appIdx]
	if !ok {
		return fmt.Errorf("no app %d", appIdx)
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

// NewBox makes a new box, through the boxMods mechanism. It can be Reset()
func (l *Ledger) NewBox(appIdx basics.AppIndex, key string, value []byte, appAddr basics.Address) error {
	if appIdx.Address() != appAddr {
		panic(fmt.Sprintf("%d %v %v", appIdx, appIdx.Address(), appAddr))
	}
	params, ok := l.applications[appIdx]
	if !ok {
		return fmt.Errorf("no app %d", appIdx)
	}
	if params.boxMods == nil {
		params.boxMods = make(map[string][]byte)
	}
	if current, ok := params.boxMods[key]; ok {
		if current != nil {
			return fmt.Errorf("attempt to recreate box %#v", key)
		}
	} else if _, ok := params.boxes[key]; ok {
		return fmt.Errorf("attempt to recreate box %#x", key)
	}
	params.boxMods[key] = value
	l.applications[appIdx] = params
	return nil
}

func (l *Ledger) GetBox(appIdx basics.AppIndex, key string) ([]byte, bool, error) {
	params, ok := l.applications[appIdx]
	if !ok {
		return nil, false, nil
	}
	if params.boxMods != nil {
		if ps, ok := params.boxMods[key]; ok {
			if ps == nil { // deletion in mod
				return nil, false, nil
			}
			return ps, true, nil
		}
	}
	if params.boxes == nil {
		return nil, false, nil
	}
	box, ok := params.boxes[key]
	return box, ok, nil
}

// SetBox set a box value through the boxMods mechanism. It can be Reset()
func (l *Ledger) SetBox(appIdx basics.AppIndex, key string, value []byte) error {
	current, ok, err := l.GetBox(appIdx, key)
	if err != nil {
		return err
	}
	if !ok {
		return fmt.Errorf("no box %d", appIdx)
	}
	params := l.applications[appIdx] // assured, based on above
	if params.boxMods == nil {
		params.boxMods = make(map[string][]byte)
	}
	if len(current) != len(value) {
		return fmt.Errorf("wrong box size %#v %d != %d", key, len(current), len(value))
	}
	params.boxMods[key] = value
	return nil
}

// DelBox deletes a value through boxMods mechanism
func (l *Ledger) DelBox(appIdx basics.AppIndex, key string, appAddr basics.Address) (bool, error) {
	if appIdx.Address() != appAddr {
		panic(fmt.Sprintf("%d %v %v", appIdx, appIdx.Address(), appAddr))
	}
	_, ok, err := l.GetBox(appIdx, key)
	if err != nil {
		return false, err
	}
	if !ok {
		return false, nil
	}
	params := l.applications[appIdx] // assured, based on above
	if params.boxMods == nil {
		params.boxMods = make(map[string][]byte)
	}
	params.boxMods[key] = nil
	return true, nil
}

// GetLocal returns the current value bound to a local key, taking
// into account mods caused by earlier executions.
func (l *Ledger) GetLocal(addr basics.Address, appIdx basics.AppIndex, key string, accountIdx uint64) (basics.TealValue, bool, error) {
	br, ok := l.balances[addr]
	if !ok {
		return basics.TealValue{}, false, fmt.Errorf("no account: %s", addr)
	}
	tkvd, ok := br.locals[appIdx]
	if !ok {
		return basics.TealValue{}, false, fmt.Errorf("account %s is not opted into %d", addr, appIdx)
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
func (l *Ledger) SetLocal(addr basics.Address, appIdx basics.AppIndex, key string, value basics.TealValue, accountIdx uint64) error {
	br, ok := l.balances[addr]
	if !ok {
		return fmt.Errorf("no account: %s", addr)
	}
	tkv, ok := br.locals[appIdx]
	if !ok {
		return fmt.Errorf("account %s is not opted into %d", addr, appIdx)
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
func (l *Ledger) DelLocal(addr basics.Address, appIdx basics.AppIndex, key string, accountIdx uint64) error {
	br, ok := l.balances[addr]
	if !ok {
		return fmt.Errorf("no account: %s", addr)
	}
	tkv, ok := br.locals[appIdx]
	if !ok {
		return fmt.Errorf("account %s is not opted into %d", addr, appIdx)
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
	br, ok := l.balances[addr]
	if !ok {
		return false, fmt.Errorf("no account: %s", addr)
	}
	_, ok = br.locals[appIdx]
	return ok, nil
}

// AssetHolding gives the amount of an ASA held by an account, or
// error if the account is not opted into the asset.
func (l *Ledger) AssetHolding(addr basics.Address, assetID basics.AssetIndex) (basics.AssetHolding, error) {
	if br, ok := l.balances[addr]; ok {
		if asset, ok := br.holdings[assetID]; ok {
			return asset, nil
		}
		return basics.AssetHolding{}, fmt.Errorf("no asset %d for account %s", assetID, addr)
	}
	return basics.AssetHolding{}, fmt.Errorf("no account: %s", addr)
}

// AssetParams gives the parameters of an ASA if it exists
func (l *Ledger) AssetParams(assetID basics.AssetIndex) (basics.AssetParams, basics.Address, error) {
	if asset, ok := l.assets[assetID]; ok {
		return asset.AssetParams, asset.Creator, nil
	}
	return basics.AssetParams{}, basics.Address{}, fmt.Errorf("no asset %d", assetID)
}

// AppParams gives the parameters of an App if it exists
func (l *Ledger) AppParams(appID basics.AppIndex) (basics.AppParams, basics.Address, error) {
	if app, ok := l.applications[appID]; ok {
		return app.AppParams, app.Creator, nil
	}
	return basics.AppParams{}, basics.Address{}, fmt.Errorf("no app %d", appID)
}

var testGenHash = crypto.Digest{0x03, 0x02, 0x03}

// GenesisHash returns a phony genesis hash that can be tested against
func (l *Ledger) GenesisHash() crypto.Digest {
	return testGenHash
}

func (l *Ledger) move(from basics.Address, to basics.Address, amount uint64) error {
	fbr, ok := l.balances[from]
	if !ok {
		fbr = newBalanceRecord(from, 0)
	}
	tbr, ok := l.balances[to]
	if !ok {
		tbr = newBalanceRecord(to, 0)
	}
	if fbr.balance < amount {
		return fmt.Errorf("insufficient balance in %v. %d < %d", from, fbr.balance, amount)
	}
	fbr.balance -= amount
	tbr.balance += amount
	// We do not check min balances yet. They are checked when txn is complete.
	l.balances[from] = fbr
	l.balances[to] = tbr
	return nil
}

func (l *Ledger) rekey(tx *transactions.Transaction) error {
	// rekeying: update br.auth to tx.RekeyTo if provided
	if (tx.RekeyTo != basics.Address{}) {
		br, ok := l.balances[tx.Sender]
		if !ok {
			return fmt.Errorf("no account")
		}
		if tx.RekeyTo == tx.Sender {
			br.auth = basics.Address{}
		} else {
			br.auth = tx.RekeyTo
		}
		l.balances[tx.Sender] = br
	}
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
		fbr = newBalanceRecord(from, 0)
	}
	fholding, ok := fbr.holdings[aid]
	if !ok {
		if amount == 0 {
			if from == to {
				// opt in
				if params, exists := l.assets[aid]; exists {
					fbr.holdings[aid] = basics.AssetHolding{
						Frozen: params.DefaultFrozen,
					}
				} else {
					return fmt.Errorf("Asset (%d) does not exist", aid)
				}
			}
		} else {
			return fmt.Errorf("Sender (%s) not opted in to %d", from, aid)
		}
	}
	if fholding.Frozen {
		return fmt.Errorf("Sender (%s) is frozen for %d", from, aid)
	}
	tbr, ok := l.balances[to]
	if !ok {
		tbr = newBalanceRecord(to, 0)
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
			cbr = newBalanceRecord(close, 0)
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

func (l *Ledger) acfg(from basics.Address, cfg transactions.AssetConfigTxnFields, ad *transactions.ApplyData) error {
	if cfg.ConfigAsset == 0 {
		aid := basics.AssetIndex(l.Counter())
		l.NewAsset(from, aid, cfg.AssetParams)
		ad.ConfigAsset = aid
		return nil
	}
	// This is just a mock.  We don't check all the rules about
	// not setting fields that have been zeroed. Nor do we keep
	// anything from before.
	l.assets[cfg.ConfigAsset] = asaParams{
		Creator:     from,
		AssetParams: cfg.AssetParams,
	}
	return nil
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
		return fmt.Errorf("%s does not hold Asset (%d)", frz.FreezeAccount, aid)
	}
	holding, ok := br.holdings[aid]
	if !ok {
		return fmt.Errorf("%s does not hold Asset (%d)", frz.FreezeAccount, aid)
	}
	holding.Frozen = frz.AssetFrozen
	br.holdings[aid] = holding
	return nil
}

func (l *Ledger) appl(from basics.Address, appl transactions.ApplicationCallTxnFields, ad *transactions.ApplyData, gi int, ep *EvalParams) error {
	aid := appl.ApplicationID
	if aid == 0 {
		aid = basics.AppIndex(l.Counter())
		params := basics.AppParams{
			ApprovalProgram:   appl.ApprovalProgram,
			ClearStateProgram: appl.ClearStateProgram,
			GlobalState:       map[string]basics.TealValue{},
			StateSchemas: basics.StateSchemas{
				LocalStateSchema: basics.StateSchema{
					NumUint:      appl.LocalStateSchema.NumUint,
					NumByteSlice: appl.LocalStateSchema.NumByteSlice,
				},
				GlobalStateSchema: basics.StateSchema{
					NumUint:      appl.GlobalStateSchema.NumUint,
					NumByteSlice: appl.GlobalStateSchema.NumByteSlice,
				},
			},
			ExtraProgramPages: appl.ExtraProgramPages,
			Version:           0,
		}
		l.NewApp(from, aid, params)
		ad.ApplicationID = aid
	}

	if appl.OnCompletion == transactions.ClearStateOC {
		return errors.New("not implemented in test ledger")
	}

	if appl.OnCompletion == transactions.OptInOC {
		br, ok := l.balances[from]
		if !ok {
			return errors.New("no account")
		}
		br.locals[aid] = make(map[string]basics.TealValue)
	}

	// Execute the Approval program
	params, ok := l.applications[aid]
	if !ok {
		return errors.New("No application")
	}
	pass, cx, err := EvalContract(params.ApprovalProgram, gi, aid, ep)
	if err != nil {
		ad.EvalDelta = transactions.EvalDelta{}
		return err
	}
	if !pass {
		ad.EvalDelta = transactions.EvalDelta{}
		return errors.New("Approval program failed")
	}
	ad.EvalDelta = cx.txn.EvalDelta

	switch appl.OnCompletion {
	case transactions.NoOpOC:
	case transactions.OptInOC:
		// done earlier so locals could be changed
	case transactions.CloseOutOC:
		// get the local state, error if not exists, delete it
		br, ok := l.balances[from]
		if !ok {
			return errors.New("no account")
		}
		_, ok = br.locals[aid]
		if !ok {
			return errors.New("not opted in")
		}
		delete(br.locals, aid)
	case transactions.DeleteApplicationOC:
		// get the global object, delete it
		_, ok := l.applications[aid]
		if !ok {
			return errors.New("no app")
		}
		delete(l.applications, aid)
	case transactions.UpdateApplicationOC:
		app, ok := l.applications[aid]
		if !ok {
			return errors.New("no app")
		}
		app.ApprovalProgram = appl.ApprovalProgram
		app.ClearStateProgram = appl.ClearStateProgram
		app.Version++
		l.applications[aid] = app
	}
	return nil
}

// Perform causes txn to "occur" against the ledger.
func (l *Ledger) Perform(gi int, ep *EvalParams) error {
	txn := &ep.TxnGroup[gi]
	err := l.move(txn.Txn.Sender, ep.Specials.FeeSink, txn.Txn.Fee.Raw)
	if err != nil {
		return err
	}

	err = l.rekey(&txn.Txn)
	if err != nil {
		return err
	}

	switch txn.Txn.Type {
	case protocol.PaymentTx:
		return l.pay(txn.Txn.Sender, txn.Txn.PaymentTxnFields)
	case protocol.AssetTransferTx:
		return l.axfer(txn.Txn.Sender, txn.Txn.AssetTransferTxnFields)
	case protocol.AssetConfigTx:
		return l.acfg(txn.Txn.Sender, txn.Txn.AssetConfigTxnFields, &txn.ApplyData)
	case protocol.AssetFreezeTx:
		return l.afrz(txn.Txn.Sender, txn.Txn.AssetFreezeTxnFields)
	case protocol.ApplicationCallTx:
		return l.appl(txn.Txn.Sender, txn.Txn.ApplicationCallTxnFields, &txn.ApplyData, gi, ep)
	case protocol.KeyRegistrationTx:
		return nil // For now, presume success in test ledger
	default:
		return fmt.Errorf("%s txn in AVM", txn.Txn.Type)
	}
}

// Get returns the AccountData of an address. This test ledger does
// not handle rewards, so withPendingRewards is ignored.
func (l *Ledger) Get(addr basics.Address, withPendingRewards bool) (basics.AccountData, error) {
	br, ok := l.balances[addr]
	if !ok {
		return basics.AccountData{}, fmt.Errorf("no account %s", addr)
	}
	return basics.AccountData{
		MicroAlgos:     basics.MicroAlgos{Raw: br.balance},
		AssetParams:    map[basics.AssetIndex]basics.AssetParams{},
		Assets:         map[basics.AssetIndex]basics.AssetHolding{},
		AppLocalStates: map[basics.AppIndex]basics.AppLocalState{},
		AppParams:      map[basics.AppIndex]basics.AppParams{},
		LastProposed:   br.proposed,
		LastHeartbeat:  br.heartbeat,
		// The fields below are not exposed to `acct_params_get`, the thinking
		// is that we don't want them used as "free" storage.  And thus far, we
		// don't have compelling reasons to examine them in AVM.
		VoteID:          br.voting.VoteID,
		SelectionID:     br.voting.SelectionID,
		StateProofID:    br.voting.StateProofID,
		VoteFirstValid:  br.voting.VoteFirstValid,
		VoteLastValid:   br.voting.VoteLastValid,
		VoteKeyDilution: br.voting.VoteKeyDilution,
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
	return basics.Address{}, false, fmt.Errorf("no creatable %v %d", ctype, cidx)
}

// SetKey creates a new key-value in {addr, aidx, global} storage
func (l *Ledger) SetKey(addr basics.Address, aidx basics.AppIndex, global bool, key string, value basics.TealValue, accountIdx uint64) error {
	if global {
		l.NewGlobal(aidx, key, value)
	} else {
		l.NewLocal(addr, aidx, key, value)
	}
	return nil
}

// DelKey removes a key from {addr, aidx, global} storage
func (l *Ledger) DelKey(addr basics.Address, aidx basics.AppIndex, global bool, key string, accountIdx uint64) error {
	if global {
		l.NoGlobal(aidx, key)
	} else {
		l.NoLocal(addr, aidx, key)
	}
	return nil
}

func (l *Ledger) Round() basics.Round {
	if l.rnd == basics.Round(0) {
		// Something big enough to shake out bugs from width
		l.rnd = basics.Round(uint64(math.MaxUint32) + 5)
	}
	return l.rnd
}
