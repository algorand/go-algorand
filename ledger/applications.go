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
	"fmt"

	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/transactions"
)

type logicLedger struct {
	aidx    basics.AppIndex
	creator basics.Address
	cow     cowForLogicLedger
}

type cowForLogicLedger interface {
	Get(addr basics.Address, withPendingRewards bool) (basics.AccountData, error)
	GetCreator(cidx basics.CreatableIndex, ctype basics.CreatableType) (basics.Address, bool, error)
	GetKey(addr basics.Address, aidx basics.AppIndex, global bool, key string, accountIdx uint64) (basics.TealValue, bool, error)
	BuildEvalDelta(aidx basics.AppIndex, txn *transactions.Transaction) (basics.EvalDelta, error)

	SetKey(addr basics.Address, aidx basics.AppIndex, global bool, key string, value basics.TealValue, accountIdx uint64) error
	DelKey(addr basics.Address, aidx basics.AppIndex, global bool, key string, accountIdx uint64) error

	round() basics.Round
	prevTimestamp() int64
	allocated(addr basics.Address, aidx basics.AppIndex, global bool) (bool, error)
}

func newLogicLedger(cow cowForLogicLedger, aidx basics.AppIndex) (*logicLedger, error) {
	if aidx == basics.AppIndex(0) {
		return nil, fmt.Errorf("cannot make logic ledger for app index 0")
	}

	al := &logicLedger{
		aidx: aidx,
		cow:  cow,
	}

	// Fetch app creator so we don't have to look it up every time we get/set/del
	// a key for this app's global state
	creator, err := al.fetchAppCreator(al.aidx)
	if err != nil {
		return nil, err
	}
	al.creator = creator

	return al, nil
}

func (al *logicLedger) Balance(addr basics.Address) (res basics.MicroAlgos, err error) {
	// Fetch record with pending rewards applied
	record, err := al.cow.Get(addr, true)
	if err != nil {
		return
	}

	return record.MicroAlgos, nil
}

func (al *logicLedger) MinBalance(addr basics.Address, proto *config.ConsensusParams) (res basics.MicroAlgos, err error) {
	record, err := al.cow.Get(addr, false) // pending rewards unneeded
	if err != nil {
		return
	}

	return record.MinBalance(proto), nil
}

func (al *logicLedger) AssetHolding(addr basics.Address, assetIdx basics.AssetIndex) (basics.AssetHolding, error) {
	// Fetch the requested balance record
	record, err := al.cow.Get(addr, false)
	if err != nil {
		return basics.AssetHolding{}, err
	}

	// Ensure we have the requested holding
	holding, ok := record.Assets[assetIdx]
	if !ok {
		err = fmt.Errorf("account %s has not opted in to asset %d", addr.String(), assetIdx)
		return basics.AssetHolding{}, err
	}

	return holding, nil
}

func (al *logicLedger) AssetParams(assetIdx basics.AssetIndex) (basics.AssetParams, error) {
	// Find asset creator
	creator, ok, err := al.cow.GetCreator(basics.CreatableIndex(assetIdx), basics.AssetCreatable)
	if err != nil {
		return basics.AssetParams{}, err
	}

	// Ensure asset exists
	if !ok {
		return basics.AssetParams{}, fmt.Errorf("asset %d does not exist", assetIdx)
	}

	// Fetch the requested balance record
	record, err := al.cow.Get(creator, false)
	if err != nil {
		return basics.AssetParams{}, err
	}

	// Ensure account created the requested asset
	params, ok := record.AssetParams[assetIdx]
	if !ok {
		err = fmt.Errorf("account %s has not created asset %d", creator, assetIdx)
		return basics.AssetParams{}, err
	}

	return params, nil
}

func (al *logicLedger) Round() basics.Round {
	return al.cow.round()
}

func (al *logicLedger) LatestTimestamp() int64 {
	return al.cow.prevTimestamp()
}

func (al *logicLedger) ApplicationID() basics.AppIndex {
	return al.aidx
}

func (al *logicLedger) CreatorAddress() basics.Address {
	return al.creator
}

func (al *logicLedger) OptedIn(addr basics.Address, appIdx basics.AppIndex) (bool, error) {
	if appIdx == basics.AppIndex(0) {
		appIdx = al.aidx
	}
	return al.cow.allocated(addr, appIdx, false)
}

func (al *logicLedger) GetLocal(addr basics.Address, appIdx basics.AppIndex, key string, accountIdx uint64) (basics.TealValue, bool, error) {
	if appIdx == basics.AppIndex(0) {
		appIdx = al.aidx
	}
	return al.cow.GetKey(addr, appIdx, false, key, accountIdx)
}

func (al *logicLedger) SetLocal(addr basics.Address, key string, value basics.TealValue, accountIdx uint64) error {
	return al.cow.SetKey(addr, al.aidx, false, key, value, accountIdx)
}

func (al *logicLedger) DelLocal(addr basics.Address, key string, accountIdx uint64) error {
	return al.cow.DelKey(addr, al.aidx, false, key, accountIdx)
}

func (al *logicLedger) fetchAppCreator(appIdx basics.AppIndex) (basics.Address, error) {
	// Fetch the application creator
	addr, ok, err := al.cow.GetCreator(basics.CreatableIndex(appIdx), basics.AppCreatable)

	if err != nil {
		return basics.Address{}, err
	}
	if !ok {
		return basics.Address{}, fmt.Errorf("app %d does not exist", appIdx)
	}
	return addr, nil
}

func (al *logicLedger) GetGlobal(appIdx basics.AppIndex, key string) (basics.TealValue, bool, error) {
	if appIdx == basics.AppIndex(0) {
		appIdx = al.aidx
	}
	addr, err := al.fetchAppCreator(appIdx)
	if err != nil {
		return basics.TealValue{}, false, err
	}
	return al.cow.GetKey(addr, appIdx, true, key, 0)
}

func (al *logicLedger) SetGlobal(key string, value basics.TealValue) error {
	return al.cow.SetKey(al.creator, al.aidx, true, key, value, 0)
}

func (al *logicLedger) DelGlobal(key string) error {
	return al.cow.DelKey(al.creator, al.aidx, true, key, 0)
}

func (al *logicLedger) GetDelta(txn *transactions.Transaction) (evalDelta basics.EvalDelta, err error) {
	return al.cow.BuildEvalDelta(al.aidx, txn)
}
