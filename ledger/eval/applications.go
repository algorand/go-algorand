// Copyright (C) 2019-2024 Algorand, Inc.
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

package eval

import (
	"fmt"

	"github.com/algorand/avm-abi/apps"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/transactions/logic"
	"github.com/algorand/go-algorand/ledger/apply"
	"github.com/algorand/go-algorand/ledger/ledgercore"
	"github.com/algorand/go-algorand/protocol"
)

/* This file adds functions to roundCowState that make it more palatable for use
   outside of the ledger package. The LedgerForLogic interface expects them. */

func (cs *roundCowState) AccountData(addr basics.Address) (ledgercore.AccountData, error) {
	record, err := cs.Get(addr, true)
	if err != nil {
		return ledgercore.AccountData{}, err
	}
	return record, nil
}

func (cs *roundCowState) Authorizer(addr basics.Address) (basics.Address, error) {
	record, err := cs.Get(addr, false) // pending rewards unneeded
	if err != nil {
		return basics.Address{}, err
	}
	if !record.AuthAddr.IsZero() {
		return record.AuthAddr, nil
	}
	return addr, nil
}

func (cs *roundCowState) AssetHolding(addr basics.Address, assetIdx basics.AssetIndex) (basics.AssetHolding, error) {
	// Fetch the requested balance record
	holding, ok, err := cs.GetAssetHolding(addr, assetIdx)
	if err != nil {
		return basics.AssetHolding{}, err
	}

	// Ensure we have the requested holding
	if !ok {
		return basics.AssetHolding{}, fmt.Errorf("account %s has not opted in to asset %d", addr, assetIdx)
	}

	return holding, nil
}

func (cs *roundCowState) AssetParams(assetIdx basics.AssetIndex) (basics.AssetParams, basics.Address, error) {
	// Find asset creator
	creator, ok, err := cs.GetCreator(basics.CreatableIndex(assetIdx), basics.AssetCreatable)
	if err != nil {
		return basics.AssetParams{}, creator, err
	}

	// Ensure asset exists
	if !ok {
		return basics.AssetParams{}, creator, fmt.Errorf("asset %d does not exist", assetIdx)
	}

	// Fetch the requested balance record
	params, ok, err := cs.GetAssetParams(creator, assetIdx)
	if err != nil {
		return basics.AssetParams{}, creator, err
	}

	// Ensure account created the requested asset
	if !ok {
		return basics.AssetParams{}, creator, fmt.Errorf("account %s has not created asset %d", creator, assetIdx)
	}

	return params, creator, nil
}

func (cs *roundCowState) AppParams(appIdx basics.AppIndex) (basics.AppParams, basics.Address, error) {
	// Find app creator
	creator, ok, err := cs.GetCreator(basics.CreatableIndex(appIdx), basics.AppCreatable)
	if err != nil {
		return basics.AppParams{}, creator, err
	}

	// Ensure app exists
	if !ok {
		return basics.AppParams{}, creator, fmt.Errorf("app %d does not exist", appIdx)
	}

	// Fetch the requested balance record
	params, ok, err := cs.GetAppParams(creator, appIdx)
	if err != nil {
		return basics.AppParams{}, creator, err
	}

	// Ensure account created the requested app
	if !ok {
		return basics.AppParams{}, creator, fmt.Errorf("account %s has not created app %d", creator, appIdx)
	}

	return params, creator, nil
}

func (cs *roundCowState) OptedIn(addr basics.Address, appIdx basics.AppIndex) (bool, error) {
	return cs.allocated(addr, appIdx, false)
}

func (cs *roundCowState) GetLocal(addr basics.Address, appIdx basics.AppIndex, key string, accountIdx uint64) (basics.TealValue, bool, error) {
	return cs.getKey(addr, appIdx, false, key, accountIdx)
}

func (cs *roundCowState) SetLocal(addr basics.Address, appIdx basics.AppIndex, key string, value basics.TealValue, accountIdx uint64) error {
	return cs.setKey(addr, appIdx, false, key, value, accountIdx)
}

func (cs *roundCowState) DelLocal(addr basics.Address, appIdx basics.AppIndex, key string, accountIdx uint64) error {
	return cs.delKey(addr, appIdx, false, key, accountIdx)
}

func (cs *roundCowState) fetchAppCreator(appIdx basics.AppIndex) (basics.Address, error) {
	// Fetch the application creator
	addr, ok, err := cs.GetCreator(basics.CreatableIndex(appIdx), basics.AppCreatable)

	if err != nil {
		return basics.Address{}, err
	}
	if !ok {
		return basics.Address{}, fmt.Errorf("app %d does not exist", appIdx)
	}
	return addr, nil
}

func (cs *roundCowState) GetGlobal(appIdx basics.AppIndex, key string) (basics.TealValue, bool, error) {
	creator, err := cs.fetchAppCreator(appIdx)
	if err != nil {
		return basics.TealValue{}, false, err
	}
	return cs.getKey(creator, appIdx, true, key, 0)
}

func (cs *roundCowState) SetGlobal(appIdx basics.AppIndex, key string, value basics.TealValue) error {
	creator, err := cs.fetchAppCreator(appIdx)
	if err != nil {
		return err
	}
	return cs.setKey(creator, appIdx, true, key, value, 0)
}

func (cs *roundCowState) DelGlobal(appIdx basics.AppIndex, key string) error {
	creator, err := cs.fetchAppCreator(appIdx)
	if err != nil {
		return err
	}
	return cs.delKey(creator, appIdx, true, key, 0)
}

func (cs *roundCowState) kvGet(key string) ([]byte, bool, error) {
	value, ok := cs.mods.KvMods[key]
	if !ok {
		return cs.lookupParent.kvGet(key)
	}
	// If value is nil, it's a marker for a local deletion
	return value.Data, value.Data != nil, nil
}

func (cb *roundCowBase) kvGet(key string) ([]byte, bool, error) {
	value, ok := cb.kvStore[key]
	if !ok {
		v, err := cb.l.LookupKv(cb.rnd, key)
		if err != nil {
			return nil, false, err
		}
		value = v
		cb.kvStore[key] = value
	}
	// If value is nil, it caches a lookup that returned nothing.
	return value, value != nil, nil
}

func (cs *roundCowState) kvPut(key string, value []byte) error {
	cs.mods.AddKvMod(key, ledgercore.KvValueDelta{Data: value})
	return nil
}

func (cs *roundCowState) kvDel(key string) error {
	cs.mods.AddKvMod(key, ledgercore.KvValueDelta{Data: nil})
	return nil
}

func (cs *roundCowState) NewBox(appIdx basics.AppIndex, key string, value []byte, appAddr basics.Address) error {
	// Use same limit on key length as for global/local storage
	if len(key) > cs.proto.MaxAppKeyLen {
		return fmt.Errorf("name too long: length was %d, maximum is %d", len(key), cs.proto.MaxAppKeyLen)
	}
	// This rule is NOT like global/local storage, but seems like it will limit
	// confusion, since these are standalone entities.
	if len(key) == 0 {
		return fmt.Errorf("box names may not be zero length")
	}

	size := uint64(len(value))
	if size > cs.proto.MaxBoxSize {
		return fmt.Errorf("box size too large: %d, maximum is %d", size, cs.proto.MaxBoxSize)
	}

	fullKey := apps.MakeBoxKey(uint64(appIdx), key)
	_, exists, err := cs.kvGet(fullKey)
	if err != nil {
		return err
	}
	if exists {
		return fmt.Errorf("attempt to recreate box %#x", key)
	}

	record, err := cs.Get(appAddr, false)
	if err != nil {
		return err
	}
	record.TotalBoxes = basics.AddSaturate(record.TotalBoxes, 1)
	record.TotalBoxBytes = basics.AddSaturate(record.TotalBoxBytes, uint64(len(key))+size)
	err = cs.Put(appAddr, record)
	if err != nil {
		return err
	}

	return cs.kvPut(fullKey, value)
}

func (cs *roundCowState) GetBox(appIdx basics.AppIndex, key string) ([]byte, bool, error) {
	fullKey := apps.MakeBoxKey(uint64(appIdx), key)
	return cs.kvGet(fullKey)
}

func (cs *roundCowState) SetBox(appIdx basics.AppIndex, key string, value []byte) error {
	fullKey := apps.MakeBoxKey(uint64(appIdx), key)
	old, ok, err := cs.kvGet(fullKey)
	if err != nil {
		return err
	}
	if !ok {
		return fmt.Errorf("box %#x does not exist for %d", key, appIdx)
	}
	if len(old) != len(value) {
		return fmt.Errorf("box %#x is wrong size old:%d != new:%d",
			key, len(old), len(value))
	}
	return cs.kvPut(fullKey, value)
}

func (cs *roundCowState) DelBox(appIdx basics.AppIndex, key string, appAddr basics.Address) (bool, error) {
	fullKey := apps.MakeBoxKey(uint64(appIdx), key)

	value, ok, err := cs.kvGet(fullKey)
	if err != nil {
		return false, err
	}
	if !ok {
		return false, nil
	}

	record, err := cs.Get(appAddr, false)
	if err != nil {
		return false, err
	}
	record.TotalBoxes = basics.SubSaturate(record.TotalBoxes, 1)
	record.TotalBoxBytes = basics.SubSaturate(record.TotalBoxBytes, uint64(len(key)+len(value)))
	err = cs.Put(appAddr, record)
	if err != nil {
		return false, err
	}

	return true, cs.kvDel(fullKey)
}

func (cs *roundCowState) Perform(gi int, ep *logic.EvalParams) error {
	txn := &ep.TxnGroup[gi]

	// move fee to pool
	err := cs.Move(txn.Txn.Sender, ep.Specials.FeeSink, txn.Txn.Fee, &txn.ApplyData.SenderRewards, nil)
	if err != nil {
		return err
	}

	err = apply.Rekey(cs, &txn.Txn)
	if err != nil {
		return err
	}

	// compared to eval.transaction() it may seem strange that we
	// increment the transaction count *before* transaction
	// processing, rather than after. But we need to account for the
	// fact that our outer transaction has not yet incremented their
	// count (in addTx()), so we need to increment ahead of use, so we
	// don't use the same index.  If eval.transaction() incremented
	// ahead of processing, we'd have to do ours *after* so that we'd
	// use the next id.  So either way, this would seem backwards at
	// first glance.
	cs.incTxnCount()

	switch txn.Txn.Type {
	case protocol.PaymentTx:
		err = apply.Payment(txn.Txn.PaymentTxnFields, txn.Txn.Header, cs, *ep.Specials, &txn.ApplyData)

	case protocol.KeyRegistrationTx:
		err = apply.Keyreg(txn.Txn.KeyregTxnFields, txn.Txn.Header, cs, *ep.Specials, &txn.ApplyData,
			cs.Round())

	case protocol.AssetConfigTx:
		err = apply.AssetConfig(txn.Txn.AssetConfigTxnFields, txn.Txn.Header, cs, *ep.Specials, &txn.ApplyData,
			cs.Counter())

	case protocol.AssetTransferTx:
		err = apply.AssetTransfer(txn.Txn.AssetTransferTxnFields, txn.Txn.Header, cs, *ep.Specials, &txn.ApplyData)

	case protocol.AssetFreezeTx:
		err = apply.AssetFreeze(txn.Txn.AssetFreezeTxnFields, txn.Txn.Header, cs, *ep.Specials, &txn.ApplyData)

	case protocol.ApplicationCallTx:
		err = apply.ApplicationCall(txn.Txn.ApplicationCallTxnFields, txn.Txn.Header, cs, &txn.ApplyData,
			gi, ep, cs.Counter())

	default:
		err = fmt.Errorf("%s tx in AVM", txn.Txn.Type)
	}
	if err != nil {
		return err
	}

	// We don't check min balances during in app txns.

	// func (eval *BlockEvaluator) checkMinBalance will take care of it when the
	// top-level txn concludes, because cow will return all changed accounts in
	// modifiedAccounts().

	return nil
}
