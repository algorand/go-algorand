// Copyright (C) 2019-2022 Algorand, Inc.
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

package internal

import (
	"fmt"

	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/bookkeeping"
	"github.com/algorand/go-algorand/data/transactions"
	"github.com/algorand/go-algorand/data/transactions/logic"
	"github.com/algorand/go-algorand/ledger/apply"
	"github.com/algorand/go-algorand/ledger/ledgercore"
	"github.com/algorand/go-algorand/protocol"
)

type logicLedger struct {
	cow cowForLogicLedger
}

type cowForLogicLedger interface {
	Get(addr basics.Address, withPendingRewards bool) (ledgercore.AccountData, error)
	GetAppParams(addr basics.Address, aidx basics.AppIndex) (basics.AppParams, bool, error)
	GetAssetParams(addr basics.Address, aidx basics.AssetIndex) (basics.AssetParams, bool, error)
	GetAssetHolding(addr basics.Address, aidx basics.AssetIndex) (basics.AssetHolding, bool, error)
	GetCreator(cidx basics.CreatableIndex, ctype basics.CreatableType) (basics.Address, bool, error)
	GetKey(addr basics.Address, aidx basics.AppIndex, global bool, key string, accountIdx uint64) (basics.TealValue, bool, error)
	BuildEvalDelta(aidx basics.AppIndex, txn *transactions.Transaction) (transactions.EvalDelta, error)

	SetKey(addr basics.Address, aidx basics.AppIndex, global bool, key string, value basics.TealValue, accountIdx uint64) error
	DelKey(addr basics.Address, aidx basics.AppIndex, global bool, key string, accountIdx uint64) error

	round() basics.Round
	prevTimestamp() int64
	allocated(addr basics.Address, aidx basics.AppIndex, global bool) (bool, error)
	txnCounter() uint64
	incTxnCount()

	// The method should use the txtail to ensure MaxTxnLife+1 headers back are available
	blockHdrCached(round basics.Round) (bookkeeping.BlockHeader, error)
}

func newLogicLedger(cow cowForLogicLedger) *logicLedger {
	return &logicLedger{
		cow: cow,
	}
}

func (al *logicLedger) AccountData(addr basics.Address) (ledgercore.AccountData, error) {
	record, err := al.cow.Get(addr, true)
	if err != nil {
		return ledgercore.AccountData{}, err
	}
	return record, nil
}

func (al *logicLedger) Authorizer(addr basics.Address) (basics.Address, error) {
	record, err := al.cow.Get(addr, false) // pending rewards unneeded
	if err != nil {
		return basics.Address{}, err
	}
	if !record.AuthAddr.IsZero() {
		return record.AuthAddr, nil
	}
	return addr, nil
}

func (al *logicLedger) AssetHolding(addr basics.Address, assetIdx basics.AssetIndex) (basics.AssetHolding, error) {
	// Fetch the requested balance record
	holding, ok, err := al.cow.GetAssetHolding(addr, assetIdx)
	if err != nil {
		return basics.AssetHolding{}, err
	}

	// Ensure we have the requested holding
	if !ok {
		err = fmt.Errorf("account %s has not opted in to asset %d", addr.String(), assetIdx)
		return basics.AssetHolding{}, err
	}

	return holding, nil
}

func (al *logicLedger) AssetParams(assetIdx basics.AssetIndex) (basics.AssetParams, basics.Address, error) {
	// Find asset creator
	creator, ok, err := al.cow.GetCreator(basics.CreatableIndex(assetIdx), basics.AssetCreatable)
	if err != nil {
		return basics.AssetParams{}, creator, err
	}

	// Ensure asset exists
	if !ok {
		return basics.AssetParams{}, creator, fmt.Errorf("asset %d does not exist", assetIdx)
	}

	// Fetch the requested balance record
	params, ok, err := al.cow.GetAssetParams(creator, assetIdx)
	if err != nil {
		return basics.AssetParams{}, creator, err
	}

	// Ensure account created the requested asset
	if !ok {
		err = fmt.Errorf("account %s has not created asset %d", creator, assetIdx)
		return basics.AssetParams{}, creator, err
	}

	return params, creator, nil
}

func (al *logicLedger) AppParams(appIdx basics.AppIndex) (basics.AppParams, basics.Address, error) {
	// Find app creator
	creator, ok, err := al.cow.GetCreator(basics.CreatableIndex(appIdx), basics.AppCreatable)
	if err != nil {
		return basics.AppParams{}, creator, err
	}

	// Ensure app exists
	if !ok {
		return basics.AppParams{}, creator, fmt.Errorf("app %d does not exist", appIdx)
	}

	// Fetch the requested balance record
	params, ok, err := al.cow.GetAppParams(creator, appIdx)
	if err != nil {
		return basics.AppParams{}, creator, err
	}

	// Ensure account created the requested app
	if !ok {
		err = fmt.Errorf("account %s has not created app %d", creator, appIdx)
		return basics.AppParams{}, creator, err
	}

	return params, creator, nil
}

func (al *logicLedger) Round() basics.Round {
	return al.cow.round()
}

func (al *logicLedger) LatestTimestamp() int64 {
	return al.cow.prevTimestamp()
}

func (al *logicLedger) BlockHdrCached(round basics.Round) (bookkeeping.BlockHeader, error) {
	return al.cow.blockHdrCached(round)
}

func (al *logicLedger) OptedIn(addr basics.Address, appIdx basics.AppIndex) (bool, error) {
	return al.cow.allocated(addr, appIdx, false)
}

func (al *logicLedger) GetLocal(addr basics.Address, appIdx basics.AppIndex, key string, accountIdx uint64) (basics.TealValue, bool, error) {
	return al.cow.GetKey(addr, appIdx, false, key, accountIdx)
}

func (al *logicLedger) SetLocal(addr basics.Address, appIdx basics.AppIndex, key string, value basics.TealValue, accountIdx uint64) error {
	return al.cow.SetKey(addr, appIdx, false, key, value, accountIdx)
}

func (al *logicLedger) DelLocal(addr basics.Address, appIdx basics.AppIndex, key string, accountIdx uint64) error {
	return al.cow.DelKey(addr, appIdx, false, key, accountIdx)
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
	addr, err := al.fetchAppCreator(appIdx)
	if err != nil {
		return basics.TealValue{}, false, err
	}
	return al.cow.GetKey(addr, appIdx, true, key, 0)
}

func (al *logicLedger) SetGlobal(appIdx basics.AppIndex, key string, value basics.TealValue) error {
	creator, err := al.fetchAppCreator(appIdx)
	if err != nil {
		return err
	}
	return al.cow.SetKey(creator, appIdx, true, key, value, 0)
}

func (al *logicLedger) DelGlobal(appIdx basics.AppIndex, key string) error {
	creator, err := al.fetchAppCreator(appIdx)
	if err != nil {
		return err
	}
	return al.cow.DelKey(creator, appIdx, true, key, 0)
}

func (al *logicLedger) balances() (apply.Balances, error) {
	balances, ok := al.cow.(apply.Balances)
	if !ok {
		return nil, fmt.Errorf("cannot get a Balances object from %v", al)
	}
	return balances, nil
}

func (al *logicLedger) Perform(gi int, ep *logic.EvalParams) error {
	txn := &ep.TxnGroup[gi]
	balances, err := al.balances()
	if err != nil {
		return err
	}

	// move fee to pool
	err = balances.Move(txn.Txn.Sender, ep.Specials.FeeSink, txn.Txn.Fee, &txn.ApplyData.SenderRewards, nil)
	if err != nil {
		return err
	}

	err = apply.Rekey(balances, &txn.Txn)
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
	al.cow.incTxnCount()

	switch txn.Txn.Type {
	case protocol.PaymentTx:
		err = apply.Payment(txn.Txn.PaymentTxnFields, txn.Txn.Header, balances, *ep.Specials, &txn.ApplyData)

	case protocol.KeyRegistrationTx:
		err = apply.Keyreg(txn.Txn.KeyregTxnFields, txn.Txn.Header, balances, *ep.Specials, &txn.ApplyData,
			al.Round())

	case protocol.AssetConfigTx:
		err = apply.AssetConfig(txn.Txn.AssetConfigTxnFields, txn.Txn.Header, balances, *ep.Specials, &txn.ApplyData,
			al.cow.txnCounter())

	case protocol.AssetTransferTx:
		err = apply.AssetTransfer(txn.Txn.AssetTransferTxnFields, txn.Txn.Header, balances, *ep.Specials, &txn.ApplyData)

	case protocol.AssetFreezeTx:
		err = apply.AssetFreeze(txn.Txn.AssetFreezeTxnFields, txn.Txn.Header, balances, *ep.Specials, &txn.ApplyData)

	case protocol.ApplicationCallTx:
		err = apply.ApplicationCall(txn.Txn.ApplicationCallTxnFields, txn.Txn.Header, balances, &txn.ApplyData,
			gi, ep, al.cow.txnCounter())

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

func (al *logicLedger) Counter() uint64 {
	return al.cow.txnCounter()
}
