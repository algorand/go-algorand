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

	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/transactions"
)

func cloneAssetHoldings(m map[basics.AssetIndex]basics.AssetHolding) map[basics.AssetIndex]basics.AssetHolding {
	res := make(map[basics.AssetIndex]basics.AssetHolding)
	for id, val := range m {
		res[id] = val
	}
	return res
}

func cloneAssetParams(m map[basics.AssetIndex]basics.AssetParams) map[basics.AssetIndex]basics.AssetParams {
	res := make(map[basics.AssetIndex]basics.AssetParams)
	for id, val := range m {
		res[id] = val
	}
	return res
}

func getParams(balances Balances, aidx basics.AssetIndex) (params basics.AssetParams, creator basics.Address, err error) {
	creator, exists, err := balances.GetCreator(basics.CreatableIndex(aidx), basics.AssetCreatable)
	if err != nil {
		return
	}

	// For assets, anywhere we're attempting to fetch parameters, we are
	// assuming that the asset should exist.
	if !exists {
		err = fmt.Errorf("asset %d does not exist or has been deleted", aidx)
		return
	}

	creatorRecord, err := balances.Get(creator, false)
	if err != nil {
		return
	}

	params, ok := creatorRecord.AssetParams[aidx]
	if !ok {
		err = fmt.Errorf("asset index %d not found in account %s", aidx, creator.String())
		return
	}

	return
}

// AssetConfig applies an AssetConfig transaction using the Balances interface.
func AssetConfig(cc transactions.AssetConfigTxnFields, header transactions.Header, balances Balances, spec transactions.SpecialAddresses, ad *transactions.ApplyData, txnCounter uint64) error {
	if cc.ConfigAsset == 0 {
		// Allocating an asset.
		record, err := balances.Get(header.Sender, false)
		if err != nil {
			return err
		}
		record.Assets = cloneAssetHoldings(record.Assets)
		record.AssetParams = cloneAssetParams(record.AssetParams)

		// Ensure index is never zero
		newidx := basics.AssetIndex(txnCounter + 1)

		// Sanity check that there isn't an asset with this counter value.
		_, present := record.AssetParams[newidx]
		if present {
			return fmt.Errorf("already found asset with index %d", newidx)
		}

		record.AssetParams[newidx] = cc.AssetParams
		record.Assets[newidx] = basics.AssetHolding{
			Amount: cc.AssetParams.Total,
		}

		if len(record.Assets) > balances.ConsensusParams().MaxAssetsPerAccount {
			return fmt.Errorf("too many assets in account: %d > %d", len(record.Assets), balances.ConsensusParams().MaxAssetsPerAccount)
		}

		// Tell the cow what asset we created
		created := &basics.CreatableLocator{
			Creator: header.Sender,
			Type:    basics.AssetCreatable,
			Index:   basics.CreatableIndex(newidx),
		}

		return balances.PutWithCreatable(header.Sender, record, created, nil)
	}

	// Re-configuration and destroying must be done by the manager key.
	params, creator, err := getParams(balances, cc.ConfigAsset)
	if err != nil {
		return err
	}

	if params.Manager.IsZero() || (header.Sender != params.Manager) {
		return fmt.Errorf("this transaction should be issued by the manager. It is issued by %v, manager key %v", header.Sender, params.Manager)
	}

	record, err := balances.Get(creator, false)
	if err != nil {
		return err
	}

	record.Assets = cloneAssetHoldings(record.Assets)
	record.AssetParams = cloneAssetParams(record.AssetParams)

	var deleted *basics.CreatableLocator
	if cc.AssetParams == (basics.AssetParams{}) {
		// Destroying an asset.  The creator account must hold
		// the entire outstanding asset amount.
		if record.Assets[cc.ConfigAsset].Amount != params.Total {
			return fmt.Errorf("cannot destroy asset: creator is holding only %d/%d", record.Assets[cc.ConfigAsset].Amount, params.Total)
		}

		// Tell the cow what asset we deleted
		deleted = &basics.CreatableLocator{
			Creator: creator,
			Type:    basics.AssetCreatable,
			Index:   basics.CreatableIndex(cc.ConfigAsset),
		}

		delete(record.Assets, cc.ConfigAsset)
		delete(record.AssetParams, cc.ConfigAsset)
	} else {
		// Changing keys in an asset.
		if !params.Manager.IsZero() {
			params.Manager = cc.AssetParams.Manager
		}
		if !params.Reserve.IsZero() {
			params.Reserve = cc.AssetParams.Reserve
		}
		if !params.Freeze.IsZero() {
			params.Freeze = cc.AssetParams.Freeze
		}
		if !params.Clawback.IsZero() {
			params.Clawback = cc.AssetParams.Clawback
		}

		record.AssetParams[cc.ConfigAsset] = params
	}

	return balances.PutWithCreatable(creator, record, nil, deleted)
}

func takeOut(balances Balances, addr basics.Address, asset basics.AssetIndex, amount uint64, bypassFreeze bool) error {
	if amount == 0 {
		return nil
	}

	snd, err := balances.Get(addr, false)
	if err != nil {
		return err
	}

	snd.Assets = cloneAssetHoldings(snd.Assets)
	sndHolding, ok := snd.Assets[asset]
	if !ok {
		return fmt.Errorf("asset %v missing from %v", asset, addr)
	}

	if sndHolding.Frozen && !bypassFreeze {
		return fmt.Errorf("asset %v frozen in %v", asset, addr)
	}

	newAmount, overflowed := basics.OSub(sndHolding.Amount, amount)
	if overflowed {
		return fmt.Errorf("underflow on subtracting %d from sender amount %d", amount, sndHolding.Amount)
	}
	sndHolding.Amount = newAmount

	snd.Assets[asset] = sndHolding
	return balances.Put(addr, snd)
}

func putIn(balances Balances, addr basics.Address, asset basics.AssetIndex, amount uint64, bypassFreeze bool) error {
	if amount == 0 {
		return nil
	}

	rcv, err := balances.Get(addr, false)
	if err != nil {
		return err
	}

	rcv.Assets = cloneAssetHoldings(rcv.Assets)
	rcvHolding, ok := rcv.Assets[asset]
	if !ok {
		return fmt.Errorf("asset %v missing from %v", asset, addr)
	}

	if rcvHolding.Frozen && !bypassFreeze {
		return fmt.Errorf("asset frozen in recipient")
	}

	var overflowed bool
	rcvHolding.Amount, overflowed = basics.OAdd(rcvHolding.Amount, amount)
	if overflowed {
		return fmt.Errorf("overflow on adding %d to receiver amount %d", amount, rcvHolding.Amount)
	}

	rcv.Assets[asset] = rcvHolding
	return balances.Put(addr, rcv)
}

// AssetTransfer applies an AssetTransfer transaction using the Balances interface.
func AssetTransfer(ct transactions.AssetTransferTxnFields, header transactions.Header, balances Balances, spec transactions.SpecialAddresses, ad *transactions.ApplyData) error {
	// Default to sending from the transaction sender's account.
	source := header.Sender
	clawback := false

	if !ct.AssetSender.IsZero() {
		// Clawback transaction.  Check that the transaction sender
		// is the Clawback address for this asset.
		params, _, err := getParams(balances, ct.XferAsset)
		if err != nil {
			return err
		}

		if params.Clawback.IsZero() || (header.Sender != params.Clawback) {
			return fmt.Errorf("clawback not allowed: sender %v, clawback %v", header.Sender, params.Clawback)
		}

		// Transaction sent from the correct clawback address,
		// execute asset transfer from specified source.
		source = ct.AssetSender
		clawback = true
	}

	// Allocate a slot for asset (self-transfer of zero amount).
	if ct.AssetAmount == 0 && ct.AssetReceiver == source && !clawback {
		snd, err := balances.Get(source, false)
		if err != nil {
			return err
		}

		snd.Assets = cloneAssetHoldings(snd.Assets)
		sndHolding, ok := snd.Assets[ct.XferAsset]
		if !ok {
			// Initialize holding with default Frozen value.
			params, _, err := getParams(balances, ct.XferAsset)
			if err != nil {
				return err
			}

			sndHolding.Frozen = params.DefaultFrozen
			snd.Assets[ct.XferAsset] = sndHolding

			if len(snd.Assets) > balances.ConsensusParams().MaxAssetsPerAccount {
				return fmt.Errorf("too many assets in account: %d > %d", len(snd.Assets), balances.ConsensusParams().MaxAssetsPerAccount)
			}

			err = balances.Put(source, snd)
			if err != nil {
				return err
			}
		}
	}

	// Actually move the asset.  Zero transfers return right away
	// without looking up accounts, so it's fine to have a zero transfer
	// to an all-zero address (e.g., when the only meaningful part of
	// the transaction is the close-to address). Similarly, takeOut and
	// putIn will succeed for zero transfers on frozen asset holdings
	err := takeOut(balances, source, ct.XferAsset, ct.AssetAmount, clawback)
	if err != nil {
		return err
	}

	err = putIn(balances, ct.AssetReceiver, ct.XferAsset, ct.AssetAmount, clawback)
	if err != nil {
		return err
	}

	if ct.AssetCloseTo != (basics.Address{}) {
		// Cannot close by clawback
		if clawback {
			return fmt.Errorf("cannot close asset by clawback")
		}

		// Fetch the sender balance record. We will use this to ensure
		// that the sender is not the creator of the asset, and to
		// figure out how much of the asset to move.
		snd, err := balances.Get(source, false)
		if err != nil {
			return err
		}

		// The creator of the asset cannot close their holding of the
		// asset. Check if we are the creator by seeing if there is an
		// AssetParams entry for the asset index.
		if _, ok := snd.AssetParams[ct.XferAsset]; ok {
			return fmt.Errorf("cannot close asset ID in allocating account")
		}

		// Fetch our asset holding, which should exist since we're
		// closing it out
		sndHolding, ok := snd.Assets[ct.XferAsset]
		if !ok {
			return fmt.Errorf("asset %v not present in account %v", ct.XferAsset, source)
		}

		// Fetch the destination balance record to check if we are
		// closing out to the creator
		dst, err := balances.Get(ct.AssetCloseTo, false)
		if err != nil {
			return err
		}

		// Allow closing out to the asset creator even when frozen.
		// If we are closing out 0 units of the asset, then takeOut
		// and putIn will short circuit (so bypassFreeze doesn't matter)
		_, bypassFreeze := dst.AssetParams[ct.XferAsset]

		// AssetCloseAmount was a late addition, checking that the current protocol version supports it.
		if balances.ConsensusParams().EnableAssetCloseAmount {
			// Add the close amount to ApplyData.
			closeAmount := sndHolding.Amount
			ad.AssetClosingAmount = closeAmount
		}

		// Move the balance out.
		err = takeOut(balances, source, ct.XferAsset, sndHolding.Amount, bypassFreeze)
		if err != nil {
			return err
		}

		// Put the balance in.
		err = putIn(balances, ct.AssetCloseTo, ct.XferAsset, sndHolding.Amount, bypassFreeze)
		if err != nil {
			return err
		}

		// Delete the slot from the account.
		snd, err = balances.Get(source, false)
		if err != nil {
			return err
		}

		snd.Assets = cloneAssetHoldings(snd.Assets)
		sndHolding = snd.Assets[ct.XferAsset]
		if sndHolding.Amount != 0 {
			return fmt.Errorf("asset %v not zero (%d) after closing", ct.XferAsset, sndHolding.Amount)
		}

		delete(snd.Assets, ct.XferAsset)
		err = balances.Put(source, snd)
		if err != nil {
			return err
		}
	}

	return nil
}

// AssetFreeze applies an AssetFreeze transaction using the Balances interface.
func AssetFreeze(cf transactions.AssetFreezeTxnFields, header transactions.Header, balances Balances, spec transactions.SpecialAddresses, ad *transactions.ApplyData) error {
	// Only the Freeze address can change the freeze value.
	params, _, err := getParams(balances, cf.FreezeAsset)
	if err != nil {
		return err
	}

	if params.Freeze.IsZero() || (header.Sender != params.Freeze) {
		return fmt.Errorf("freeze not allowed: sender %v, freeze %v", header.Sender, params.Freeze)
	}

	// Get the account to be frozen/unfrozen.
	record, err := balances.Get(cf.FreezeAccount, false)
	if err != nil {
		return err
	}
	record.Assets = cloneAssetHoldings(record.Assets)

	holding, ok := record.Assets[cf.FreezeAsset]
	if !ok {
		return fmt.Errorf("asset not found in account")
	}

	holding.Frozen = cf.AssetFrozen
	record.Assets[cf.FreezeAsset] = holding
	return balances.Put(cf.FreezeAccount, record)
}
