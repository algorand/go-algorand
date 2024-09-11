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

package apply

import (
	"fmt"

	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/transactions"
)

func getParams(balances Balances, aidx basics.AssetIndex) (params basics.AssetParams, creator basics.Address, err error) {
	var exists bool
	creator, exists, err = balances.GetCreator(basics.CreatableIndex(aidx), basics.AssetCreatable)
	if err != nil {
		return
	}

	// For assets, anywhere we're attempting to fetch parameters, we are
	// assuming that the asset should exist.
	if !exists {
		err = fmt.Errorf("asset %d does not exist or has been deleted", aidx)
		return
	}

	var ok bool
	params, ok, err = balances.GetAssetParams(creator, aidx)
	if err != nil {
		return
	}

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

		// Ensure index is never zero
		newidx := basics.AssetIndex(txnCounter + 1)

		// Sanity check that there isn't an asset with this counter value.
		present, err := balances.HasAssetParams(header.Sender, newidx)
		if err != nil {
			return err
		}
		if present {
			return fmt.Errorf("already found asset with index %d", newidx)
		}

		assetParams := cc.AssetParams
		assetHolding := basics.AssetHolding{
			Amount: cc.AssetParams.Total,
		}

		totalAssets := record.TotalAssets
		maxAssetsPerAccount := balances.ConsensusParams().MaxAssetsPerAccount
		if maxAssetsPerAccount > 0 && totalAssets >= uint64(maxAssetsPerAccount) {
			return fmt.Errorf("too many assets in account: %d >= %d", totalAssets, maxAssetsPerAccount)
		}

		record.TotalAssets = basics.AddSaturate(record.TotalAssets, 1)
		record.TotalAssetParams = basics.AddSaturate(record.TotalAssetParams, 1)

		err = balances.Put(header.Sender, record)
		if err != nil {
			return err
		}
		err = balances.PutAssetParams(header.Sender, newidx, assetParams)
		if err != nil {
			return err
		}
		err = balances.PutAssetHolding(header.Sender, newidx, assetHolding)
		if err != nil {
			return err
		}

		ad.ConfigAsset = newidx

		// Tell the cow what asset we created
		err = balances.AllocateAsset(header.Sender, newidx, true)
		if err != nil {
			return err
		}
		return balances.AllocateAsset(header.Sender, newidx, false)
	}

	// Re-configuration and destroying must be done by the manager key.
	params, creator, paramsErr := getParams(balances, cc.ConfigAsset)
	if paramsErr != nil {
		return paramsErr
	}

	if params.Manager.IsZero() || (header.Sender != params.Manager) {
		return fmt.Errorf("this transaction should be issued by the manager. It is issued by %v, manager key %v", header.Sender, params.Manager)
	}

	if cc.AssetParams == (basics.AssetParams{}) {
		record, err := balances.Get(creator, false)
		if err != nil {
			return err
		}

		if record.TotalAssets == 0 {
			return fmt.Errorf("cannot destroy asset: account %v holds no assets", creator)
		}

		if record.TotalAssetParams == 0 {
			return fmt.Errorf("cannot destroy asset: account %v created no assets", creator)
		}

		// assetHolding is initialized to the zero value if none was found.
		assetHolding, _, err := balances.GetAssetHolding(creator, cc.ConfigAsset)
		if err != nil {
			return err
		}

		// Destroying an asset.  The creator account must hold
		// the entire outstanding asset amount.
		if assetHolding.Amount != params.Total {
			return fmt.Errorf("cannot destroy asset: creator is holding only %d/%d", assetHolding.Amount, params.Total)
		}

		record.TotalAssetParams = basics.SubSaturate(record.TotalAssetParams, 1)
		record.TotalAssets = basics.SubSaturate(record.TotalAssets, 1)

		err = balances.Put(creator, record)
		if err != nil {
			return err
		}

		// Tell the cow what asset we deleted
		err = balances.DeallocateAsset(creator, cc.ConfigAsset, true)
		if err != nil {
			return err
		}
		err = balances.DeallocateAsset(creator, cc.ConfigAsset, false)
		if err != nil {
			return err
		}

		err = balances.DeleteAssetHolding(creator, cc.ConfigAsset)
		if err != nil {
			return err
		}
		err = balances.DeleteAssetParams(creator, cc.ConfigAsset)
		if err != nil {
			return err
		}
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

		paramsErr = balances.PutAssetParams(creator, cc.ConfigAsset, params)
		if paramsErr != nil {
			return paramsErr
		}
	}

	return nil
}

func takeOut(balances Balances, addr basics.Address, asset basics.AssetIndex, amount uint64, bypassFreeze bool) error {
	if amount == 0 {
		return nil
	}

	sndHolding, ok, err := balances.GetAssetHolding(addr, asset)
	if err != nil {
		return err
	}
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

	return balances.PutAssetHolding(addr, asset, sndHolding)
}

func putIn(balances Balances, addr basics.Address, asset basics.AssetIndex, amount uint64, bypassFreeze bool) error {
	if amount == 0 {
		return nil
	}

	rcvHolding, ok, err := balances.GetAssetHolding(addr, asset)
	if err != nil {
		return err
	}
	if !ok {
		return fmt.Errorf("receiver error: must optin, asset %v missing from %v", asset, addr)
	}

	if rcvHolding.Frozen && !bypassFreeze {
		return fmt.Errorf("asset frozen in recipient")
	}

	var overflowed bool
	rcvHolding.Amount, overflowed = basics.OAdd(rcvHolding.Amount, amount)
	if overflowed {
		return fmt.Errorf("overflow on adding %d to receiver amount %d", amount, rcvHolding.Amount)
	}

	return balances.PutAssetHolding(addr, asset, rcvHolding)
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
		sndHolding, ok, err := balances.GetAssetHolding(source, ct.XferAsset)
		if err != nil {
			return err
		}

		if !ok {
			// Initialize holding with default Frozen value.
			params, _, err := getParams(balances, ct.XferAsset)
			if err != nil {
				return err
			}

			sndHolding.Frozen = params.DefaultFrozen

			record, err := balances.Get(source, false)
			if err != nil {
				return err
			}

			totalSndAssets := record.TotalAssets
			maxAssetsPerAccount := balances.ConsensusParams().MaxAssetsPerAccount
			if maxAssetsPerAccount > 0 && totalSndAssets >= uint64(maxAssetsPerAccount) {
				return fmt.Errorf("too many assets in account: %d >= %d", totalSndAssets, maxAssetsPerAccount)
			}

			record.TotalAssets = basics.AddSaturate(record.TotalAssets, 1)
			err = balances.Put(source, record)
			if err != nil {
				return err
			}

			err = balances.PutAssetHolding(source, ct.XferAsset, sndHolding)
			if err != nil {
				return err
			}

			err = balances.AllocateAsset(source, ct.XferAsset, false)
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

		record, err := balances.Get(source, false)
		if err != nil {
			return err
		}

		if record.TotalAssets == 0 {
			return fmt.Errorf("cannot close asset holding on account %s : account is not opted in asset %d ", source.String(), ct.XferAsset)
		}

		// Fetch the sender asset data. We will use this to ensure
		// that the sender is not the creator of the asset, and to
		// figure out how much of the asset to move.

		// The creator of the asset cannot close their holding of the
		// asset. Check if we are the creator by seeing if there is an
		// AssetParams entry for the asset index.
		ok, err := balances.HasAssetParams(source, ct.XferAsset)
		if err != nil {
			return err
		}
		if ok {
			return fmt.Errorf("cannot close asset ID in allocating account")
		}

		// Fetch our asset holding, which should exist since we're
		// closing it out
		sndHolding, ok, err := balances.GetAssetHolding(source, ct.XferAsset)
		if err != nil {
			return err
		}
		if !ok {
			return fmt.Errorf("asset %v not present in account %v", ct.XferAsset, source)
		}

		// Fetch the destination asset params to check if we are
		// closing out to the creator
		dstAssetParamsExist, err := balances.HasAssetParams(ct.AssetCloseTo, ct.XferAsset)
		if err != nil {
			return err
		}

		// Allow closing out to the asset creator even when frozen.
		// If we are closing out 0 units of the asset, then takeOut
		// and putIn will short circuit (so bypassFreeze doesn't matter)
		bypassFreeze := dstAssetParamsExist

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
		sndHolding, _, err = balances.GetAssetHolding(source, ct.XferAsset)
		if err != nil {
			return err
		}

		if sndHolding.Amount != 0 {
			return fmt.Errorf("asset %v not zero (%d) after closing", ct.XferAsset, sndHolding.Amount)
		}

		record.TotalAssets = basics.SubSaturate(record.TotalAssets, 1)
		err = balances.Put(source, record)
		if err != nil {
			return err
		}

		err = balances.DeleteAssetHolding(source, ct.XferAsset)
		if err != nil {
			return err
		}

		err = balances.DeallocateAsset(source, ct.XferAsset, false)
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
	holding, ok, err := balances.GetAssetHolding(cf.FreezeAccount, cf.FreezeAsset)
	if err != nil {
		return err
	}
	if !ok {
		return fmt.Errorf("asset not found in account")
	}

	holding.Frozen = cf.AssetFrozen
	return balances.PutAssetHolding(cf.FreezeAccount, cf.FreezeAsset, holding)
}
