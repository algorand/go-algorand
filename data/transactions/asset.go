// Copyright (C) 2019 Algorand, Inc.
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

package transactions

import (
	"fmt"

	"github.com/algorand/go-algorand/data/basics"
)

// AssetConfigTxnFields captures the fields used for asset
// allocation, re-configuration, and destruction.
type AssetConfigTxnFields struct {
	_struct struct{} `codec:",omitempty,omitemptyarray"`

	// ConfigAsset is the asset being configured or destroyed.
	// A zero value (including the creator address) means allocation.
	ConfigAsset basics.AssetID `codec:"caid"`

	// AssetParams are the parameters for the asset being
	// created or re-configured.  A zero value means destruction.
	AssetParams basics.AssetParams `codec:"apar"`
}

// AssetTransferTxnFields captures the fields used for asset transfers.
type AssetTransferTxnFields struct {
	_struct struct{} `codec:",omitempty,omitemptyarray"`

	XferAsset basics.AssetID `codec:"xaid"`

	// AssetAmount is the amount of asset to transfer.
	// A zero amount transferred to self allocates that asset
	// in the account's Assets map.
	AssetAmount uint64 `codec:"aamt"`

	// AssetSender is the sender of the transfer.  If this is not
	// a zero value, the real transaction sender must be the Clawback
	// address from the AssetParams.  If this is the zero value,
	// the asset is sent from the transaction's Sender.
	AssetSender basics.Address `codec:"asnd"`

	// AssetReceiver is the recipient of the transfer.
	AssetReceiver basics.Address `codec:"arcv"`

	// AssetCloseTo indicates that the asset should be removed
	// from the account's Assets map, and specifies where the remaining
	// asset holdings should be transferred.  It's always valid to transfer
	// remaining asset holdings to the AssetID account.
	AssetCloseTo basics.Address `codec:"aclose"`
}

// AssetFreezeTxnFields captures the fields used for freezing asset slots.
type AssetFreezeTxnFields struct {
	_struct struct{} `codec:",omitempty,omitemptyarray"`

	// FreezeAccount is the address of the account whose asset
	// slot is being frozen or un-frozen.
	FreezeAccount basics.Address `codec:"fadd"`

	// FreezeAsset is the asset ID being frozen or un-frozen.
	FreezeAsset basics.AssetID `codec:"faid"`

	// AssetFrozen is the new frozen value.
	AssetFrozen bool `codec:"afrz"`
}

func clone(m map[basics.AssetID]basics.AssetHolding) map[basics.AssetID]basics.AssetHolding {
	res := make(map[basics.AssetID]basics.AssetHolding)
	for id, val := range m {
		res[id] = val
	}
	return res
}

func cloneParams(m map[uint64]basics.AssetParams) map[uint64]basics.AssetParams {
	res := make(map[uint64]basics.AssetParams)
	for id, val := range m {
		res[id] = val
	}
	return res
}

func getParams(balances Balances, cid basics.AssetID) (basics.AssetParams, error) {
	creator, err := balances.Get(cid.Creator, false)
	if err != nil {
		return basics.AssetParams{}, err
	}

	curr, ok := creator.AssetParams[cid.Index]
	if !ok {
		return basics.AssetParams{}, fmt.Errorf("asset index %d not found in account %v", cid.Index, cid.Creator)
	}

	return curr, nil
}

func (cc AssetConfigTxnFields) apply(header Header, balances Balances, spec SpecialAddresses, ad *ApplyData, txnCounter uint64) error {
	if cc.ConfigAsset == (basics.AssetID{}) {
		// Allocating an asset.
		record, err := balances.Get(header.Sender, false)
		if err != nil {
			return err
		}
		record.Assets = clone(record.Assets)
		record.AssetParams = cloneParams(record.AssetParams)

		// Ensure index is never zero
		newidx := txnCounter + 1

		// Sanity check that there isn't an asset with this counter value.
		_, present := record.AssetParams[newidx]
		if present {
			return fmt.Errorf("already found asset with index %d", newidx)
		}

		cid := basics.AssetID{
			Creator: header.Sender,
			Index:   newidx,
		}

		record.AssetParams[cid.Index] = cc.AssetParams
		record.Assets[cid] = basics.AssetHolding{
			Amount: cc.AssetParams.Total,
		}

		if len(record.Assets) > balances.ConsensusParams().MaxAssetsPerAccount {
			return fmt.Errorf("too many assets in account: %d > %d", len(record.Assets), balances.ConsensusParams().MaxAssetsPerAccount)
		}

		return balances.Put(record)
	}

	// Re-configuration and destroying must be done by the manager key.
	params, err := getParams(balances, cc.ConfigAsset)
	if err != nil {
		return err
	}

	if header.Sender != params.Manager {
		return fmt.Errorf("transaction issued by %v, not manager key %v", header.Sender, params.Manager)
	}

	record, err := balances.Get(cc.ConfigAsset.Creator, false)
	if err != nil {
		return err
	}

	record.Assets = clone(record.Assets)
	record.AssetParams = cloneParams(record.AssetParams)

	if cc.AssetParams == (basics.AssetParams{}) {
		// Destroying an asset.  The creator account must hold
		// the entire outstanding asset amount.
		if record.Assets[cc.ConfigAsset].Amount != params.Total {
			return fmt.Errorf("cannot destroy asset: creator is holding only %d/%d", record.Assets[cc.ConfigAsset].Amount, params.Total)
		}

		delete(record.Assets, cc.ConfigAsset)
		delete(record.AssetParams, cc.ConfigAsset.Index)
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

		record.AssetParams[cc.ConfigAsset.Index] = params
	}

	return balances.Put(record)
}

func takeOut(balances Balances, addr basics.Address, asset basics.AssetID, amount uint64, bypassFreeze bool) error {
	if amount == 0 {
		return nil
	}

	snd, err := balances.Get(addr, false)
	if err != nil {
		return err
	}

	snd.Assets = clone(snd.Assets)
	sndHolding, ok := snd.Assets[asset]
	if !ok {
		return fmt.Errorf("asset %v missing from %v", asset, addr)
	}

	if sndHolding.Frozen && !bypassFreeze {
		return fmt.Errorf("asset %v frozen in %v", asset, addr)
	}

	var overflowed bool
	sndHolding.Amount, overflowed = basics.OSub(sndHolding.Amount, amount)
	if overflowed {
		return fmt.Errorf("underflow on subtracting %d from sender amount %d", amount, sndHolding.Amount)
	}

	snd.Assets[asset] = sndHolding
	return balances.Put(snd)
}

func putIn(balances Balances, addr basics.Address, asset basics.AssetID, amount uint64, bypassFreeze bool) error {
	if amount == 0 {
		return nil
	}

	rcv, err := balances.Get(addr, false)
	if err != nil {
		return err
	}

	rcv.Assets = clone(rcv.Assets)
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
	return balances.Put(rcv)
}

func (ct AssetTransferTxnFields) apply(header Header, balances Balances, spec SpecialAddresses, ad *ApplyData) error {
	// Default to sending from the transaction sender's account.
	source := header.Sender
	clawback := false

	if !ct.AssetSender.IsZero() {
		// Clawback transaction.  Check that the transaction sender
		// is the Clawback address for this asset.
		params, err := getParams(balances, ct.XferAsset)
		if err != nil {
			return err
		}

		if header.Sender != params.Clawback {
			return fmt.Errorf("clawback not allowed: sender %v != clawback %v", header.Sender, params.Clawback)
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

		snd.Assets = clone(snd.Assets)
		sndHolding, ok := snd.Assets[ct.XferAsset]
		if !ok {
			// Initialize holding with default Frozen value.
			params, err := getParams(balances, ct.XferAsset)
			if err != nil {
				return err
			}

			sndHolding.Frozen = params.DefaultFrozen
			snd.Assets[ct.XferAsset] = sndHolding

			if len(snd.Assets) > balances.ConsensusParams().MaxAssetsPerAccount {
				return fmt.Errorf("too many assets in account: %d > %d", len(snd.Assets), balances.ConsensusParams().MaxAssetsPerAccount)
			}

			err = balances.Put(snd)
			if err != nil {
				return err
			}
		}
	}

	// Actually move the asset.  Zero transfers return right away
	// without looking up accounts, so it's fine to have a zero transfer
	// to an all-zero address (e.g., when the only meaningful part of
	// the transaction is the close-to address).
	err := takeOut(balances, source, ct.XferAsset, ct.AssetAmount, clawback)
	if err != nil {
		return err
	}

	err = putIn(balances, ct.AssetReceiver, ct.XferAsset, ct.AssetAmount, clawback)
	if err != nil {
		return err
	}

	if ct.AssetCloseTo != (basics.Address{}) {
		// Cannot close asset ID allocated by this account; must use destroy.
		if ct.XferAsset.Creator == source {
			return fmt.Errorf("cannot close asset ID in allocating account")
		}

		// Cannot close by clawback.
		if clawback {
			return fmt.Errorf("cannot close asset by clawback")
		}

		// Figure out how much balance to move.
		snd, err := balances.Get(source, false)
		if err != nil {
			return err
		}

		sndHolding, ok := snd.Assets[ct.XferAsset]
		if !ok {
			return fmt.Errorf("asset %v not present in account %v", ct.XferAsset, source)
		}

		// Move the balance out.
		err = takeOut(balances, source, ct.XferAsset, sndHolding.Amount, clawback)
		if err != nil {
			return err
		}

		err = putIn(balances, ct.AssetCloseTo, ct.XferAsset, sndHolding.Amount, clawback)
		if err != nil {
			return err
		}

		// Delete the slot from the account.
		snd, err = balances.Get(source, false)
		if err != nil {
			return err
		}

		snd.Assets = clone(snd.Assets)
		sndHolding = snd.Assets[ct.XferAsset]
		if sndHolding.Amount != 0 {
			return fmt.Errorf("asset %v not zero (%d) after closing", ct.XferAsset, sndHolding.Amount)
		}

		delete(snd.Assets, ct.XferAsset)
		err = balances.Put(snd)
		if err != nil {
			return err
		}
	}

	return nil
}

func (cf AssetFreezeTxnFields) apply(header Header, balances Balances, spec SpecialAddresses, ad *ApplyData) error {
	// Only the Freeze address can change the freeze value.
	params, err := getParams(balances, cf.FreezeAsset)
	if err != nil {
		return err
	}

	if header.Sender != params.Freeze {
		return fmt.Errorf("freeze not allowed: sender %v != freeze %v", header.Sender, params.Freeze)
	}

	// Get the account to be frozen/unfrozen.
	record, err := balances.Get(cf.FreezeAccount, false)
	if err != nil {
		return err
	}
	record.Assets = clone(record.Assets)

	holding, ok := record.Assets[cf.FreezeAsset]
	if !ok {
		return fmt.Errorf("asset not found in account")
	}

	holding.Frozen = cf.AssetFrozen
	record.Assets[cf.FreezeAsset] = holding
	return balances.Put(record)
}
