// Copyright (C) 2019-2023 Algorand, Inc.
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

package appliers

import (
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/ledger/apply"
	"github.com/algorand/go-algorand/protocol"
)

// Simple adapters wrapping the existing (sort of) pure functions.
// State passes between them via the StateChanger object (a.k.a. Balances).

// ApplyFee handles the transaction fee.
func ApplyFee(params *ApplierParams) (bool, error) {
	return false, params.StateChanger.Move(params.Tx.Sender, params.Specials.FeeSink, params.Tx.Fee, &(params.Ad.SenderRewards), nil)
}

// ApplyRekey handles rekeying.
func ApplyRekey(params *ApplierParams) (bool, error) {
	return false, apply.Rekey(params.StateChanger, params.Tx)
}

// ApplyPayment handles a payment transaction.
func ApplyPayment(params *ApplierParams) (bool, error) {
	if params.Tx.Type != protocol.PaymentTx {
		return false, nil
	}
	return true, apply.Payment(params.Tx.PaymentTxnFields, params.Tx.Header, params.StateChanger, *params.Specials, params.Ad)
}

// ApplyKeyRegistration handles a key registration transaction.
func ApplyKeyRegistration(params *ApplierParams) (bool, error) {
	if params.Tx.Type != protocol.KeyRegistrationTx {
		return false, nil
	}
	return true, apply.Keyreg(params.Tx.KeyregTxnFields, params.Tx.Header, params.StateChanger, *params.Specials, params.Ad, params.Round)
}

// ApplyAssetConfig handles an asset config transaction.
func ApplyAssetConfig(params *ApplierParams) (bool, error) {
	if params.Tx.Type != protocol.AssetConfigTx {
		return false, nil
	}
	return true, apply.AssetConfig(params.Tx.AssetConfigTxnFields, params.Tx.Header, params.StateChanger, *params.Specials, params.Ad, params.Ctr)
}

// ApplyAssetTransfer handles an asset transfer transaction.
func ApplyAssetTransfer(params *ApplierParams) (bool, error) {
	if params.Tx.Type != protocol.AssetTransferTx {
		return false, nil
	}
	return true, apply.AssetTransfer(params.Tx.AssetTransferTxnFields, params.Tx.Header, params.StateChanger, *params.Specials, params.Ad)
}

// ApplyAssetFreeze handles an asset freeze transaction.
func ApplyAssetFreeze(params *ApplierParams) (bool, error) {
	if params.Tx.Type != protocol.AssetFreezeTx {
		return false, nil
	}
	return true, apply.AssetFreeze(params.Tx.AssetFreezeTxnFields, params.Tx.Header, params.StateChanger, *params.Specials, params.Ad)
}

// ApplyApplicationCall handles an application call transaction.
func ApplyApplicationCall(params *ApplierParams) (bool, error) {
	if params.Tx.Type != protocol.ApplicationCallTx {
		return false, nil
	}
	return true, apply.ApplicationCall(params.Tx.ApplicationCallTxnFields, params.Tx.Header, params.StateChanger, params.Ad, params.Gi, params.EvalParams, params.Ctr)
}

// ApplyStateProof is attached to the block evaluator for the validate/generate fields. This pattern is another way to
// pass state instead of using pure functions.
func ApplyStateProof(params *ApplierParams) (bool, error) {
	if params.Tx.Type != protocol.StateProofTx {
		return false, nil
	}

	// in case of a StateProofTx transaction, we want to "apply" it only in validate or generate mode. This will deviate the cow's StateProofNextRound depending on
	// whether we're in validate/generate mode or not, however - given that this variable is only being used in these modes, it would be safe.
	// The reason for making this into an exception is that during initialization time, the accounts update is "converting" the recent 320 blocks into deltas to
	// be stored in memory. These deltas don't care about the state proofs, and so we can improve the node load time. Additionally, it save us from
	// performing the validation during catchup, which is another performance boost.
	if !(params.Validate || params.Generate) {
		// return true because even though this is a no-op, it's still considered "handled"
		return true, nil
	}

	return true, apply.StateProof(params.Tx.StateProofTxnFields, params.Tx.Header.FirstValid, params.StateChanger, params.Validate)
}

// ApplyAppThings does some sort of app things.
func ApplyAppThings(params *ApplierParams) (bool, error) {
	// Record first, so that details can all be used in logic evaluation, even
	// if cleared below. For example, `gaid`, introduced in v28 is now
	// implemented in terms of the AD fields introduced in v30.
	params.EvalParams.RecordAD(params.Gi, *params.Ad)

	return false, nil
}

// ApplyDisableRewards makes sure rewards are not accidentally set.
// You could imagine conditionally adding this to the list of middlewards instead of checking the protocol.
func ApplyDisableRewards(params *ApplierParams) (bool, error) {
	// If the protocol does not support rewards in ApplyData,
	// clear them out.
	if !params.Params.RewardsInApplyData {
		params.Ad.SenderRewards = basics.MicroAlgos{}
		params.Ad.ReceiverRewards = basics.MicroAlgos{}
		params.Ad.CloseRewards = basics.MicroAlgos{}
	}

	return false, nil
}

// ApplyInnerTxnThing clears out IDs for some reason.
// You could imagine conditionally adding this to the list of middlewards instead of checking the protocol.
func ApplyInnerTxnThing(params *ApplierParams) (bool, error) {
	// No separate config for activating these AD fields because inner
	// transactions require their presence, so the consensus update to add
	// inners also stores these IDs.
	if params.Params.MaxInnerTransactions == 0 {
		params.Ad.ApplicationID = 0
		params.Ad.ConfigAsset = 0
	}

	return false, nil
}
