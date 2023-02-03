package appliers

import (
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/ledger/apply"
	"github.com/algorand/go-algorand/protocol"
)

// Simple adapters wrapping the existing (sort of) pure functions.
// State passes between them via the StateChanger object (a.k.a. Balances).

func ApplyFee(params *ApplierParams) (bool, error) {
	return false, params.StateChanger.Move(params.Tx.Sender, params.Specials.FeeSink, params.Tx.Fee, &(params.Ad.SenderRewards), nil)
}

func ApplyRekey(params *ApplierParams) (bool, error) {
	return false, apply.Rekey(params.StateChanger, params.Tx)
}

func ApplyPayment(params *ApplierParams) (bool, error) {
	if params.Tx.Type != protocol.PaymentTx {
		return false, nil
	}
	return true, apply.Payment(params.Tx.PaymentTxnFields, params.Tx.Header, params.StateChanger, *params.Specials, params.Ad)
}

func ApplyKeyRegistration(params *ApplierParams) (bool, error) {
	if params.Tx.Type != protocol.KeyRegistrationTx {
		return false, nil
	}
	return true, apply.Keyreg(params.Tx.KeyregTxnFields, params.Tx.Header, params.StateChanger, *params.Specials, params.Ad, params.Round)
}

func ApplyAssetConfig(params *ApplierParams) (bool, error) {
	if params.Tx.Type != protocol.AssetConfigTx {
		return false, nil
	}
	return true, apply.AssetConfig(params.Tx.AssetConfigTxnFields, params.Tx.Header, params.StateChanger, *params.Specials, params.Ad, params.Ctr)
}

func ApplyAssetTransfer(params *ApplierParams) (bool, error) {
	if params.Tx.Type != protocol.AssetTransferTx {
		return false, nil
	}
	return true, apply.AssetTransfer(params.Tx.AssetTransferTxnFields, params.Tx.Header, params.StateChanger, *params.Specials, params.Ad)
}

func ApplyAssetFreeze(params *ApplierParams) (bool, error) {
	if params.Tx.Type != protocol.AssetFreezeTx {
		return false, nil
	}
	return true, apply.AssetFreeze(params.Tx.AssetFreezeTxnFields, params.Tx.Header, params.StateChanger, *params.Specials, params.Ad)
}

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

func ApplyAppThings(params *ApplierParams) (bool, error) {
	// Record first, so that details can all be used in logic evaluation, even
	// if cleared below. For example, `gaid`, introduced in v28 is now
	// implemented in terms of the AD fields introduced in v30.
	params.EvalParams.RecordAD(params.Gi, *params.Ad)

	return false, nil
}

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
