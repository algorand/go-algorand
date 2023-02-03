package appliers

import (
	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/transactions"
	"github.com/algorand/go-algorand/data/transactions/logic"
	"github.com/algorand/go-algorand/ledger/apply"
)

// applierStateChanger can be extended to add in new interfaces to roundCowState.
// alternatively closures or recievers methods could attach this state such that it is invisible to the BlockEvaluator.
type ApplierStateChanger interface {
	apply.Balances
	apply.StateProofsApplier
}

// TransactionApplier is the interface used to apply updates from transactions to the balances.
// return values:
//   * txHandled - return true if the TransactionApplier handled the transaction. Multiple appliers handling the transaction is illegal.
type TransactionApplier func(params *ApplierParams) (txHandled bool, err error)
type ApplierParams struct {
	Tx       *transactions.Transaction
	Params   *config.ConsensusParams
	Specials *transactions.SpecialAddresses
	Ad       *transactions.ApplyData

	// apply.Balances is used for everything except state proofs, which uses apply.StateProofsApplier.
	StateChanger ApplierStateChanger

	// keyreg
	Round basics.Round

	// app call
	Gi         int
	EvalParams *logic.EvalParams

	// asset config, app call
	// ctr is the transaction counter
	Ctr uint64

	// StateProof
	Validate bool
	Generate bool
}
