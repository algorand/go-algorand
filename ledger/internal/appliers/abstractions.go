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
	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/transactions"
	"github.com/algorand/go-algorand/data/transactions/logic"
	"github.com/algorand/go-algorand/ledger/apply"
)

// ApplierStateChanger can be extended to add in new interfaces to roundCowState.
// alternatively closures or receivers methods could attach this state such that it is invisible to the BlockEvaluator.
type ApplierStateChanger interface {
	apply.Balances
	apply.StateProofsApplier
}

// TransactionApplier is the interface used to apply updates from transactions to the balances.
// return values:
//   * txHandled - return true if the TransactionApplier handled the transaction. Multiple appliers handling the transaction is illegal.
type TransactionApplier func(params *ApplierParams) (txHandled bool, err error)

// ApplierParams is a parameter object to the TransactionApplier.
// I'm not really happy about this, it would be nice to slim it down.
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
