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

package ledgercore

import (
	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/data/basics"
)

// StateProofVerificationData represents the data provided by the ledger to verify a state proof transaction.
type StateProofVerificationData struct {
	_struct struct{} `codec:",omitempty,omitemptyarray"`

	// TargetStateProofRound is the last attested round of the state proof verified using this data.
	TargetStateProofRound basics.Round `codec:"spround"`

	// VotersCommitment is the vector commitment root of the top N accounts to sign the next state proof.
	VotersCommitment crypto.GenericDigest `codec:"vc"`

	// ProvenWeight is the total amount of stake attesting to the next state proof.
	ProvenWeight basics.MicroAlgos `codec:"pw"`
}
