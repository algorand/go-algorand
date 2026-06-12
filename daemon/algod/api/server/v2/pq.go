// Copyright (C) 2019-2026 Algorand Foundation Ltd.
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

package v2

import (
	"errors"
	"fmt"

	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/data/transactions"
)

func pqSignatureHasPlaceholder(stxn transactions.SignedTxn) bool {
	return stxn.Sig.Blank() && stxn.Msig.Blank() && stxn.Lsig.Blank() &&
		!stxn.PQSig.Blank() && len(stxn.PQSig.Signature) == 0
}

func validatePQSignatureForAPI(proto config.ConsensusParams, stxn transactions.SignedTxn, allowEmptySignature bool, deferPlaceholderEnvelope bool) error {
	if stxn.PQSig.Blank() {
		return nil
	}

	if !(deferPlaceholderEnvelope && allowEmptySignature && pqSignatureHasPlaceholder(stxn)) {
		if err := stxn.PQSig.ValidateEnvelope(proto, stxn.Authorizer()); err != nil {
			return err
		}
	}

	if len(stxn.PQSig.Signature) == 0 && !allowEmptySignature {
		return errors.New("pq signature is empty")
	}

	authorizer := stxn.PQSig.AuthorizerAddress()
	if !authorizer.IsPQCompliant() {
		return fmt.Errorf("pq signature authorizer address %s is not compliant", authorizer)
	}

	return nil
}

func validatePQSignaturesForAPI(proto config.ConsensusParams, txgroup []transactions.SignedTxn, allowEmptySignature bool, deferPlaceholderEnvelope bool) error {
	for txnIdx, stxn := range txgroup {
		if err := validatePQSignatureForAPI(proto, stxn, allowEmptySignature, deferPlaceholderEnvelope); err != nil {
			return fmt.Errorf("transaction %d: %w", txnIdx, err)
		}
	}
	return nil
}
