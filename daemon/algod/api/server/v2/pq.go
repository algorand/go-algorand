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

// The PQ admission policies below layer API-only checks on top of the shared
// transactions.PQSig envelope validation: the submit path requires a complete
// proof (valid envelope, non-empty signature), the simulate path additionally
// understands placeholder proofs, and both require the authorizer address to
// be PQ compliant, which consensus deliberately does not enforce.

// isPlaceholderPQSig reports whether stxn carries a placeholder PQSig:
// a non-blank PQ envelope with empty signature bytes and no other signature
// category set.
func isPlaceholderPQSig(stxn transactions.SignedTxn) bool {
	return stxn.Sig.Blank() && stxn.Msig.Blank() && stxn.Lsig.Blank() &&
		!stxn.PQSig.Blank() && len(stxn.PQSig.Signature) == 0
}

// requirePQAuthorizerCompliant is the API-only admission check that the
// PQSig-derived authorizer address is PQ compliant. Consensus accepts any
// salt whose derived address matches the authorizer; the API boundary insists
// on compliant addresses so that accounts created through algod retain the
// post-quantum guarantee.
func requirePQAuthorizerCompliant(stxn transactions.SignedTxn) error {
	authorizer := stxn.PQSig.AuthorizerAddress()
	if !authorizer.IsPQCompliant() {
		return fmt.Errorf("pq signature authorizer address %s is not compliant", authorizer)
	}
	return nil
}

// enforcePQSubmitPolicy enforces the strict PQ admission policy for
// transaction submission: every non-blank PQSig must be a structurally
// complete proof (valid envelope, non-empty signature) with a PQ-compliant
// authorizer address. Cryptographic signature verification is left to the
// transaction verification pipeline.
func enforcePQSubmitPolicy(proto config.ConsensusParams, txgroup []transactions.SignedTxn) error {
	for txnIdx, stxn := range txgroup {
		if err := checkPQSubmitPolicy(proto, stxn); err != nil {
			return fmt.Errorf("transaction %d: %w", txnIdx, err)
		}
	}
	return nil
}

func checkPQSubmitPolicy(proto config.ConsensusParams, stxn transactions.SignedTxn) error {
	if stxn.PQSig.Blank() {
		return nil
	}
	if err := stxn.PQSig.ValidateEnvelope(proto, stxn.Authorizer()); err != nil {
		return err
	}
	if len(stxn.PQSig.Signature) == 0 {
		return errors.New("pq signature is empty") // matches the consensus rejection text
	}
	return requirePQAuthorizerCompliant(stxn)
}

// enforcePQSimulatePolicy enforces the PQ admission policy for
// simulation. allowEmptySignatures and fixSigners mirror the simulate request
// fields:
//   - allowEmptySignatures permits a placeholder PQSig (an envelope with empty
//     signature bytes); the simulator substitutes a proxy signature.
//   - fixSigners defers placeholder envelope validation to the simulator: the
//     derived-authorizer check cannot pass before the simulator rewrites
//     AuthAddr, after which it re-validates the envelope. The compliance check
//     still runs here because it does not depend on the authorizer match.
//
// Without allowEmptySignatures, the simulate policy is the submit policy (a
// fixSigners-only request is rejected later by the simulator, which requires
// allowEmptySignatures).
func enforcePQSimulatePolicy(proto config.ConsensusParams, txgroup []transactions.SignedTxn, allowEmptySignatures bool, fixSigners bool) error {
	for txnIdx, stxn := range txgroup {
		if err := checkPQSimulatePolicy(proto, stxn, allowEmptySignatures, fixSigners); err != nil {
			return fmt.Errorf("transaction %d: %w", txnIdx, err)
		}
	}
	return nil
}

func checkPQSimulatePolicy(proto config.ConsensusParams, stxn transactions.SignedTxn, allowEmptySignatures bool, fixSigners bool) error {
	if stxn.PQSig.Blank() {
		return nil
	}
	if !allowEmptySignatures {
		return checkPQSubmitPolicy(proto, stxn)
	}
	if !(fixSigners && isPlaceholderPQSig(stxn)) {
		if err := stxn.PQSig.ValidateEnvelope(proto, stxn.Authorizer()); err != nil {
			return err
		}
	}
	return requirePQAuthorizerCompliant(stxn)
}
