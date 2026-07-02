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
	"fmt"

	"github.com/algorand/go-algorand/data/transactions"
)

// The PQ admission policies below layer API-only authorizer compliance checks
// on top of the shared transactions.PQSig validation.

// requirePQAuthorizerCompliant is the API-only admission check that the
// PQSig-derived authorizer address is PQ compliant. Consensus accepts any
// salt whose derived address matches the authorizer; the API boundary insists
// on compliant addresses so that accounts created through algod retain the
// post-quantum guarantee.
func requirePQAuthorizerCompliant(stxn transactions.SignedTxn) error {
	authorizer := stxn.PQsig.AuthorizerAddress()
	if !authorizer.IsPQCompliant() {
		return fmt.Errorf("pq signature authorizer address %s is not compliant", authorizer)
	}
	return nil
}

func enforcePQAuthorizerCompliance(txgroup []transactions.SignedTxn) error {
	for txnIdx, stxn := range txgroup {
		if stxn.PQsig.Blank() || len(stxn.PQsig.PublicKey) == 0 {
			continue
		}
		if err := requirePQAuthorizerCompliant(stxn); err != nil {
			return fmt.Errorf("transaction %d: %w", txnIdx, err)
		}
	}
	return nil
}
