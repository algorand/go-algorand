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

	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/transactions"
	"github.com/algorand/go-algorand/protocol"
)

func validatePQSignatureForAPI(stxn transactions.SignedTxn, proto config.ConsensusParams) error {
	if stxn.PQSig.Blank() {
		return nil
	}

	switch stxn.PQSig.Scheme {
	case protocol.PQSchemeFalcon1024:
		if !proto.EnablePQSchemeFalcon1024 {
			return fmt.Errorf("pq signature scheme not enabled")
		}
	default:
		return basics.ErrPQSchemeNotSupported
	}

	if err := basics.ValidatePQPublicKey(stxn.PQSig.Scheme, stxn.PQSig.PublicKey); err != nil {
		return fmt.Errorf("pq signature public key invalid: %w", err)
	}

	authorizer := stxn.PQSig.AuthorizerAddress()
	if !basics.IsPQAddressCompliant(authorizer) {
		return fmt.Errorf("pq signature authorizer address %s is not compliant", authorizer)
	}

	return nil
}

func validatePQSignaturesForAPI(txgroups [][]transactions.SignedTxn, proto config.ConsensusParams) error {
	for groupIdx, txgroup := range txgroups {
		for txnIdx, stxn := range txgroup {
			if err := validatePQSignatureForAPI(stxn, proto); err != nil {
				return fmt.Errorf("transaction group %d transaction %d: %w", groupIdx, txnIdx, err)
			}
		}
	}
	return nil
}
