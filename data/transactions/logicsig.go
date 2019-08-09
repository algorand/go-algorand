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
	"errors"

	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/protocol"
)

// LogicSigLogic is a trivial wrapper object to organize hashing/signing the contained Logic expression
type LogicSigLogic struct {
	_struct struct{} `codec:",omitempty,omitemptyarray"`

	// Logic is an expression in a TBD language.
	Logic []byte `codec:"l"`

	// Future implementations could be "l2":[]byte, etc.
}

// LogicSig contains logic for validating a transaction.
// LogicSig is signed by an account, allowing delegation of operations.
// OR
// LogicSig defines a contract account.
type LogicSig struct {
	_struct struct{} `codec:",omitempty,omitemptyarray"`

	// LogicSigLogic signed by Sig or Msig, OR hashed to be the Address of a contract account.
	Logic LogicSigLogic `codec:"l"`

	Sig  crypto.Signature   `codec:"sig"`
	Msig crypto.MultisigSig `codec:"msig"`

	// Args are not signed, but checked by Logic
	Args [][]byte `codec:"arg"`
}

// Blank returns true if there is no content in this LogicSig
func (lsig *LogicSig) Blank() bool {
	return len(lsig.Logic.Logic) == 0
}

// ToBeHashed implements our crypto.Hashable interface
func (lsl *LogicSigLogic) ToBeHashed() (protocol.HashID, []byte) {
	return protocol.Logic, protocol.Encode(lsl)
}

// Verify checks that the signature is valid. It does not evaluate the logic.
func (lsig *LogicSig) Verify(txn *Transaction) error {
	hasSig := false
	hasMsig := false
	numSigs := 0
	if lsig.Sig != (crypto.Signature{}) {
		hasSig = true
		numSigs++
	}
	if !lsig.Msig.Blank() {
		hasMsig = true
		numSigs++
	}
	if numSigs == 0 {
		// if the txn.Sender == hash(Logic) then this is a (potentially) valid operation on a contract-only account
		lhash := crypto.HashObj(&lsig.Logic)
		if crypto.Digest(txn.Sender) == lhash {
			return nil
		}
		return errors.New("LogicNot signed and not a Logic-only account")
	}
	if numSigs > 1 {
		return errors.New("LogicSig should only have one of Sig or Msig but has more than one")
	}

	if hasSig {
		if crypto.SignatureVerifier(txn.Src()).Verify(&lsig.Logic, lsig.Sig) {
			return nil
		}
		return errors.New("logic signature validation failed")
	}
	if hasMsig {
		if ok, _ := crypto.MultisigVerify(&lsig.Logic, crypto.Digest(txn.Src()), lsig.Msig); ok {
			return nil
		}
		return errors.New("logic multisig validation failed")
	}

	return errors.New("inconsistent internal state verifying LogicSig")
}
