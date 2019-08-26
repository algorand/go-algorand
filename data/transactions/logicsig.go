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

type logicBytecodeV1 []byte

func (lsl logicBytecodeV1) ToBeHashed() (protocol.HashID, []byte) {
	return protocol.Program, []byte(lsl)
}

// HashProgram takes program bytes and returns the Digest
// This Digest can be used as an Address for a logic controlled account.
func HashProgram(program []byte) crypto.Digest {
	pb := logicBytecodeV1(program)
	return crypto.HashObj(&pb)
}

// LogicSig contains logic for validating a transaction.
// LogicSig is signed by an account, allowing delegation of operations.
// OR
// LogicSig defines a contract account.
type LogicSig struct {
	_struct struct{} `codec:",omitempty,omitemptyarray"`

	// LogicSigLogic signed by Sig or Msig, OR hashed to be the Address of a contract account.
	Logic []byte `codec:"l"`

	Sig  crypto.Signature   `codec:"sig"`
	Msig crypto.MultisigSig `codec:"msig"`

	// Args are not signed, but checked by Logic
	Args [][]byte `codec:"arg"`
}

// Blank returns true if there is no content in this LogicSig
func (lsig *LogicSig) Blank() bool {
	return len(lsig.Logic) == 0
}

// LogicSigMaxProgramLength should move to consensus params
const LogicSigMaxProgramLength = 1000

// Verify checks that the signature is valid. It does not evaluate the logic.
func (lsig *LogicSig) Verify(txn *Transaction) error {
	if len(lsig.Logic) > LogicSigMaxProgramLength {
		return errors.New("LogicSig.Logic too long")
	}
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
		program := logicBytecodeV1(lsig.Logic)
		lhash := crypto.HashObj(&program)
		if crypto.Digest(txn.Sender) == lhash {
			return nil
		}
		return errors.New("LogicNot signed and not a Logic-only account")
	}
	if numSigs > 1 {
		return errors.New("LogicSig should only have one of Sig or Msig but has more than one")
	}

	if hasSig {
		program := logicBytecodeV1(lsig.Logic)
		if crypto.SignatureVerifier(txn.Src()).Verify(&program, lsig.Sig) {
			return nil
		}
		return errors.New("logic signature validation failed")
	}
	if hasMsig {
		program := logicBytecodeV1(lsig.Logic)
		if ok, _ := crypto.MultisigVerify(&program, crypto.Digest(txn.Src()), lsig.Msig); ok {
			return nil
		}
		return errors.New("logic multisig validation failed")
	}

	return errors.New("inconsistent internal state verifying LogicSig")
}
