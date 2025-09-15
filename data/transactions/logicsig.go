// Copyright (C) 2019-2025 Algorand, Inc.
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
	"bytes"

	"github.com/algorand/go-algorand/crypto"
)

// EvalMaxArgs is the maximum number of arguments to an LSig
const EvalMaxArgs = 255

// MaxLogicSigArgSize is the maximum size of an argument to an LSig
// We use 4096 to match the maximum size of a TEAL value
// (as defined in `const maxStringSize` in package logic)
const MaxLogicSigArgSize = 4096

// LogicSig contains logic for validating a transaction.
// LogicSig is signed by an account, allowing delegation of operations.
// OR
// LogicSig defines a contract account.
type LogicSig struct {
	_struct struct{} `codec:",omitempty,omitemptyarray"`

	// Logic signed by Sig or Msig, OR hashed to be the Address of an account.
	Logic []byte `codec:"l,allocbound=bounds.MaxLogicSigMaxSize"`

	Sig   crypto.Signature   `codec:"sig"`
	Msig  crypto.MultisigSig `codec:"msig"`
	LMsig crypto.MultisigSig `codec:"lmsig"`

	// Args are not signed, but checked by Logic
	Args [][]byte `codec:"arg,allocbound=EvalMaxArgs,allocbound=MaxLogicSigArgSize,maxtotalbytes=bounds.MaxLogicSigMaxSize"`
}

// Blank returns true if there is no content in this LogicSig
func (lsig *LogicSig) Blank() bool {
	return len(lsig.Logic) == 0
}

// Len returns the length of Logic plus the length of the Args
// This is limited by config.ConsensusParams.LogicSigMaxSize
func (lsig *LogicSig) Len() int {
	lsiglen := len(lsig.Logic)
	for _, arg := range lsig.Args {
		lsiglen += len(arg)
	}
	return lsiglen
}

// Equal returns true if both LogicSig are equivalent.
//
// Out of paranoia, Equal distinguishes zero-length byte slices
// from byte slice-typed nil values as they may have subtly
// different behaviors within the evaluation of a LogicSig,
// due to differences in msgpack encoding behavior.
func (lsig *LogicSig) Equal(b *LogicSig) bool {
	sigs := lsig.Sig == b.Sig && lsig.Msig.Equal(b.Msig) && lsig.LMsig.Equal(b.LMsig)
	if !sigs {
		return false
	}
	if !safeSliceCheck(lsig.Logic, b.Logic) {
		return false
	}

	if len(lsig.Args) != len(b.Args) {
		return false
	}
	for i := range lsig.Args {
		if !safeSliceCheck(lsig.Args[i], b.Args[i]) {
			return false
		}
	}
	return true
}

func safeSliceCheck(a, b []byte) bool {
	if a != nil && b != nil {
		return bytes.Equal(a, b)
	}
	return a == nil && b == nil
}
