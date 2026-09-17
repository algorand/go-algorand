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

package transactions

import (
	"bytes"
	"errors"

	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/protocol"
)

// EvalMaxArgs is the maximum number of arguments to an LSig
const EvalMaxArgs = 255

// MaxLogicSigArgSize is the maximum size of an argument to an LSig
const MaxLogicSigArgSize = config.MaxAVMBytesSize

// LogicSigArgs are arguments to a program that is not carried in a LogicSig,
// which is how an ls-scheme PQSig holds the arguments to its own program. They
// are the same thing as LogicSig.Args, in a place that has no room for a
// structured field, so they carry the same bounds. The total encoded size is
// bounded by whatever holds them.
//
//msgp:allocbound LogicSigArgs EvalMaxArgs,MaxLogicSigArgSize
type LogicSigArgs [][]byte

// errLogicSigArgsNotCanonical is returned for arguments that decode correctly
// but were not encoded the way EncodeLogicSigArgs would encode them.
var errLogicSigArgsNotCanonical = errors.New("logicsig args are not canonically encoded")

// EncodeLogicSigArgs encodes program arguments for carrying somewhere that has
// only room for bytes. No arguments encode to no bytes, so that "absent" and
// "present but empty" have one representation between them rather than two.
func EncodeLogicSigArgs(args LogicSigArgs) []byte {
	if len(args) == 0 {
		return nil
	}
	return protocol.Encode(args)
}

// DecodeLogicSigArgs decodes program arguments encoded by EncodeLogicSigArgs.
// It insists on that exact encoding, by re-encoding what it decoded and
// requiring the bytes back. Nothing signs these bytes, so without that rule one
// set of arguments would have many equally valid wire forms, differing in how
// msgpack spelled the lengths.
func DecodeLogicSigArgs(encoded []byte) (LogicSigArgs, error) {
	if len(encoded) == 0 {
		return nil, nil
	}
	var args LogicSigArgs
	if err := protocol.Decode(encoded, &args); err != nil {
		return nil, err
	}
	if !bytes.Equal(EncodeLogicSigArgs(args), encoded) {
		return nil, errLogicSigArgsNotCanonical
	}
	return args, nil
}

// Len returns the total size of the arguments, which is what the LogicSig size
// pool measures. It does not count the bytes msgpack spends framing them.
func (args LogicSigArgs) Len() int {
	size := 0
	for _, arg := range args {
		size += len(arg)
	}
	return size
}

// LogicSig contains logic for validating a transaction.
// LogicSig is signed by an account, allowing delegation of operations.
// OR
// LogicSig defines a contract account.
type LogicSig struct {
	_struct struct{} `codec:",omitempty,omitemptyarray"`

	// Logic signed by one of the delegation signature categories below, OR
	// hashed to be the Address of an account.
	Logic []byte `codec:"l,allocbound=bounds.MaxLogicSigMaxSize"`

	Sig   crypto.Signature   `codec:"sig"`
	Msig  crypto.MultisigSig `codec:"msig"`
	LMsig crypto.MultisigSig `codec:"lmsig"`
	PQsig PQSig              `codec:"pqsig"`

	// Args are not signed, but checked by Logic
	Args [][]byte `codec:"arg,allocbound=EvalMaxArgs,allocbound=MaxLogicSigArgSize,maxtotalbytes=bounds.MaxLogicSigMaxSize"`
}

// Blank returns true if the LogicSig is entirely empty.
func (lsig *LogicSig) Blank() bool {
	return len(lsig.Logic) == 0 && len(lsig.Args) == 0 &&
		lsig.Sig.Blank() && lsig.Msig.Blank() && lsig.LMsig.Blank() && lsig.PQsig.Blank()
}

// HasProgram returns true if the LogicSig carries a program.
func (lsig *LogicSig) HasProgram() bool {
	return len(lsig.Logic) != 0
}

// Len returns the total byte length of a logicSig program and arguments
func (lsig *LogicSig) Len() int {
	lsiglen := len(lsig.Logic)
	return lsiglen + lsig.ArgsLen()
}

// ArgsLen returns the total byte length of the LogicSig arguments
func (lsig *LogicSig) ArgsLen() int {
	argsLen := 0
	for _, arg := range lsig.Args {
		argsLen += len(arg)
	}
	return argsLen
}

// Equal returns true if both LogicSig are equivalent.
//
// Out of paranoia, Equal distinguishes zero-length byte slices
// from byte slice-typed nil values as they may have subtly
// different behaviors within the evaluation of a LogicSig,
// due to differences in msgpack encoding behavior.
func (lsig *LogicSig) Equal(b *LogicSig) bool {
	sigs := lsig.Sig == b.Sig &&
		lsig.Msig.Equal(b.Msig) &&
		lsig.LMsig.Equal(b.LMsig) &&
		lsig.PQsig.Equal(b.PQsig)
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
