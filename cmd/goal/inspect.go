// Copyright (C) 2019-2021 Algorand, Inc.
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

package main

import (
	"fmt"
	"reflect"

	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/transactions"
	"github.com/algorand/go-algorand/data/transactions/logic"
	"github.com/algorand/go-algorand/protocol"
)

// inspectSignedTxn is isomorphic to SignedTxn but uses different
// types to print public keys using algorand's address format
// (base32 + checksum) in JSON, instead of the default base64.
type inspectSignedTxn struct {
	_struct struct{} `codec:",omitempty,omitemptyarray"`

	Sig      crypto.Signature         `codec:"sig"`
	Msig     inspectMultisigSig       `codec:"msig"`
	Lsig     inspectLogicSig          `codec:"lsig"`
	Txn      transactions.Transaction `codec:"txn"`
	AuthAddr basics.Address           `codec:"sgnr"`
}

// inspectMultisigSig is isomorphic to MultisigSig but uses different
// types to print public keys using algorand's address format in JSON.
type inspectMultisigSig struct {
	_struct struct{} `codec:",omitempty,omitemptyarray"`

	Version   uint8                   `codec:"v"`
	Threshold uint8                   `codec:"thr"`
	Subsigs   []inspectMultisigSubsig `codec:"subsig"`
}

// inspectMultisigSig is isomorphic to MultisigSig but uses different
// types to print public keys using algorand's address format in JSON.
type inspectMultisigSubsig struct {
	_struct struct{} `codec:",omitempty,omitemptyarray"`

	Key basics.Address   `codec:"pk"`
	Sig crypto.Signature `codec:"s"`
}

// similar to data/transactions/logicsig.go LogicSig but uses types
// that format better as JSON.
type inspectLogicSig struct {
	_struct struct{} `codec:",omitempty,omitemptyarray"`

	// Logic signed by Sig or Msig, OR hashed to be the Address of an account.
	Logic inspectProgram `codec:"l"`

	Sig  crypto.Signature   `codec:"sig"`
	Msig inspectMultisigSig `codec:"msig"`

	// Args are not signed, but checked by Logic
	Args [][]byte `codec:"arg"`
}

type inspectProgram []byte

func (prog inspectProgram) String() string {
	text, err := logic.Disassemble([]byte(prog))
	if err != nil {
		return err.Error()
	}
	return text
}

func (prog inspectProgram) GoString() string {
	return prog.String()
}

func (prog inspectProgram) MarshalText() ([]byte, error) {
	text, err := logic.Disassemble([]byte(prog))
	return []byte(text), err
}

func (prog *inspectProgram) UnmarshalText(text []byte) error {
	ops, err := logic.AssembleString(string(text))
	if err == nil {
		*prog = ops.Program
	}
	return err
}

func inspectTxn(stxn transactions.SignedTxn) (sti inspectSignedTxn, err error) {
	sti = stxnToInspect(stxn)
	if !reflect.DeepEqual(stxn, stxnFromInspect(sti)) {
		err = fmt.Errorf("non-idempotent transformation to inspectSignedTxn (DeepEqual)")
		return
	}
	if !reflect.DeepEqual(protocol.EncodeReflect(sti), protocol.Encode(&stxn)) {
		err = fmt.Errorf("non-idempotent transformation to inspectSignedTxn (protocol.Encode)")
		return
	}
	return
}

func stxnToInspect(stxn transactions.SignedTxn) inspectSignedTxn {
	return inspectSignedTxn{
		Txn:      stxn.Txn,
		Sig:      stxn.Sig,
		Msig:     msigToInspect(stxn.Msig),
		Lsig:     lsigToInspect(stxn.Lsig),
		AuthAddr: stxn.AuthAddr,
	}
}

func stxnFromInspect(sti inspectSignedTxn) transactions.SignedTxn {
	return transactions.SignedTxn{
		Txn:      sti.Txn,
		Sig:      sti.Sig,
		Msig:     msigFromInspect(sti.Msig),
		Lsig:     lsigFromInspect(sti.Lsig),
		AuthAddr: sti.AuthAddr,
	}
}

func msigToInspect(msig crypto.MultisigSig) inspectMultisigSig {
	res := inspectMultisigSig{
		Version:   msig.Version,
		Threshold: msig.Threshold,
	}

	for _, subsig := range msig.Subsigs {
		res.Subsigs = append(res.Subsigs, inspectMultisigSubsig{
			Sig: subsig.Sig,
			Key: basics.Address(subsig.Key),
		})
	}

	return res
}

func msigFromInspect(msi inspectMultisigSig) crypto.MultisigSig {
	res := crypto.MultisigSig{
		Version:   msi.Version,
		Threshold: msi.Threshold,
	}

	for _, subsig := range msi.Subsigs {
		res.Subsigs = append(res.Subsigs, crypto.MultisigSubsig{
			Sig: subsig.Sig,
			Key: crypto.PublicKey(subsig.Key),
		})
	}

	return res
}

func lsigToInspect(lsig transactions.LogicSig) inspectLogicSig {
	return inspectLogicSig{
		Logic: inspectProgram(lsig.Logic),
		Sig:   lsig.Sig,
		Msig:  msigToInspect(lsig.Msig),
		Args:  lsig.Args,
	}
}

func lsigFromInspect(lsig inspectLogicSig) transactions.LogicSig {
	return transactions.LogicSig{
		Logic: []byte(lsig.Logic),
		Sig:   lsig.Sig,
		Msig:  msigFromInspect(lsig.Msig),
		Args:  lsig.Args,
	}
}
