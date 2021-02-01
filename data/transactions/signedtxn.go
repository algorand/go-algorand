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

package transactions

import (
	"errors"

	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/protocol"
)

// SignedTxn wraps a transaction and a signature.
// It exposes a Verify() method that verifies the signature and checks that the
// underlying transaction is well-formed.
// TODO: update this documentation now that there's multisig
type SignedTxn struct {
	_struct struct{} `codec:",omitempty,omitemptyarray"`

	Sig      crypto.Signature   `codec:"sig"`
	Msig     crypto.MultisigSig `codec:"msig"`
	Lsig     LogicSig           `codec:"lsig"`
	Txn      Transaction        `codec:"txn"`
	AuthAddr basics.Address     `codec:"sgnr"`
}

// SignedTxnInBlock is how a signed transaction is encoded in a block.
type SignedTxnInBlock struct {
	_struct struct{} `codec:",omitempty,omitemptyarray"`

	SignedTxnWithAD

	Digest crypto.Digest

	HasGenesisID   bool `codec:"hgi"`
	HasGenesisHash bool `codec:"hgh"`
}

// SignedTxnWithAD is a (decoded) SignedTxn with associated ApplyData
type SignedTxnWithAD struct {
	_struct struct{} `codec:",omitempty,omitemptyarray"`

	SignedTxn
	ApplyData
}

// ID returns the Txid (i.e., hash) of the underlying transaction.
func (s SignedTxn) ID() Txid {
	return s.Txn.ID()
}

// ToBeHashed implements the crypto.Hashable interface.
func (s SignedTxn) ToBeHashed() (protocol.HashID, []byte) {
	return protocol.SignedTxn, protocol.Encode(&s)
}

// ID on SignedTxnInBlock should never be called, because the ID depends
// on the block from which this transaction will be decoded.  By having
// a different return value from SignedTxn.ID(), we will catch errors at
// compile-time.
func (s SignedTxnInBlock) ID() {
}

// GetEncodedLength returns the length in bytes of the encoded transaction
func (s SignedTxn) GetEncodedLength() int {
	enc := s.MarshalMsg(protocol.GetEncodingBuf())
	defer protocol.PutEncodingBuf(enc)
	return len(enc)
}

// GetEncodedLength returns the length in bytes of the encoded transaction
func (s SignedTxnInBlock) GetEncodedLength() int {
	enc := s.MarshalMsg(protocol.GetEncodingBuf())
	defer protocol.PutEncodingBuf(enc)
	return len(enc)
}

// Authorizer returns the address against which the signature/msig/lsig should be checked,
// or so the SignedTxn claims.
// This is just s.AuthAddr or, if s.AuthAddr is zero, s.Txn.Sender.
// It's provided as a convenience method.
func (s SignedTxn) Authorizer() basics.Address {
	if (s.AuthAddr == basics.Address{}) {
		return s.Txn.Sender
	}
	return s.AuthAddr
}

// AssembleSignedTxn assembles a multisig-signed transaction from a transaction an optional sig, and an optional multisig.
// No signature checking is done -- for example, this might only be a partial multisig
// TODO: is this method used anywhere, or is it safe to remove?
func AssembleSignedTxn(txn Transaction, sig crypto.Signature, msig crypto.MultisigSig) (SignedTxn, error) {
	if sig != (crypto.Signature{}) && !msig.Blank() {
		return SignedTxn{}, errors.New("signed txn can only have one of sig or msig")
	}
	s := SignedTxn{
		Txn:  txn,
		Sig:  sig,
		Msig: msig,
	}
	return s, nil
}
