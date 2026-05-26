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
	"errors"
	"fmt"

	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/data/basics"
)

var (
	ErrFalcon1024SigBlank              = errors.New("f1 signature is blank")
	ErrFalcon1024SigEmpty              = errors.New("f1 signature is empty")
	ErrFalcon1024SigInvalidAuthorizer  = errors.New("f1 salt and public key derive an invalid PQ address")
	ErrFalcon1024SigAuthorizerMismatch = errors.New("f1 authorizer mismatch")
	ErrFalcon1024SigVerificationFailed = errors.New("f1 signature verification failed")
)

type Falcon1024Sig struct {
	_struct struct{} `codec:",omitempty,omitemptyarray"`

	AddressSalt basics.PQAddressSalt   `codec:"slt"`
	PublicKey   crypto.FalconPublicKey `codec:"pk"`
	Signature   crypto.FalconSignature `codec:"sig"`
}

func (f *Falcon1024Sig) Blank() bool {
	if f == nil {
		return true
	}

	var emptyPK crypto.FalconPublicKey

	return f.PublicKey == emptyPK &&
		f.AddressSalt == 0 &&
		len(f.Signature) == 0
}

func (f *Falcon1024Sig) AuthorizerAddress() (basics.Address, bool) {
	if f == nil {
		return basics.Address{}, false
	}
	return basics.Falcon1024Address(f.AddressSalt, &f.PublicKey)
}

// Verify validates that f is an inline f1 authorization proof for txn and authorizer.
// It derives the authorizer address from the carried address salt and Falcon-1024
// public key, then verifies the Deterministic Falcon-1024 signature over the
// unsigned transaction.
func (f *Falcon1024Sig) Verify(txn Transaction, authorizer basics.Address) error {
	if f.Blank() {
		return ErrFalcon1024SigBlank
	}

	if len(f.Signature) == 0 {
		return ErrFalcon1024SigEmpty
	}

	f1Authorizer, ok := f.AuthorizerAddress()
	if !ok {
		return ErrFalcon1024SigInvalidAuthorizer
	}

	if f1Authorizer != authorizer {
		return fmt.Errorf("%w: derived %s, expected %s", ErrFalcon1024SigAuthorizerMismatch, f1Authorizer, authorizer)
	}

	fv := crypto.FalconVerifier{PublicKey: f.PublicKey}
	if err := fv.Verify(txn, f.Signature); err != nil {
		return fmt.Errorf("%w: %w", ErrFalcon1024SigVerificationFailed, err)
	}

	return nil
}
