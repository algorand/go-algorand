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
	"errors"

	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/crypto/stateproof"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/stateproofmsg"
	"github.com/algorand/go-algorand/protocol"
)

// StateProofTxnFields captures the fields used for stateproof transactions.
type StateProofTxnFields struct {
	_struct struct{} `codec:",omitempty,omitemptyarray"`

	StateProofType protocol.StateProofType `codec:"sptype"`
	StateProof     stateproof.StateProof   `codec:"sp"`
	Message        stateproofmsg.Message   `codec:"spmsg"`
}

var errBadSenderInStateProofTxn = errors.New("sender must be the state-proof sender")
var errFeeMustBeZeroInStateproofTxn = errors.New("fee must be zero in state-proof transaction")
var errNoteMustBeEmptyInStateproofTxn = errors.New("note must be empty in state-proof transaction")
var errGroupMustBeZeroInStateproofTxn = errors.New("group must be zero in state-proof transaction")
var errRekeyToMustBeZeroInStateproofTxn = errors.New("rekey must be zero in state-proof transaction")
var errLeaseMustBeZeroInStateproofTxn = errors.New("lease must be zero in state-proof transaction")

// wellFormed performs stateless checks on the StateProof transaction
func (sp StateProofTxnFields) wellFormed(header Header) error {
	// This is a placeholder transaction used to store state proofs
	// on the ledger, and ensure they are broadly available.  Most of
	// the fields must be empty.  It must be issued from a special
	// sender address.
	if header.Sender != StateProofSender {
		return errBadSenderInStateProofTxn
	}
	if !header.Fee.IsZero() {
		return errFeeMustBeZeroInStateproofTxn
	}
	if len(header.Note) != 0 {
		return errNoteMustBeEmptyInStateproofTxn
	}
	if !header.Group.IsZero() {
		return errGroupMustBeZeroInStateproofTxn
	}
	if !header.RekeyTo.IsZero() {
		return errRekeyToMustBeZeroInStateproofTxn
	}
	if header.Lease != [32]byte{} {
		return errLeaseMustBeZeroInStateproofTxn
	}
	return nil
}

// specialAddr is used to form a unique address that will send out state proofs.
//
//msgp:ignore specialAddr
type specialAddr string

// ToBeHashed implements the crypto.Hashable interface
func (a specialAddr) ToBeHashed() (protocol.HashID, []byte) {
	return protocol.SpecialAddr, []byte(a)
}

// StateProofSender is the computed address for sending out state proofs.
var StateProofSender basics.Address

func init() {
	StateProofSender = basics.Address(crypto.HashObj(specialAddr("StateProofSender")))
}
