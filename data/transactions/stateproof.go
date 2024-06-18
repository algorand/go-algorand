// Copyright (C) 2019-2024 Algorand, Inc.
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

// Empty returns whether the StateProofTxnFields are all zero,
// in the sense of being omitted in a msgpack encoding.
func (sp StateProofTxnFields) Empty() bool {
	return sp.StateProofType == protocol.StateProofBasic &&
		sp.StateProof.MsgIsZero() &&
		sp.Message.MsgIsZero()
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
