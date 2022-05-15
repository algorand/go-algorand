// Copyright (C) 2019-2022 Algorand, Inc.
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

	StateProofIntervalLatestRound basics.Round            `codec:"sprnd"`
	StateProofType                protocol.StateProofType `codec:"sptype"`
	StateProof                    stateproof.StateProof   `codec:"sp"`
	StateProofMessage             stateproofmsg.Message   `codec:"spmsg"`
}

// Empty returns whether the StateProofTxnFields are all zero,
// in the sense of being omitted in a msgpack encoding.
func (sp StateProofTxnFields) Empty() bool {
	if sp.StateProofIntervalLatestRound != 0 {
		return false
	}
	if !sp.StateProof.SigCommit.IsEmpty() || sp.StateProof.SignedWeight != 0 {
		return false
	}
	if len(sp.StateProof.SigProofs.Path) != 0 || len(sp.StateProof.PartProofs.Path) != 0 {
		return false
	}
	if len(sp.StateProof.Reveals) != 0 {
		return false
	}
	if !sp.StateProofMessage.MsgIsZero() {
		return false
	}

	return true
}

//msgp:ignore specialAddr
// specialAddr is used to form a unique address that will send out compact certs.
type specialAddr string

// ToBeHashed implements the crypto.Hashable interface
func (a specialAddr) ToBeHashed() (protocol.HashID, []byte) {
	return protocol.SpecialAddr, []byte(a)
}

// StateProofSender is the computed address for sending out compact certs.
var StateProofSender basics.Address

func init() {
	StateProofSender = basics.Address(crypto.HashObj(specialAddr("StateProofSender")))
}
