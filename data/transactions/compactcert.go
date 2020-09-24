// Copyright (C) 2019-2020 Algorand, Inc.
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
	"github.com/algorand/go-algorand/crypto/compactcert"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/protocol"
)

// CompactCertTxnFields captures the fields used for compact cert transactions.
type CompactCertTxnFields struct {
	_struct struct{} `codec:",omitempty,omitemptyarray"`

	CertRound basics.Round     `codec:"certrnd"`
	Cert      compactcert.Cert `codec:"cert"`
}

// Empty returns whether the CompactCertTxnFields are all zero,
// in the sense of being omitted in a msgpack encoding.
func (cc CompactCertTxnFields) Empty() bool {
	if cc.CertRound != 0 {
		return false
	}
	if !cc.Cert.SigCommit.IsZero() || cc.Cert.SignedWeight != 0 {
		return false
	}
	if len(cc.Cert.SigProofs) != 0 || len(cc.Cert.PartProofs) != 0 {
		return false
	}
	if len(cc.Cert.Reveals) != 0 {
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

// CompactCertSender is the computed address for sending out compact certs.
var CompactCertSender basics.Address

func init() {
	CompactCertSender = basics.Address(crypto.HashObj(specialAddr("CompactCertSender")))
}
