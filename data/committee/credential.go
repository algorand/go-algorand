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

package committee

import (
	"encoding/binary"
	"fmt"
	"math/big"

	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/committee/sortition"
	"github.com/algorand/go-algorand/logging"
	"github.com/algorand/go-algorand/protocol"
)

type (
	// An UnauthenticatedCredential is a Credential which has not yet been
	// authenticated.
	UnauthenticatedCredential struct {
		_struct struct{}        `codec:",omitempty,omitemptyarray"`
		Proof   crypto.VrfProof `codec:"pf"`
	}

	// A Credential represents a proof of committee membership.
	//
	// The multiplicity of this membership is specified in the Credential's
	// weight. The VRF output hash (with the owner's address hashed in) is
	// also cached.
	//
	// Upgrades: whether or not domain separation is enabled is cached.
	// If this flag is set, this flag also includes original hashable
	// credential.
	Credential struct {
		_struct struct{}      `codec:",omitempty,omitemptyarray"`
		Weight  uint64        `codec:"wt"`
		VrfOut  crypto.Digest `codec:"h"`

		DomainSeparationEnabled bool               `codec:"ds"`
		Hashable                hashableCredential `codec:"hc"`

		UnauthenticatedCredential
	}

	hashableCredential struct {
		_struct struct{}         `codec:",omitempty,omitemptyarray"`
		RawOut  crypto.VrfOutput `codec:"v"`
		Member  basics.Address   `codec:"m"`
		Iter    uint64           `codec:"i"`
	}
)

// Verify an unauthenticated Credential that was received from the network.
//
// Verify checks if the given credential is a valid proof of membership
// conditioned on the provided committee membership parameters.
//
// If it is, the returned Credential constitutes a proof of this fact.
// Otherwise, an error is returned.
func (cred UnauthenticatedCredential) Verify(proto config.ConsensusParams, m Membership) (res Credential, err error) {
	selectionKey := m.Record.SelectionID
	ok, vrfOut := selectionKey.Verify(cred.Proof, m.Selector)

	hashable := hashableCredential{
		RawOut: vrfOut,
		Member: m.Record.Addr,
	}

	// Also hash in the address. This is necessary to decorrelate the selection of different accounts that have the same VRF key.
	var h crypto.Digest
	if proto.CredentialDomainSeparationEnabled {
		h = crypto.HashObj(hashable)
	} else {
		h = crypto.Hash(append(vrfOut[:], m.Record.Addr[:]...))
	}

	if !ok {
		err = fmt.Errorf("UnauthenticatedCredential.Verify: could not verify VRF Proof with %v (parameters = %+v, proof = %#v)", selectionKey, m, cred.Proof)
		return
	}

	var weight uint64
	userMoney := m.Record.VotingStake()
	expectedSelection := float64(m.Selector.CommitteeSize(proto))

	if m.TotalMoney.Raw < userMoney.Raw {
		logging.Base().Panicf("UnauthenticatedCredential.Verify: total money = %v, but user money = %v", m.TotalMoney, userMoney)
	} else if m.TotalMoney.IsZero() || expectedSelection == 0 || expectedSelection > float64(m.TotalMoney.Raw) {
		logging.Base().Panicf("UnauthenticatedCredential.Verify: m.TotalMoney %v, expectedSelection %v", m.TotalMoney.Raw, expectedSelection)
	} else if !userMoney.IsZero() {
		weight = sortition.Select(userMoney.Raw, m.TotalMoney.Raw, expectedSelection, h)
	}

	if weight == 0 {
		err = fmt.Errorf("UnauthenticatedCredential.Verify: credential has weight 0")
	} else {
		res = Credential{
			UnauthenticatedCredential: cred,
			VrfOut:                    h,
			Weight:                    weight,
			DomainSeparationEnabled:   proto.CredentialDomainSeparationEnabled,
		}
		if res.DomainSeparationEnabled {
			res.Hashable = hashable
		}
	}
	return
}

// MakeCredential creates a new unauthenticated Credential given some selector.
func MakeCredential(secrets *crypto.VrfPrivkey, sel Selector) UnauthenticatedCredential {
	pf, ok := secrets.Prove(sel)
	if !ok {
		logging.Base().Error("Failed to construct a VRF proof -- participation key may be corrupt")
		return UnauthenticatedCredential{}
	}
	return UnauthenticatedCredential{Proof: pf}
}

// Less returns true if this Credential is less than the other credential; false
// otherwise (i.e., >=).
// Used for breaking ties when there are multiple proposals.
//
// Precondition: both credentials have nonzero weight
func (cred Credential) Less(otherCred Credential) bool {
	i1 := cred.lowestOutput()
	i2 := otherCred.lowestOutput()

	return i1.Cmp(i2) < 0
}

// Equals compares the hash of two Credentials to determine equality and returns
// true if they're equal.
func (cred Credential) Equals(otherCred Credential) bool {
	return cred.VrfOut == otherCred.VrfOut
}

// Selected returns whether this Credential was selected (i.e., if its weight is
// greater than zero).
func (cred Credential) Selected() bool {
	return cred.Weight > 0
}

// lowestOutput is used for breaking ties when there are multiple proposals.
// People will vote for the proposal whose credential has the lowest lowestOutput.
//
// We hash the credential and interpret the output as a bigint.
// For credentials with weight w > 1, we hash the credential w times (with
// different counter values) and use the lowest output.
//
// This is because a weight w credential is simulating being selected to be on the
// leader committee w times, so each of the w proposals would have a different hash,
// and the lowest would win.
func (cred Credential) lowestOutput() *big.Int {
	var lowest big.Int

	h1 := cred.VrfOut
	// It is important that i start at 1 rather than 0 because cred.Hashable
	// was already hashed with iter = 0 earlier (in UnauthenticatedCredential.Verify)
	// for determining the weight of the credential. A nonzero iter provides
	// domain separation between lowestOutput and UnauthenticatedCredential.Verify
	//
	// If we reused the iter = 0 hash output here it would be nonuniformly
	// distributed (because lowestOutput can only get called if weight > 0).
	// In particular if i starts at 0 then weight-1 credentials are at a
	// significant disadvantage because UnauthenticatedCredential.Verify
	// wants the hash to be large but tiebreaking between proposals wants
	// the hash to be small.
	for i := uint64(1); i <= cred.Weight; i++ {
		var h crypto.Digest
		if cred.DomainSeparationEnabled {
			cred.Hashable.Iter = i
			h = crypto.HashObj(cred.Hashable)
		} else {
			var h2 crypto.Digest
			binary.BigEndian.PutUint64(h2[:], i)
			h = crypto.Hash(append(h1[:], h2[:]...))
		}

		if i == 1 {
			lowest.SetBytes(h[:])
		} else {
			var temp big.Int
			temp.SetBytes(h[:])
			if temp.Cmp(&lowest) < 0 {
				lowest.Set(&temp)
			}
		}
	}

	return &lowest
}

// LowestOutputDigest gives the lowestOutput as a crypto.Digest, which allows
// pretty-printing a proposal's lowest output.
// This function is only used for debugging.
func (cred Credential) LowestOutputDigest() crypto.Digest {
	lbytes := cred.lowestOutput().Bytes()
	var out crypto.Digest
	if len(lbytes) > len(out) {
		panic("Cred lowest output too long")
	}
	copy(out[len(out)-len(lbytes):], lbytes)
	return out
}

func (cred hashableCredential) ToBeHashed() (protocol.HashID, []byte) {
	return protocol.Credential, protocol.Encode(&cred)
}
