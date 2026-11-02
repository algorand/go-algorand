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

	"github.com/algorand/msgp/msgp"

	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/config/bounds"
	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/protocol"
)

var (
	// ErrPQSchemeNotSupported is returned when a PQScheme is not supported.
	ErrPQSchemeNotSupported = errors.New("pq signature scheme not supported")

	// ErrPQSchemeNotEnabled is returned when a PQScheme is not enabled under the protocol.
	ErrPQSchemeNotEnabled = errors.New("pq signature scheme not enabled")
)

// pqScheme is everything the protocol knows about one PQSig scheme.
type pqScheme struct {
	// verifier checks the scheme's signature bytes. It is nil for ls, which
	// authorizes by evaluating a program, so callers must ask IsLogicSig first.
	verifier crypto.PQVerifier

	// enabled reports the consensus parameter that turns the scheme on. The
	// flag itself must stay in config.ConsensusParams, which is versioned and
	// can be set from a custom consensus.json.
	enabled func(config.ConsensusParams) bool

	// fee is the additional fee factor charged for a transaction authorized
	// with the scheme, as a fixed-point multiple of the basic min fee (1e6 ==
	// one basic min fee).
	fee basics.Micros

	// maxPublicKeySize and maxSignatureSize bound the scheme's bytes on the
	// wire. They are functions so that a scheme's sizes may come from
	// config/bounds, which are computed when consensus parameters are loaded.
	maxPublicKeySize func() int
	maxSignatureSize func() int
}

func constSize(n int) func() int { return func() int { return n } }

// pqSchemes lists every PQSig scheme. To add one:
//   - add its protocol.PQScheme tag,
//   - add an entry here, with a crypto.PQVerifier (implementing
//     crypto.PQBatchPreparer if the scheme is batch-verified) unless, like ls,
//     it does not authorize by checking signature bytes,
//   - add its config.ConsensusParams enable flag,
//   - add the signing/private-key ops in cmd/algokey,
//   - add it to basics_testing.PQTestSchemes.
var pqSchemes = map[protocol.PQScheme]pqScheme{
	protocol.PQSchemeFalcon1024: {
		verifier:         crypto.PQFalcon1024{},
		enabled:          func(proto config.ConsensusParams) bool { return proto.EnablePQSchemeFalcon1024 },
		fee:              2e6,
		maxPublicKeySize: constSize(crypto.Falcon1024PublicKeySize),
		maxSignatureSize: constSize(crypto.Falcon1024MaxSignatureSize),
	},
	protocol.PQSchemeFalcon512: {
		verifier:         crypto.PQFalcon512{},
		enabled:          func(proto config.ConsensusParams) bool { return proto.EnablePQSchemeFalcon512 },
		fee:              1e6, // half of the Falcon-1024 contribution
		maxPublicKeySize: constSize(crypto.Falcon512PublicKeySize),
		maxSignatureSize: constSize(crypto.Falcon512MaxSignatureSize),
	},
	protocol.PQSchemeEd25519: {
		verifier:         crypto.PQEd25519{},
		enabled:          func(proto config.ConsensusParams) bool { return proto.EnablePQSchemeEd25519 },
		fee:              0, // a single Ed25519 signature is part of the min fee
		maxPublicKeySize: constSize(len(crypto.PublicKey{})),
		maxSignatureSize: constSize(len(crypto.Signature{})),
	},
	protocol.PQSchemeLogicSig: {
		enabled: func(proto config.ConsensusParams) bool { return proto.EnablePQSchemeLogicSig },
		// No surcharge. A surcharge here would make the off-curve form cost
		// more than the on-curve SignedTxn.Lsig form it exists to replace.
		fee: 0,
		// The public key is a program, and the signature its encoded arguments,
		// so they are bounded like LogicSig.Logic and LogicSig.Args.
		maxPublicKeySize: func() int { return bounds.MaxLogicSigMaxSize },
		maxSignatureSize: func() int {
			return msgp.ArrayHeaderSize + EvalMaxArgs*msgp.BytesPrefixSize + bounds.MaxLogicSigMaxSize
		},
	},
}

// PQSchemeSupported reports whether scheme is a known PQSig scheme, enabled or
// not.
func PQSchemeSupported(scheme protocol.PQScheme) bool {
	_, ok := pqSchemes[scheme]
	return ok
}

// PQSchemeEnabled reports whether scheme is known and enabled under proto.
func PQSchemeEnabled(proto config.ConsensusParams, scheme protocol.PQScheme) bool {
	s, ok := pqSchemes[scheme]
	return ok && s.enabled(proto)
}

// PQSchemeFeeContribution is the additional fee factor charged for a
// transaction authorized with scheme, as a fixed-point multiple of the basic
// min fee (1e6 == one basic min fee). An unknown scheme contributes zero, which
// is safe because the transaction will be rejected during verification. It
// takes proto, though no fee varies by protocol yet, so that one can without
// changing call sites.
func PQSchemeFeeContribution(_ config.ConsensusParams, scheme protocol.PQScheme) basics.Micros {
	return pqSchemes[scheme].fee
}

// maxPQPublicKeySize and maxPQSignatureSize are the largest sizes over all
// schemes, and bound PQSig's byte fields on the wire.
func maxPQPublicKeySize() int {
	n := 0
	for _, s := range pqSchemes {
		n = max(n, s.maxPublicKeySize())
	}
	return n
}

func maxPQSignatureSize() int {
	n := 0
	for _, s := range pqSchemes {
		n = max(n, s.maxSignatureSize())
	}
	return n
}
