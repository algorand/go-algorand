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
	// ErrSigSchemeNotSupported is returned when a SigScheme is not supported.
	ErrSigSchemeNotSupported = errors.New("signature scheme not supported")

	// ErrSigSchemeNotEnabled is returned when a SigScheme is not enabled under the protocol.
	ErrSigSchemeNotEnabled = errors.New("signature scheme not enabled")
)

// sigScheme is everything the protocol knows about one HashedKeySig scheme.
type sigScheme struct {
	// verifier checks the scheme's signature bytes. It is nil for ls, which
	// authorizes by evaluating a program, so callers must ask IsLogicSig first.
	verifier crypto.SigSchemeVerifier

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

// sigSchemes lists every HashedKeySig scheme. To add one:
//   - add its protocol.SigScheme tag,
//   - add an entry here, with a crypto.SigSchemeVerifier (implementing
//     crypto.SigSchemeBatchPreparer if the scheme is batch-verified) unless, like ls,
//     it does not authorize by checking signature bytes,
//   - add its config.ConsensusParams enable flag,
//   - add the signing/private-key ops in cmd/algokey,
//   - add it to basics_testing.SigSchemeTests.
var sigSchemes = map[protocol.SigScheme]sigScheme{
	protocol.SigSchemeFalcon1024: {
		verifier:         crypto.Falcon1024SchemeVerifier{},
		enabled:          func(proto config.ConsensusParams) bool { return proto.EnablePQSchemeFalcon1024 },
		fee:              2e6,
		maxPublicKeySize: constSize(crypto.Falcon1024PublicKeySize),
		maxSignatureSize: constSize(crypto.Falcon1024MaxSignatureSize),
	},
	protocol.SigSchemeFalcon512: {
		verifier:         crypto.Falcon512SchemeVerifier{},
		enabled:          func(proto config.ConsensusParams) bool { return proto.EnableSigSchemeFalcon512 },
		fee:              1e6, // half of the Falcon-1024 contribution
		maxPublicKeySize: constSize(crypto.Falcon512PublicKeySize),
		maxSignatureSize: constSize(crypto.Falcon512MaxSignatureSize),
	},
	protocol.SigSchemeEd25519: {
		verifier:         crypto.Ed25519SchemeVerifier{},
		enabled:          func(proto config.ConsensusParams) bool { return proto.EnableSigSchemeEd25519 },
		fee:              0, // a single Ed25519 signature is part of the min fee
		maxPublicKeySize: constSize(len(crypto.PublicKey{})),
		maxSignatureSize: constSize(len(crypto.Signature{})),
	},
	protocol.SigSchemeLogicSig: {
		enabled: func(proto config.ConsensusParams) bool { return proto.EnableSigSchemeLogicSig },
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

// SigSchemeSupported reports whether scheme is a known HashedKeySig scheme, enabled or
// not.
func SigSchemeSupported(scheme protocol.SigScheme) bool {
	_, ok := sigSchemes[scheme]
	return ok
}

// SigSchemeEnabled reports whether scheme is known and enabled under proto.
func SigSchemeEnabled(proto config.ConsensusParams, scheme protocol.SigScheme) bool {
	s, ok := sigSchemes[scheme]
	return ok && s.enabled(proto)
}

// SigSchemeFeeContribution is the additional fee factor charged for a
// transaction authorized with scheme, as a fixed-point multiple of the basic
// min fee (1e6 == one basic min fee). An unknown scheme contributes zero, which
// is safe because the transaction will be rejected during verification. It
// takes proto, though no fee varies by protocol yet, so that one can without
// changing call sites.
func SigSchemeFeeContribution(_ config.ConsensusParams, scheme protocol.SigScheme) basics.Micros {
	return sigSchemes[scheme].fee
}

// maxSigSchemePublicKeySize and maxSigSchemeSignatureSize are the largest sizes over all
// schemes, and bound HashedKeySig's byte fields on the wire.
func maxSigSchemePublicKeySize() int {
	n := 0
	for _, s := range sigSchemes {
		n = max(n, s.maxPublicKeySize())
	}
	return n
}

func maxSigSchemeSignatureSize() int {
	n := 0
	for _, s := range sigSchemes {
		n = max(n, s.maxSignatureSize())
	}
	return n
}
