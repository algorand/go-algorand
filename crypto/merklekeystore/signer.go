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

package merklekeystore

import (
	"fmt"
	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/crypto/merklearray"
)

type ephemeralKeys []*crypto.SignatureAlgorithm

//Length returns the amount of disposable keys
func (d ephemeralKeys) Length() uint64 {
	return uint64(len(d))
}

// GetHash Gets the hash of the VerifyingKey tied to the signatureAlgorithm in pos.
func (d ephemeralKeys) GetHash(pos uint64) (crypto.Digest, error) {
	return disposableKeyHash(d[pos])
}

func disposableKeyHash(s *crypto.SignatureAlgorithm) (crypto.Digest, error) {
	vkey := s.GetSigner().GetVerifyingKey()
	return crypto.HashObj(&vkey), nil
}

// Signature is a byte signature on a crypto.Hashable object, and includes a merkle proof for the signing key.
type Signature struct {
	crypto.ByteSignature
	Proof []crypto.Digest
	*crypto.VerifyingKey
	// the lead position of the VerifyingKey
	pos uint64
}

// Signer is a merkleKeyStore, contain multiple keys which can be used per round.
type Signer struct {
	// these keys are the keys used to sign in a round.
	// should be disposed of once possible.
	ephemeralKeys `codec:"keys"`
	startRound    uint64            `codec:"sround"`
	tree          *merklearray.Tree `codec:"tree"`
}

var errStartBiggerThanEndRound = fmt.Errorf("cannot create merkleKeyStore because end round is smaller then start round")

// New Generates a merklekeystore.Signer
func New(startRound, endRound uint64) (*Signer, error) {
	if startRound > endRound {
		return nil, errStartBiggerThanEndRound
	}
	keys := make(ephemeralKeys, endRound-startRound)
	for i := range keys {
		keys[i] = crypto.NewSigner(crypto.PlaceHolderType)
	}
	tree, err := merklearray.Build(keys)
	if err != nil {
		return nil, err
	}

	return &Signer{
		ephemeralKeys: keys,
		startRound:    startRound,
		tree:          tree,
	}, nil
}

// GetVerifier can be used to store the commitment and verifier for this signer.
func (m *Signer) GetVerifier() *Verifier {
	return &Verifier{
		root: m.tree.Root(),
	}
}

// Sign outputs a signature + proof for the signing key.
func (m *Signer) Sign(hashable crypto.Hashable, round int) (Signature, error) {
	pos, err := m.getKeyPosition(uint64(round))
	if err != nil {
		return Signature{}, err
	}

	proof, err := m.tree.Prove([]uint64{pos})
	if err != nil {
		return Signature{}, err
	}

	signer := m.ephemeralKeys[pos].GetSigner()
	vkey := signer.GetVerifyingKey()
	return Signature{
		ByteSignature: signer.Sign(hashable),
		Proof:         proof,
		VerifyingKey:  &vkey,
		pos:           pos,
	}, nil
}

var errOutOfBounds = fmt.Errorf("cannot find signing key for given round")

func (m *Signer) getKeyPosition(round uint64) (uint64, error) {
	if round < m.startRound {
		return 0, errOutOfBounds
	}

	pos := round - m.startRound
	if pos >= uint64(len(m.ephemeralKeys)) {
		return 0, errOutOfBounds
	}
	return pos, nil
}
