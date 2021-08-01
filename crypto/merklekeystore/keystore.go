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
	"errors"

	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/crypto/merklearray"
	"github.com/algorand/go-algorand/protocol"
	"github.com/algorand/go-deadlock"
)

type (
	// CommittablePublicKey is a key tied to a specific round and is committed by the merklekeystore.Signer.
	CommittablePublicKey struct {
		_struct struct{} `codec:",omitempty,omitemptyarray"`

		VerifyingKey crypto.VerifyingKey `codec:"pk"`
		Round        uint64              `codec:"rnd"`
	}

	//Proof represent the merkle proof in each signature.
	//msgp:allocbound Proof -
	Proof []crypto.Digest

	// Signature is a byte signature on a crypto.Hashable object,
	// crypto.VerifyingKey and includes a merkle proof for the key.
	Signature struct {
		_struct              struct{} `codec:",omitempty,omitemptyarray"`
		crypto.ByteSignature `codec:"bsig"`

		Proof        `codec:"prf"`
		VerifyingKey crypto.VerifyingKey `codec:"vkey"`
		round        uint64
	}

	// Signer is a merkleKeyStore, contain multiple keys which can be used per round.
	// Signer will generate all keys in the range [A,Z] that are divisible by some divisor d.
	// in case A equals zero then signer will generate all keys from (0,Z], i.e will not generate key for round zero.
	Signer struct {
		_struct struct{} `codec:",omitempty,omitemptyarray"`
		// these keys are the keys used to sign in a round.
		// should be disposed of once possible.
		SignatureAlgorithms []crypto.SignatureAlgorithm `codec:"sks,allocbound=-"`
		// the first round is used to set up the intervals.
		FirstValid uint64 `codec:"rnd"`
		// Used to align a position to a shrank array.
		ArrayBase uint64 `codec:"az"`
		Interval  uint64 `codec:"iv"`

		Tree merklearray.Tree `codec:"tree"`
		mu   deadlock.RWMutex
	}

	// Verifier Is a way to verify a Signature produced by merklekeystore.Signer.
	// it also serves as a commit over all keys contained in the merklekeystore.Signer.
	Verifier struct {
		_struct struct{} `codec:",omitempty,omitemptyarray"`

		Root crypto.Digest `codec:"r"`
	}
)

var errStartBiggerThanEndRound = errors.New("cannot create merkleKeyStore because end round is smaller then start round")
var errReceivedRoundIsBeforeFirst = errors.New("round translated to be prior to first key position")
var errOutOfBounds = errors.New("round translated to be after last key position")
var errNonExistantKey = errors.New("key doesn't exist")
var errDivisorIsZero = errors.New("received zero Interval")

// ToBeHashed implementation means CommittablePublicKey is crypto.Hashable.
func (e *CommittablePublicKey) ToBeHashed() (protocol.HashID, []byte) {
	return protocol.EphemeralPK, protocol.Encode(e)
}

//Length returns the amount of disposable keys
func (s *Signer) Length() uint64 {
	return uint64(len(s.SignatureAlgorithms))
}

// GetHash Gets the hash of the VerifyingKey tied to the signatureAlgorithm in pos.
func (s *Signer) GetHash(pos uint64) (crypto.Digest, error) {
	ephPK := CommittablePublicKey{
		VerifyingKey: s.SignatureAlgorithms[pos].GetSigner().GetVerifyingKey(),
		Round:        indexToRound(s.FirstValid, s.Interval, pos),
	}
	return crypto.HashObj(&ephPK), nil
}

func (s *Signer) getActualPos(pos uint64) uint64 {
	return pos
}

// New Generates a merklekeystore.Signer
// The function allow creation of empty signers, i.e signers without any key to sign with.
// keys can be created between [A,Z], if A == 0, keys created will be in the range (0,Z]
func New(firstValid, lastValid, interval uint64, sigAlgoType crypto.AlgorithmType) (*Signer, error) {
	if firstValid > lastValid {
		return nil, errStartBiggerThanEndRound
	}
	if interval == 0 {
		return nil, errDivisorIsZero
	}
	if firstValid == 0 {
		firstValid++
	}
	numberOfKeys := roundToIndex(firstValid, lastValid, interval) + 1
	if numberOfKeys == 0 {
		// always outputs a valid signer that doesn't crash.
		return &Signer{Interval: interval}, nil
	}

	keys := make([]crypto.SignatureAlgorithm, numberOfKeys)
	for i := range keys {
		keys[i] = *crypto.NewSigner(sigAlgoType)
	}
	s := &Signer{
		SignatureAlgorithms: keys,
		FirstValid:          firstValid,
		ArrayBase:           0,
		Interval:            interval,
		mu:                  deadlock.RWMutex{},
	}
	tree, err := merklearray.Build(s)
	if err != nil {
		return nil, err
	}

	s.Tree = *tree
	return s, nil
}

// GetVerifier can be used to store the commitment and verifier for this signer.
func (s *Signer) GetVerifier() *Verifier {
	return &Verifier{
		Root: s.Tree.Root(),
	}
}

// Sign outputs a signature + proof for the signing key.
func (s *Signer) Sign(hashable crypto.Hashable, round uint64) (Signature, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	pos, err := s.getKeyPosition(round)
	if err != nil {
		return Signature{}, err
	}
	index := roundToIndex(s.FirstValid, round, s.Interval)
	proof, err := s.Tree.Prove([]uint64{index})
	if err != nil {
		return Signature{}, err
	}

	signer := s.SignatureAlgorithms[pos].GetSigner()
	return Signature{
		ByteSignature: signer.Sign(hashable),
		Proof:         proof,
		VerifyingKey:  signer.GetVerifyingKey(),
	}, nil
}

func (s *Signer) getKeyPosition(round uint64) (uint64, error) {
	if round < s.FirstValid {
		return 0, errReceivedRoundIsBeforeFirst
	}
	pos := roundToIndex(s.FirstValid, round, s.Interval)
	pos = pos - s.ArrayBase
	if round%s.Interval != 0 {
		return pos, errNonExistantKey
	}
	if pos >= uint64(len(s.SignatureAlgorithms)) {
		return 0, errOutOfBounds
	}
	return pos, nil
}

// Trim shortness deletes keys that existed before a specific round,
// will return an error for non existing keys/ out of bounds keys.
// the output is a copy of the signer - which can be persisted.
func (s *Signer) Trim(before uint64) (*Signer, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	pos, err := s.getKeyPosition(before)
	if err != nil {
		return nil, err
	}
	s.dropKeys(int(pos))

	// advance the array zero location.
	s.ArrayBase = roundToIndex(s.FirstValid, before, s.Interval) + 1
	cpy := s.copy()

	// Swapping the keys (both of them are the same, but the one in cpy doesn't contain a dangling array behind it.
	// e.g: A=A[len(A)-20:] doesn't mean the garbage collector will free parts of memory from the array.
	// assuming that cpy will be used briefly and then dropped - it's better to swap their key slices.
	s.SignatureAlgorithms, cpy.SignatureAlgorithms =
		cpy.SignatureAlgorithms, s.SignatureAlgorithms

	return cpy, nil
}

func (s *Signer) copy() *Signer {
	signerCopy := Signer{
		_struct: struct{}{},

		SignatureAlgorithms: make([]crypto.SignatureAlgorithm, len(s.SignatureAlgorithms)),
		FirstValid:          s.FirstValid,
		Interval:            s.Interval,
		ArrayBase:           s.ArrayBase,

		Tree: s.Tree,
		mu:   deadlock.RWMutex{},
	}

	copy(signerCopy.SignatureAlgorithms, s.SignatureAlgorithms)
	return &signerCopy
}

func (s *Signer) dropKeys(upTo int) {
	for i := 0; i <= upTo; i++ {
		// zero the keys.
		s.SignatureAlgorithms[i] = crypto.SignatureAlgorithm{}
	}
	s.SignatureAlgorithms = s.SignatureAlgorithms[upTo+1:]
}

// Verify receives a signature over a specific crypto.Hashable object, and makes certain the signature is correct.
func (v *Verifier) Verify(firstValid, round, interval uint64, obj crypto.Hashable, sig Signature) error {

	if firstValid == 0 {
		firstValid++
	}
	if round < firstValid {
		return errReceivedRoundIsBeforeFirst
	}

	ephkey := CommittablePublicKey{
		VerifyingKey: sig.VerifyingKey,
		Round:        round,
	}

	pos := roundToIndex(firstValid, round, interval)
	isInTree := merklearray.Verify(v.Root, map[uint64]crypto.Digest{pos: crypto.HashObj(&ephkey)}, sig.Proof)
	if isInTree != nil {
		return isInTree
	}

	return sig.VerifyingKey.GetVerifier().Verify(obj, sig.ByteSignature)
}
