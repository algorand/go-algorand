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
	"github.com/algorand/go-algorand/util/db"
)

type (
	// CommittablePublicKey is a key tied to a specific round and is committed by the merklekeystore.Signer.
	CommittablePublicKey struct {
		_struct struct{} `codec:",omitempty,omitemptyarray"`

		VerifyingKey crypto.GenericVerifyingKey `codec:"pk"`
		Round        uint64                     `codec:"rnd"`
	}

	//Proof represent the merkle proof in each signature.
	Proof merklearray.Proof

	// Signature is a byte signature on a crypto.Hashable object,
	// crypto.GenericVerifyingKey and includes a merkle proof for the key.
	Signature struct {
		_struct              struct{} `codec:",omitempty,omitemptyarray"`
		crypto.ByteSignature `codec:"bsig"`

		Proof        Proof                      `codec:"prf"`
		VerifyingKey crypto.GenericVerifyingKey `codec:"vkey"`
	}

	// Signer is a merkleKeyStore, contain multiple keys which can be used per round.
	// Signer will generate all keys in the range [A,Z] that are divisible by some divisor d.
	// in case A equals zero then signer will generate all keys from (0,Z], i.e will not generate key for round zero.
	Signer struct {
		_struct struct{} `codec:",omitempty,omitemptyarray"`

		// these keys should be temporarily stored in memory until Persist is called,
		// in which they will be dumped into database and disposed of.
		// non-exported fields to prevent msgpack marshalling
		signatureAlgorithms []crypto.GenericSigningKey
		keyStore            PersistentKeystore

		// the first round is used to set up the intervals.
		FirstValid uint64 `codec:"rnd"`

		Interval uint64 `codec:"iv"`

		Tree merklearray.Tree `codec:"tree"`
	}

	// Verifier is used to verify a merklekeystore.Signature produced by merklekeystore.Signer.
	// It validates a merklekeystore.Signature by validating the commitment on the GenericVerifyingKey and validating the signature with that key
	Verifier struct {
		_struct struct{} `codec:",omitempty,omitemptyarray"`

		Root [KeyStoreRootSize]byte `codec:"r"`
	}

	// keysArray is only used for building the merkle-tree and nothing else.
	keysArray struct {
		keys       []crypto.GenericSigningKey
		firstValid uint64
		interval   uint64
	}
)

var errStartBiggerThanEndRound = errors.New("cannot create merkleKeyStore because end round is smaller then start round")
var errOutOfBounds = errors.New("round translated to be after last key position")
var errNonExistantKey = errors.New("key doesn't exist")
var errDivisorIsZero = errors.New("received zero Interval")

// ToBeHashed implementation means CommittablePublicKey is crypto.Hashable, required by merklekeystore.Verifier.Verify()
func (e *CommittablePublicKey) ToBeHashed() (protocol.HashID, []byte) {
	return protocol.KeystorePK, protocol.Encode(e)
}

func (k *keysArray) Length() uint64 {
	return uint64(len(k.keys))
}

// Marshal Gets []byte to represent a GenericVerifyingKey tied to the signatureAlgorithm in a pos.
// used to implement the merklearray.Array interface needed to build a tree.
func (k *keysArray) Marshal(pos uint64) ([]byte, error) {
	signer := k.keys[pos].GetSigner()
	ephPK := CommittablePublicKey{
		VerifyingKey: *signer.GetVerifyingKey(),
		Round:        indexToRound(k.firstValid, k.interval, pos),
	}

	return crypto.HashRep(&ephPK), nil
}

// New Generates a merklekeystore.Signer
// The function allow creation of empty signers, i.e signers without any key to sign with.
// keys can be created between [A,Z], if A == 0, keys created will be in the range (0,Z]
func New(firstValid, lastValid, interval uint64, sigAlgoType crypto.AlgorithmType, store db.Accessor) (*Signer, error) {
	if firstValid > lastValid {
		return nil, errStartBiggerThanEndRound
	}
	if interval == 0 {
		return nil, errDivisorIsZero
	}
	if firstValid == 0 {
		firstValid = 1
	}

	// calculates the number of indices from first valid round and up to lastValid.
	// writing this explicit calculation to avoid overflow.
	numberOfKeys := lastValid/interval - ((firstValid - 1) / interval)
	keys := make([]crypto.GenericSigningKey, numberOfKeys)
	for i := range keys {
		sigAlgo, err := crypto.NewSigner(sigAlgoType)
		if err != nil {
			return nil, err
		}
		keys[i] = *sigAlgo
	}

	s := &Signer{
		keyStore:            PersistentKeystore{store},
		signatureAlgorithms: keys,
		FirstValid:          firstValid,
		Interval:            interval,
	}
	tree, err := merklearray.Build(&keysArray{keys, firstValid, interval}, crypto.HashFactory{HashType: KeyStoreHashFunction})
	if err != nil {
		return nil, err
	}
	s.Tree = *tree
	return s, nil
}

// Persist dumps the keys into the database and deletes the reference to them in Signer
func (s *Signer) Persist() error {
	err := s.keyStore.Persist(s.signatureAlgorithms, s.FirstValid, s.Interval)
	if err != nil {
		return err
	}

	// Let the garbage collector remove these from memory
	s.signatureAlgorithms = nil
	return nil
}

// GetVerifier can be used to store the commitment and verifier for this signer.
func (s *Signer) GetVerifier() *Verifier {
	root := [KeyStoreRootSize]byte{}
	ss := s.Tree.Root().ToSlice()
	copy(root[:], ss)
	return &Verifier{
		Root: root,
	}
}

// Sign outputs a signature + proof for the signing key.
func (s *Signer) Sign(hashable crypto.Hashable, round uint64) (Signature, error) {
	key, err := s.keyStore.GetKey(round)
	if err != nil {
		return Signature{}, err
	}
	signingKey := key.GetSigner()

	if err = checkKeystoreParams(s.FirstValid, round, s.Interval); err != nil {
		return Signature{}, err
	}

	index := s.getMerkleTreeIndex(round)
	proof, err := s.Tree.Prove([]uint64{index})
	if err != nil {
		return Signature{}, err
	}

	return Signature{
		ByteSignature: signingKey.Sign(hashable),
		Proof:         Proof(*proof),
		VerifyingKey:  *signingKey.GetVerifyingKey(),
	}, nil
}

// expects valid rounds, i.e round that are bigger than FirstValid.
func (s *Signer) getMerkleTreeIndex(round uint64) uint64 {
	return roundToIndex(s.FirstValid, round, s.Interval)
}

// Trim shortness deletes keys that existed before a specific round (including),
// will return an error for non existing keys/ out of bounds keys.
// If before value is higher than the lastValid - the earlier keys will still be deleted,
// and no error value will be returned.
func (s *Signer) Trim(before uint64) (count int64, err error) {
	count, err = s.keyStore.DropKeys(before)
	return count, err
}

// Restore loads Signer from given database, as well as restoring PersistenKeystore (where the actual keys are stored)
func (s *Signer) Restore(store db.Accessor) (err error) {
	keystore, err := RestoreKeystore(store)
	if err != nil {
		return
	}
	s.keyStore = keystore
	return
}

// IsEmpty returns true if the verifier contains an empty key
func (v *Verifier) IsEmpty() bool {
	return v.Root == [KeyStoreRootSize]byte{}
}

// Verify receives a signature over a specific crypto.Hashable object, and makes certain the signature is correct.
func (v *Verifier) Verify(firstValid, round, interval uint64, obj crypto.Hashable, sig Signature) error {
	if firstValid == 0 {
		firstValid = 1
	}
	if err := checkKeystoreParams(firstValid, round, interval); err != nil {
		return err
	}

	ephkey := CommittablePublicKey{
		VerifyingKey: sig.VerifyingKey,
		Round:        round,
	}

	pos := roundToIndex(firstValid, round, interval)
	err := merklearray.Verify(
		(crypto.GenericDigest)(v.Root[:]),
		map[uint64]crypto.Hashable{pos: &ephkey},
		(*merklearray.Proof)(&sig.Proof),
	)
	if err != nil {
		return err
	}

	return sig.VerifyingKey.GetVerifier().Verify(obj, sig.ByteSignature)
}
