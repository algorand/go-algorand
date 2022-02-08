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

package merklesignature

import (
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/crypto/merklearray"
)

type (
	// Signature represents a signature in the merkle signature scheme using falcon signatures as an underlying crypto scheme.
	// It consists of an ephemeral public key, a signature, a merkle verification path and an index.
	// The merkle signature considered valid only if the Signature is verified under the ephemeral public key and
	// the Merkle verification path verifies that the ephemeral public key is located at the given index of the tree
	// (for the root given in the long-term public key).
	// More details can be found on Algorand's spec
	Signature struct {
		_struct struct{} `codec:",omitempty,omitemptyarray"`

		Signature        crypto.FalconSignature      `codec:"sig"`
		MerkleArrayIndex uint64                      `codec:"idx"`
		Proof            merklearray.SingleLeafProof `codec:"prf"`
		VerifyingKey     crypto.FalconVerifier       `codec:"vkey"`
	}

	// Secrets contains the private data needed by the merkle signature scheme.
	Secrets struct {
		_struct struct{} `codec:",omitempty,omitemptyarray"`

		// these keys should be temporarily stored in memory until Persist is called,
		// in which they will be dumped into database and disposed of.
		// non-exported fields to prevent msgpack marshalling
		ephemeralKeys []crypto.FalconSigner

		SignerContext
	}

	// Signer represents the StateProof signer for a specified round.
	//msgp:ignore Signer
	Signer struct {
		SigningKey *crypto.FalconSigner

		// The round for which this SigningKey is related to
		Round uint64

		SignerContext
	}

	// SignerContext contains all the immutable data and metadata related to merklesignature.Secrets (without the secret keys)
	SignerContext struct {
		_struct struct{} `codec:",omitempty,omitemptyarray"`

		FirstValid uint64           `codec:"fv"`
		Interval   uint64           `codec:"iv"`
		Tree       merklearray.Tree `codec:"tree"`
	}

	// Verifier is used to verify a merklesignature.Signature produced by merklesignature.Secrets.
	Verifier [MerkleSignatureSchemeRootSize]byte

	//KeyRoundPair represents an ephemeral signing key with it's corresponding round
	KeyRoundPair struct {
		_struct struct{} `codec:",omitempty,omitemptyarray"`

		Round uint64               `codec:"rnd"`
		Key   *crypto.FalconSigner `codec:"key"`
	}
)

// CryptoPrimitivesID is an identification that the Merkle Signature Scheme uses a subset sum hash function
// and a falcon signature scheme.
var CryptoPrimitivesID = uint16(0)

// Errors for the merkle signature scheme
var (
	ErrStartBiggerThanEndRound           = errors.New("cannot create Merkle Signature Scheme because end round is smaller then start round")
	ErrDivisorIsZero                     = errors.New("received zero Interval")
	ErrNoStateProofKeyForRound           = errors.New("no stateproof key exists for this round")
	ErrSignatureSchemeVerificationFailed = errors.New("merkle signature verification failed")
)

// New creates secrets needed for the merkle signature scheme.
// This function generates one key for each round within the participation period [firstValid, lastValid] (inclusive bounds)
// which holds round % interval == 0.
// In case firstValid equals zero then signer will generate all keys from (0,Z], i.e will not generate key for round zero.
func New(firstValid, lastValid, interval uint64) (*Secrets, error) {
	if firstValid > lastValid {
		return nil, ErrStartBiggerThanEndRound
	}
	if interval == 0 {
		return nil, ErrDivisorIsZero
	}

	if firstValid == 0 {
		firstValid = 1
	}

	// calculates the number of indices from first valid round and up to lastValid.
	// writing this explicit calculation to avoid overflow.
	numberOfKeys := lastValid/interval - ((firstValid - 1) / interval)

	keys, err := KeysBuilder(numberOfKeys)
	if err != nil {
		return nil, err
	}
	tree, err := merklearray.BuildVectorCommitmentTree(&committablePublicKeyArray{keys, firstValid, interval}, crypto.HashFactory{HashType: MerkleSignatureSchemeHashFunction})
	if err != nil {
		return nil, err
	}

	return &Secrets{
		ephemeralKeys: keys,
		SignerContext: SignerContext{
			FirstValid: firstValid,
			Interval:   interval,
			Tree:       *tree,
		},
	}, nil
}

// GetVerifier can be used to store the commitment and verifier for this signer.
func (s *Secrets) GetVerifier() *Verifier {
	return s.SignerContext.GetVerifier()
}

// GetVerifier can be used to store the commitment and verifier for this signer.
func (s *SignerContext) GetVerifier() *Verifier {
	ver := [MerkleSignatureSchemeRootSize]byte{}
	ss := s.Tree.Root().ToSlice()
	copy(ver[:], ss)
	return (*Verifier)(&ver)
}

// Sign signs a hash of a given message. The signature is valid on a specific round
func (s *Signer) Sign(hashable crypto.Hashable) (Signature, error) {
	key := s.SigningKey
	// Possible since there may not be a StateProof key for this specific round
	if key == nil {
		return Signature{}, ErrNoStateProofKeyForRound
	}

	if err := checkMerkleSignatureSchemeParams(s.FirstValid, s.Round, s.Interval); err != nil {
		return Signature{}, err
	}

	index := s.getMerkleTreeIndex(s.Round)
	proof, err := s.Tree.ProveSingleLeaf(index)
	if err != nil {
		return Signature{}, err
	}

	sig, err := s.SigningKey.Sign(hashable)
	if err != nil {
		return Signature{}, err
	}

	return Signature{
		Signature:        sig,
		Proof:            *proof,
		VerifyingKey:     *s.SigningKey.GetVerifyingKey(),
		MerkleArrayIndex: index,
	}, nil
}

// expects valid rounds, i.e round that are bigger than FirstValid.
func (s *Signer) getMerkleTreeIndex(round uint64) uint64 {
	return roundToIndex(s.FirstValid, round, s.Interval)
}

// GetAllKeys returns all stateproof secrets.
// An empty array will be return if no stateproof secrets are found
func (s *Secrets) GetAllKeys() []KeyRoundPair {
	NumOfKeys := uint64(len(s.ephemeralKeys))
	keys := make([]KeyRoundPair, NumOfKeys)
	for i := uint64(0); i < NumOfKeys; i++ {
		keyRound := KeyRoundPair{
			Round: indexToRound(s.SignerContext.FirstValid, s.SignerContext.Interval, i),
			Key:   &s.ephemeralKeys[i],
		}
		keys[i] = keyRound
	}
	return keys
}

// GetKey retrieves key from memory
// the function return nil if the key does not exists
func (s *Secrets) GetKey(round uint64) *crypto.FalconSigner {
	idx := roundToIndex(s.FirstValid, round, s.Interval)
	if idx >= uint64(len(s.ephemeralKeys)) || (round%s.Interval) != 0 {
		return nil
	}

	return &s.ephemeralKeys[idx]
}

// GetSigner returns the secret keys required for the specified round as well as the rest of the required state proof immutable data
func (s *Secrets) GetSigner(round uint64) *Signer {
	return &Signer{
		SigningKey:    s.GetKey(round),
		Round:         round,
		SignerContext: s.SignerContext,
	}
}

// IsEmpty returns true if the verifier contains an empty key
func (v *Verifier) IsEmpty() bool {
	return *v == [MerkleSignatureSchemeRootSize]byte{}
}

// Verify verifies that a merklesignature sig is valid, on a specific round, under a given public key
func (v *Verifier) Verify(round uint64, msg crypto.Hashable, sig Signature) error {

	ephkey := CommittablePublicKey{
		VerifyingKey: sig.VerifyingKey,
		Round:        round,
	}

	// verify the merkle tree verification path using the ephemeral public key, the
	// verification path and the index.
	err := merklearray.VerifyVectorCommitment(
		v[:],
		map[uint64]crypto.Hashable{sig.MerkleArrayIndex: &ephkey},
		sig.Proof.ToProof(),
	)
	if err != nil {
		return fmt.Errorf("%w - %v", ErrSignatureSchemeVerificationFailed, err)
	}

	// verify that the signature is valid under the ephemeral public key
	err = sig.VerifyingKey.Verify(msg, sig.Signature)
	if err != nil {
		return fmt.Errorf("%w - %v", ErrSignatureSchemeVerificationFailed, err)
	}
	return nil
}

// GetFixedLengthHashableRepresentation returns the signature as a hashable byte sequence.
// the format details can be found in the Algorand's spec.
func (s *Signature) GetFixedLengthHashableRepresentation() ([]byte, error) {
	schemeType := make([]byte, 2)
	binary.LittleEndian.PutUint16(schemeType, CryptoPrimitivesID)
	sigBytes, err := s.VerifyingKey.GetSignatureFixedLengthHashableRepresentation(s.Signature)
	if err != nil {
		return nil, err
	}

	verifierBytes := s.VerifyingKey.GetFixedLengthHashableRepresentation()

	binaryMerkleIndex := make([]byte, 8)
	binary.LittleEndian.PutUint64(binaryMerkleIndex, s.MerkleArrayIndex)

	proofBytes := s.Proof.GetFixedLengthHashableRepresentation()

	merkleSignatureBytes := make([]byte, 0, len(schemeType)+len(sigBytes)+len(verifierBytes)+len(binaryMerkleIndex)+len(proofBytes))
	merkleSignatureBytes = append(merkleSignatureBytes, schemeType...)
	merkleSignatureBytes = append(merkleSignatureBytes, sigBytes...)
	merkleSignatureBytes = append(merkleSignatureBytes, verifierBytes...)
	merkleSignatureBytes = append(merkleSignatureBytes, binaryMerkleIndex...)
	merkleSignatureBytes = append(merkleSignatureBytes, proofBytes...)
	return merkleSignatureBytes, nil
}
