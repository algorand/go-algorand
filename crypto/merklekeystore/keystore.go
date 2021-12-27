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

package merklekeystore

import (
	"encoding/binary"
	"context"
	"database/sql"
	"errors"
	"fmt"
	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/crypto/merklearray"
	"github.com/algorand/go-algorand/util/db"
)

type (

	// Signature represents a signature in the merkle signature scheme using an underlying crypto scheme.
	// It consists of an ephemeral public key, a signature, a merkle verification path and an index.
	// The merkle signature considered valid only if the ByteSignature is verified under the ephemeral public key and
	// the Merkle verification path verifies that the ephemeral public key is located at the given index of the tree
	// (for the root given in the long-term public key).
	// More details can be found on Algorand's spec
	Signature struct {
		_struct              struct{} `codec:",omitempty,omitemptyarray"`
		crypto.ByteSignature `codec:"bsig"`

		MerkleArrayIndex uint64                     `codec:"idx"`
		Proof            merklearray.Proof          `codec:"prf"`
		VerifyingKey     crypto.GenericVerifyingKey `codec:"vkey"`
	}

	// Signer is a merkleKeyStore, contain multiple keys which can be used per round.
	// Signer will generate all keys in the range [A,Z] that are divisible by some divisor d.
	// in case A equals zero then signer will generate all keys from (0,Z], i.e will not generate key for round zero.
	// i.e. the generated keys are {all values x such that x >= firstValid, x <= lastValid, and x%interval == 0}
	Signer struct {
		_struct struct{} `codec:",omitempty,omitemptyarray"`

		// these keys should be temporarily stored in memory until Persist is called,
		// in which they will be dumped into database and disposed of.
		// non-exported fields to prevent msgpack marshalling
		signatureAlgorithms []crypto.GenericSigningKey
		//keyStore            PersistentKeystore

		SignerRecord
	}

	// SignerInRound represents the StateProof signer for a specified round.
	//msgp:ignore SignerInRound
	SignerInRound struct {
		SigningKey *crypto.GenericSigningKey

		// The round for which this SigningKey is related to
		Round uint64

		SignerRecord
	}

	// SignerRecord contains all the public immutable data related to merklekeystore.Signer
	SignerRecord struct {
		_struct struct{} `codec:",omitempty,omitemptyarray"`

		// the first round is used to set up the intervals.
		FirstValid uint64 `codec:"rnd"`

		Interval uint64 `codec:"iv"`

		Tree merklearray.Tree `codec:"tree"`
	}

	// Verifier is used to verify a merklekeystore.Signature produced by merklekeystore.Signer.
	// It validates a merklekeystore.Signature by validating the commitment on the GenericVerifyingKey and validating the signature with that key
	Verifier [KeyStoreRootSize]byte
)

var errStartBiggerThanEndRound = errors.New("cannot create merkleKeyStore because end round is smaller then start round")
var errDivisorIsZero = errors.New("received zero Interval")

// New Generates a merklekeystore.Signer
// The function allow creation of empty signers, i.e signers without any key to sign with.
// keys can be created between [firstValid,lastValid], if firstValid == 0, keys created will be in the range (0,lastValid]
func New(firstValid, lastValid, interval uint64, sigAlgoType crypto.AlgorithmType) (*Signer, error) {
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

	keys, err := KeyStoreBuilder(numberOfKeys, sigAlgoType)
	if err != nil {
		return nil, err
	}
	s := &Signer{
		signatureAlgorithms: keys,
		SignerRecord: SignerRecord{
			FirstValid: firstValid,
			Interval:   interval,
		},
	}
	tree, err := merklearray.Build(&CommittablePublicKeyArray{keys, firstValid, interval}, crypto.HashFactory{HashType: KeyStoreHashFunction})
	if err != nil {
		return nil, err
	}
	s.Tree = *tree
	return s, nil
}

// Persist dumps the keys into the database and deletes the reference to them in Signer
func (s *Signer) Persist(store db.Accessor) error {
	if s.signatureAlgorithms == nil {
		return fmt.Errorf("no keys provided (nil)")
	}

	err := store.Atomic(func(ctx context.Context, tx *sql.Tx) error {
		err := keystoreInstallDatabase(tx) // assumes schema table already exists (created by partInstallDatabase)
		if err != nil {
			return err
		}

		if s.Interval == 0 {
			return errIntervalZero
		}
		round := IndexToRound(s.FirstValid, s.Interval, 0)
		for i, key := range s.signatureAlgorithms {
			encodedKey := key.MarshalMsg(protocol.GetEncodingBuf())
			_, err := tx.Exec("INSERT INTO StateProofKeys (id, round, key) VALUES (?,?,?)", i, round, encodedKey)
			protocol.PutEncodingBuf(encodedKey)
			if err != nil {
				return fmt.Errorf("failed to insert StateProof key number %v round %d. SQL Error: %w", i, round, err)
			}
			round += s.Interval
		}

		return nil
	})
	if err != nil {
		return fmt.Errorf("PersistentKeystore.Persist: %w", err)
	}

	return nil // Success
}

const keystoreSchemaVersion = 1
const keystoreTableSchemaName = "merklekeystore"

func keystoreInstallDatabase(tx *sql.Tx) error {
	_, err := tx.Exec(`CREATE TABLE StateProofKeys (
    	id	  INTEGER PRIMARY KEY, 
    	round INTEGER,	    --*  committed round for this key
		key   BLOB  --*  msgpack encoding of ParticipationAccount.StateProof.GenericSigningKey
		);`)
	if err != nil {
		return err
	}

	_, err = tx.Exec(`CREATE UNIQUE INDEX IF NOT EXISTS roundIdx ON StateProofKeys (round);`)
	if err != nil {
		return err
	}
	_, err = tx.Exec("INSERT INTO schema (tablename, version) VALUES (?, ?)", keystoreTableSchemaName, keystoreSchemaVersion)

	return err
}

// GetVerifier can be used to store the commitment and verifier for this signer.
func (s *Signer) GetVerifier() *Verifier {
	return s.SignerRecord.GetVerifier()
}

// GetVerifier can be used to store the commitment and verifier for this signer.
func (s *SignerRecord) GetVerifier() *Verifier {
	ver := [KeyStoreRootSize]byte{}
	ss := s.Tree.Root().ToSlice()
	copy(ver[:], ss)
	return (*Verifier)(&ver)
}

// TODO: merge identical logic of Signer and SignerInRound methods
// Sign outputs a signature + proof for the signing key.
//func (s *Signer) Sign(hashable crypto.Hashable, round uint64) (Signature, error) {
//	key, err := s.keyStore.GetKey(round)
//	if err != nil {
//		return Signature{}, err
//	}
//	signingKey := key.GetSigner()
//
//	if err = checkKeystoreParams(s.FirstValid, round, s.Interval); err != nil {
//		return Signature{}, err
//	}
//
//	index := s.getMerkleTreeIndex(round)
//	proof, err := s.Tree.Prove([]uint64{index})
//	if err != nil {
//		return Signature{}, err
//	}
//
//	sig, err := signingKey.Sign(hashable)
//	if err != nil {
//		return Signature{}, err
//	}
//
//	return Signature{
//		ByteSignature: sig,
//		Proof:         Proof(*proof),
//		VerifyingKey:  *signingKey.GetVerifyingKey(),
//	}, nil
//}

// Sign outputs a signature + proof for the signing key.
func (s *SignerInRound) Sign(hashable crypto.Hashable) (Signature, error) {
	key := s.SigningKey
	// Possible since there may not be a StateProof key for this specific round
	if key == nil {
		return Signature{}, fmt.Errorf("no stateproof key exists for this round")
	}
	signingKey := key.GetSigner()

	if err := checkKeystoreParams(s.FirstValid, s.Round, s.Interval); err != nil {
		return Signature{}, err
	}

	index := s.getMerkleTreeIndex(s.Round)
	proof, err := s.Tree.Prove([]uint64{index})
	if err != nil {
		return Signature{}, err
	}

	sig, err := signingKey.Sign(hashable)
	if err != nil {
		return Signature{}, err
	}

	return Signature{
		ByteSignature: sig,
		Proof:         Proof(*proof),
		VerifyingKey:  *signingKey.GetVerifyingKey(),
	}, nil
}

// expects valid rounds, i.e round that are bigger than FirstValid.
func (s *Signer) getMerkleTreeIndex(round uint64) uint64 {
	return RoundToIndex(s.FirstValid, round, s.Interval)
}

// expects valid rounds, i.e round that are bigger than FirstValid.
func (s *SignerInRound) getMerkleTreeIndex(round uint64) uint64 {
	return RoundToIndex(s.FirstValid, round, s.Interval)
}

// TODO: delete this
// Trim shortness deletes keys that existed before a specific round (including),
// will return an error for non existing keys/ out of bounds keys.
// If before value is higher than the lastValid - the earlier keys will still be deleted,
// and no error value will be returned.
//func (s *Signer) Trim(before uint64) (count int64, err error) {
//	count, err = s.keyStore.DropKeys(before)
//	return count, err
//}

// Restore loads Signer from given database, as well as restoring PersistenKeystore (where the actual keys are stored)
func (s *Signer) Restore(store db.Accessor) (err error) {
	//keystore, err := RestoreKeystore(store)
	//if err != nil {
	//	return
	//}
	//s.keyStore = keystore
	return
}

// GetKey retrieves key from memory if exists
func (s *Signer) GetKey(round uint64) *crypto.GenericSigningKey {
	idx := RoundToIndex(s.FirstValid, round, s.Interval)
	if idx < 0 || idx >= uint64(len(s.signatureAlgorithms)) || (round%s.Interval) != 0 {
		return nil
	}

	return &s.signatureAlgorithms[idx]
}

// TODO: add unit test
// FetchKey returns the SigningKey and round for a specified index from the StateProof DB
func (s *Signer) FetchKey(id uint64, store db.Accessor) (*crypto.GenericSigningKey, uint64, error) {
	var keyB []byte
	var round uint64
	key := &crypto.GenericSigningKey{}

	err := store.Atomic(func(ctx context.Context, tx *sql.Tx) error {
		row := tx.QueryRow("SELECT key,round FROM StateProofKeys WHERE id = ?", id)
		err := row.Scan(&keyB, &round)
		if err != nil {
			return fmt.Errorf("failed to select stateProof key for round %d : %w", round, err)
		}

		return nil
	})
	if err != nil {
		return nil, 0, err // fmt.Errorf("PersistentKeystore.GetKey: %w", err)
	}

	err = protocol.Decode(keyB, key)
	if err != nil {
		return nil, 0, err // fmt.Errorf("PersistentKeystore.GetKey: %w", err)
	}

	return key, round, nil
}

// CountKeys couts the number of rows in StateProofKeys table
func (s *Signer) CountKeys(store db.Accessor) int {
	var count int
	err := store.Atomic(func(ctx context.Context, tx *sql.Tx) error {
		row := tx.QueryRow("SELECT COUNT(*) FROM StateProofKeys")
		err := row.Scan(&count)
		if err != nil {
			return fmt.Errorf("failed to count rows in table StateProofKeys : %w", err)
		}
		return nil
	})
	if err != nil {
		return -1
	}
	return count
}

func (s *Signer) RoundSecrets(round uint64) *SignerInRound {
	return &SignerInRound{
		SigningKey:   s.GetKey(round),
		Round:        round,
		SignerRecord: s.SignerRecord,
	}
}

// IsEmpty returns true if the verifier contains an empty key
func (v *Verifier) IsEmpty() bool {
	return *v == [KeyStoreRootSize]byte{}
}

// Verify receives a signature over a specific crypto.Hashable object, and makes certain the signature is correct.
func (v *Verifier) Verify(round uint64, msg crypto.Hashable, sig Signature) error {

	ephkey := CommittablePublicKey{
		VerifyingKey: sig.VerifyingKey,
		Round:        round,
	}

	// verify the merkle tree verification path using the ephemeral public key, the
	// verification path and the index.
	err := merklearray.Verify(
		v[:],
		map[uint64]crypto.Hashable{sig.MerkleArrayIndex: &ephkey},
		&sig.Proof,
	)
	if err != nil {
		return err
	}

	// verify that the signature is valid under the ephemeral public key
	return sig.VerifyingKey.GetVerifier().Verify(msg, sig.ByteSignature)
}

// GetFixedLengthHashableRepresentation returns the signature as a hashable byte sequence.
// the format details can be found in the Algorand's spec.
func (s *Signature) GetFixedLengthHashableRepresentation() ([]byte, error) {
	schemeType := make([]byte, 2)
	binary.LittleEndian.PutUint16(schemeType, uint16(s.VerifyingKey.Type))
	sigBytes, err := s.VerifyingKey.GetVerifier().GetSignatureFixedLengthHashableRepresentation(s.ByteSignature)
	if err != nil {
		return nil, err
	}

	verifierBytes := s.VerifyingKey.GetVerifier().GetFixedLengthHashableRepresentation()

	binaryMerkleIndex := make([]byte, 8)
	binary.LittleEndian.PutUint64(binaryMerkleIndex, s.MerkleArrayIndex)

	proofBytes := s.Proof.GetSerializedProof()

	merkleSignatureBytes := make([]byte, 0, len(schemeType)+len(sigBytes)+len(verifierBytes)+len(binaryMerkleIndex)+len(proofBytes))
	merkleSignatureBytes = append(merkleSignatureBytes, schemeType...)
	merkleSignatureBytes = append(merkleSignatureBytes, sigBytes...)
	merkleSignatureBytes = append(merkleSignatureBytes, verifierBytes...)
	merkleSignatureBytes = append(merkleSignatureBytes, binaryMerkleIndex...)
	merkleSignatureBytes = append(merkleSignatureBytes, proofBytes...)
	return merkleSignatureBytes, nil
}
