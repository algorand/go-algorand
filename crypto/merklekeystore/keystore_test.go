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
	"context"
	"crypto/rand"
	"database/sql"
	"fmt"
	"testing"

	uuid "github.com/satori/go.uuid"
	"github.com/stretchr/testify/require"

	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/protocol"
	"github.com/algorand/go-algorand/test/partitiontest"
	"github.com/algorand/go-algorand/util/db"
)

type TestingHashable struct {
	data []byte
}

func (s TestingHashable) ToBeHashed() (protocol.HashID, []byte) {
	return protocol.TestHashable, s.data
}

// Is this test even needed? What is the purpose?
func TestSignerCreation(t *testing.T) {
	partitiontest.PartitionTest(t)
	a := require.New(t)
	var err error

	h := genHashableForTest()
	for i := uint64(1); i < 20; i++ {
		signer := generateTestSigner(crypto.FalconType, i, i+1, 1, a)
		defer signer.keyStore.store.Close()
		_, err = signer.Sign(h, i)
		a.NoError(err)
	}

	testSignerNumKeysLimits := func(t crypto.AlgorithmType, firstValid uint64, lastValid uint64, interval uint64, expectedLen int) {
		signer := generateTestSigner(t, firstValid, lastValid, interval, a)
		defer signer.keyStore.store.Close()
		a.Equal(expectedLen, length(signer, a))
	}

	testSignerNumKeysLimits(crypto.FalconType, 0, 0, 1, 0)
	testSignerNumKeysLimits(crypto.FalconType, 0, 1, 1, 1)
	testSignerNumKeysLimits(crypto.FalconType, 2, 2, 2, 1)
	testSignerNumKeysLimits(crypto.FalconType, 8, 21, 10, 2)
	testSignerNumKeysLimits(crypto.FalconType, 8, 20, 10, 2)
	testSignerNumKeysLimits(crypto.FalconType, 10, 21, 10, 2)
	testSignerNumKeysLimits(crypto.FalconType, 10, 20, 10, 2)
	testSignerNumKeysLimits(crypto.FalconType, 11, 20, 10, 1)

	testSignerNumKeysLimits(crypto.Ed25519Type, 0, 0, 1, 0)
	testSignerNumKeysLimits(crypto.Ed25519Type, 0, 1, 1, 1)
	testSignerNumKeysLimits(crypto.Ed25519Type, 2, 2, 2, 1)
	testSignerNumKeysLimits(crypto.Ed25519Type, 8, 21, 10, 2)
	testSignerNumKeysLimits(crypto.Ed25519Type, 8, 20, 10, 2)
	testSignerNumKeysLimits(crypto.Ed25519Type, 10, 21, 10, 2)
	testSignerNumKeysLimits(crypto.Ed25519Type, 10, 20, 10, 2)
	testSignerNumKeysLimits(crypto.Ed25519Type, 11, 20, 10, 1)

	signer := generateTestSigner(crypto.FalconType, 2, 2, 2, a)
	defer signer.keyStore.store.Close()
	a.Equal(1, length(signer, a))

	sig, err := signer.Sign(genHashableForTest(), 2)
	a.NoError(err)
	a.NoError(signer.GetVerifier().Verify(2, 2, 2, genHashableForTest(), sig))

	signer = generateTestSigner(crypto.FalconType, 2, 2, 3, a)
	defer signer.keyStore.store.Close()
	a.Equal(0, length(signer, a))
	_, err = signer.Sign(genHashableForTest(), 2)
	a.Error(err)

	signer = generateTestSigner(crypto.FalconType, 11, 19, 10, a)
	defer signer.keyStore.store.Close()
	a.Equal(0, length(signer, a))
	_, err = signer.Sign(genHashableForTest(), 2)
	a.Error(err)
}
func TestEmptyVerifier(t *testing.T) {
	partitiontest.PartitionTest(t)
	a := require.New(t)

	signer := generateTestSigner(crypto.FalconType, 8, 9, 5, a)
	defer signer.keyStore.store.Close()
	a.Equal(signer.GetVerifier().IsEmpty(), true)
}

func TestEmptySigner(t *testing.T) {
	partitiontest.PartitionTest(t)
	a := require.New(t)
	var err error

	h := genHashableForTest()
	signer := generateTestSigner(crypto.FalconType, 8, 9, 5, a)
	defer signer.keyStore.store.Close()
	a.NoError(err)
	a.Equal(0, length(signer, a))

	_, err = signer.Sign(h, 8)
	a.Error(err)

	_, err = signer.Sign(h, 9)
	a.Error(err)

	_, err = signer.Trim(10)
	a.NoError(err)
}

func TestDisposableKeysGeneration(t *testing.T) {
	partitiontest.PartitionTest(t)
	a := require.New(t)
	var err error

	signer := generateTestSigner(crypto.FalconType, 0, 100, 1, a)
	defer signer.keyStore.store.Close()
	for i := uint64(1); i < 100; i++ {
		_, err = signer.keyStore.GetKey(i)
		a.NoError(err, i)
	}

	_, err = signer.keyStore.GetKey(101)
	a.Error(err)

	signer = generateTestSigner(crypto.FalconType, 1000, 1100, 1, a)
	defer signer.keyStore.store.Close()
	for i := uint64(1000); i < 1100; i++ {
		_, err = signer.keyStore.GetKey(i)
		a.NoError(err, i)
	}

	_, err = signer.keyStore.GetKey(999)
	a.Error(err)

	signer = generateTestSigner(crypto.FalconType, 1000, 1100, 101, a)
	defer signer.keyStore.store.Close()
	intervalRounds := make([]uint64, 0)
	for i := uint64(1000); i <= 1100; i++ {
		if i%101 == 0 {
			intervalRounds = append(intervalRounds, i)
			continue
		}
		_, err := signer.keyStore.GetKey(i)
		a.Error(err, i)
	}
}

func TestNonEmptyDisposableKeys(t *testing.T) {
	partitiontest.PartitionTest(t)
	a := require.New(t)

	signer := generateTestSigner(crypto.FalconType, 0, 100, 1, a)
	defer signer.keyStore.store.Close()

	s := crypto.GenericSigningKey{}
	for i := uint64(1); i <= 100; i++ {
		key, err := signer.keyStore.GetKey(i)
		a.NoError(err)
		a.NotEqual(s, key)
	}

	signer = generateTestSigner(crypto.Ed25519Type, 0, 100, 1, a)
	defer signer.keyStore.store.Close()

	s = crypto.GenericSigningKey{}
	for i := uint64(1); i <= 100; i++ {
		key, err := signer.keyStore.GetKey(i)
		a.NoError(err)
		a.NotEqual(s, key)
	}
}

func TestSignatureStructure(t *testing.T) {
	partitiontest.PartitionTest(t)
	a := require.New(t)

	signer := generateTestSigner(crypto.FalconType, 50, 100, 1, a)
	defer signer.keyStore.store.Close()

	hashable := genHashableForTest()
	sig, err := signer.Sign(hashable, 51)
	a.NoError(err)

	key, err := signer.keyStore.GetKey(51)
	a.NoError(err)

	a.Equal(sig.VerifyingKey, *key.GetSigner().GetVerifyingKey())

	proof, err := signer.Tree.Prove([]uint64{1})
	a.NoError(err)
	a.Equal(Proof(*proof), sig.Proof)

	a.NotEqual(nil, sig.ByteSignature)
}

func genHashableForTest() crypto.Hashable {
	hashable := TestingHashable{[]byte("test msg")}

	return hashable
}

func TestSigning(t *testing.T) {
	partitiontest.PartitionTest(t)
	a := require.New(t)

	start, end := uint64(50), uint64(100)
	signer := generateTestSigner(crypto.FalconType, start, end, 1, a)
	defer signer.keyStore.store.Close()

	hashable := genHashableForTest()

	sig, err := signer.Sign(hashable, start)
	a.NoError(err)
	a.NoError(signer.GetVerifier().Verify(start, start, 1, hashable, sig))

	_, err = signer.Sign(hashable, start-1)
	a.Error(err)

	_, err = signer.Sign(hashable, end+1)
	a.Error(err)

	signer = generateTestSigner(crypto.FalconType, start, end, 10, a)
	defer signer.keyStore.store.Close()

	sig, err = signer.Sign(hashable, start)
	a.NoError(err)
	a.NoError(signer.GetVerifier().Verify(start, start, 1, hashable, sig))

	sig, err = signer.Sign(hashable, start+5)
	a.Error(err)
	a.Error(signer.GetVerifier().Verify(start, start+5, 1, hashable, sig))

	signer = generateTestSigner(crypto.FalconType, 50, 100, 12, a)
	defer signer.keyStore.store.Close()
	a.Equal(length(signer, a), 4)

	for i := uint64(50); i < 100; i++ {
		if i%12 != 0 {
			_, err = signer.Sign(hashable, i)
			a.Error(err)
		} else {
			sig, err = signer.Sign(hashable, i)
			a.NoError(err)
			a.NoError(signer.GetVerifier().Verify(50, i, 12, hashable, sig))
		}
	}

	signer = generateTestSigner(crypto.FalconType, 234, 4634, 128, a)
	defer signer.keyStore.store.Close()
	_, err = signer.keyStore.GetKey(256)
	a.NoError(err)
	_, err = signer.keyStore.GetKey(4096)
	a.NoError(err)
	_, err = signer.keyStore.GetKey(234 + 128)
	a.Error(err)
}

func TestBadRound(t *testing.T) {
	partitiontest.PartitionTest(t)
	a := require.New(t)

	start, _, signer := generateTestSignerAux(a)
	defer signer.keyStore.store.Close()
	hashable, sig := makeSig(signer, start, a)

	a.Error(signer.GetVerifier().Verify(0, start, 1, hashable, sig))
	a.Error(signer.GetVerifier().Verify(start, start+1, 1, hashable, sig))

	hashable, sig = makeSig(signer, start+1, a)
	a.Error(signer.GetVerifier().Verify(start, start, 1, hashable, sig))
	a.Error(signer.GetVerifier().Verify(start, start+2, 1, hashable, sig))
}

func TestBadMerkleProofInSignature(t *testing.T) {
	partitiontest.PartitionTest(t)
	a := require.New(t)

	start, _, signer := generateTestSignerAux(a)
	defer signer.keyStore.store.Close()
	hashable, sig := makeSig(signer, start, a)

	sig2 := copySig(sig)
	sig2.Proof.Path = sig2.Proof.Path[:len(sig2.Proof.Path)-1]
	a.Error(signer.GetVerifier().Verify(start, start, 1, hashable, sig2))

	sig3 := copySig(sig)
	someDigest := crypto.Digest{}
	rand.Read(someDigest[:])
	sig3.Proof.Path[0] = someDigest[:]
	a.Error(signer.GetVerifier().Verify(start, start, 1, hashable, sig3))
}

func copySig(sig Signature) Signature {
	bsig := make([]byte, len(sig.ByteSignature))
	copy(bsig, sig.ByteSignature)

	return Signature{
		ByteSignature: bsig,
		Proof:         copyProof(sig.Proof),
		VerifyingKey:  sig.VerifyingKey,
	}
}

func copyProof(proof Proof) Proof {
	path := make([]crypto.GenericDigest, len(proof.Path))
	for i, digest := range proof.Path {
		path[i] = make([]byte, len(digest))
		copy(path[i], digest)
	}
	return Proof{
		Path:        path,
		HashFactory: proof.HashFactory,
	}
}

func TestIncorrectByteSignature(t *testing.T) {
	partitiontest.PartitionTest(t)
	a := require.New(t)

	start, _, signer := generateTestSignerAux(a)
	defer signer.keyStore.store.Close()
	hashable, sig := makeSig(signer, start, a)

	sig2 := sig
	bs := make([]byte, len(sig.ByteSignature))
	copy(bs, sig2.ByteSignature)
	bs[0]++
	sig2.ByteSignature = bs
	a.Error(signer.GetVerifier().Verify(start, start, 1, hashable, sig2))
}

func TestAttemptToUseDifferentKey(t *testing.T) {
	partitiontest.PartitionTest(t)
	a := require.New(t)
	var err error

	start, _, signer := generateTestSignerAux(a)
	defer signer.keyStore.store.Close()
	hashable, sig := makeSig(signer, start+1, a)
	// taking signature for specific round and changing the round

	// taking signature and changing the key to match different round
	sig2 := sig
	key, err := signer.keyStore.GetKey(start)
	a.NoError(err)

	sig2.VerifyingKey = *(key.GetSigner().GetVerifyingKey())
	a.Error(signer.GetVerifier().Verify(start, start+1, 1, hashable, sig2))
}

func TestMarshal(t *testing.T) {
	partitiontest.PartitionTest(t)
	a := require.New(t)

	signer := generateTestSigner(crypto.FalconType, 0, 10, 1, a)
	store := signer.keyStore.store
	defer store.Close()

	out := protocol.Encode(signer)
	decodeInto := &Signer{}
	a.NoError(protocol.Decode(out, decodeInto))
	decodeInto.keyStore.store = store // restore PersistentKeystore
	a.Equal(signer, decodeInto)

	verifier := signer.GetVerifier()
	bs := protocol.Encode(verifier)
	verifierToDecodeInto := Verifier{}
	protocol.Decode(bs, &verifierToDecodeInto)
	a.Equal(*verifier, verifierToDecodeInto)
}

func TestSignerTrim(t *testing.T) {
	partitiontest.PartitionTest(t)
	a := require.New(t)
	var err error

	signer := generateTestSigner(crypto.FalconType, 1, 100, 1, a)
	defer signer.keyStore.store.Close()

	_, err = signer.Trim(1)
	a.NoError(err)
	a.Equal(signer.FirstValid, uint64(1))
	a.Equal(length(signer, a), 99)

	_, err = signer.Trim(10)
	a.NoError(err)
	a.Equal(length(signer, a), 90)

	signer.Trim(20)
	a.Equal(length(signer, a), 80)

	signer = generateTestSigner(crypto.FalconType, 1, 100, 11, a)
	defer signer.keyStore.store.Close()
	a.Equal(9, length(signer, a))

	// Should not trim, removes only keys <= round 10
	signer.Trim(10)
	a.Equal(signer.FirstValid, uint64(1))
	a.Equal(9, length(signer, a))

	// Should delete keys for rounds 11 and 22
	signer.Trim(22)
	a.Equal(signer.FirstValid, uint64(1))
	a.Equal(7, length(signer, a))

	signer.Trim(99)
	a.Equal(signer.FirstValid, uint64(1))
	a.Equal(length(signer, a), 0)

	// create signer and delete all keys.
	signer = generateTestSigner(crypto.FalconType, 1, 60, 1, a)
	defer signer.keyStore.store.Close()
	_, err = signer.Trim(60)
	a.NoError(err)
	a.Equal(0, length(signer, a))
	_, err = signer.Trim(61) // should not return error for rounds bigger than lastValid
	a.NoError(err)
	a.Equal(0, length(signer, a))

	signer = generateTestSigner(crypto.FalconType, 1, 60, 11, a)
	defer signer.keyStore.store.Close()
	_, err = signer.Trim(55)
	a.NoError(err)
	a.Equal(0, length(signer, a))
}

func TestKeyDeletion(t *testing.T) {
	partitiontest.PartitionTest(t)
	a := require.New(t)
	var err error

	signer := generateTestSigner(crypto.FalconType, 1, 60, 1, a)
	defer signer.keyStore.store.Close()

	signer.Trim(50)
	_, err = signer.Sign(genHashableForTest(), 50)
	a.Error(err)

	for i := uint64(51); i <= 60; i++ {
		sig, err := signer.Sign(genHashableForTest(), i)
		a.NoError(err)

		a.NoError(signer.GetVerifier().Verify(1, i, 1, genHashableForTest(), sig))
	}

	signer = generateTestSigner(crypto.FalconType, 1, 60, 11, a)
	defer signer.keyStore.store.Close()

	signer.Trim(50)
	_, err = signer.Sign(genHashableForTest(), 49)
	a.Error(err)

	for i := uint64(50); i <= 60; i++ {
		sig, err := signer.Sign(genHashableForTest(), i)
		if i%11 != 0 {
			a.Error(err)
			continue
		}
		a.NoError(signer.GetVerifier().Verify(1, i, 11, genHashableForTest(), sig))
	}
}

func TestNumberOfGeneratedKeys(t *testing.T) {
	partitiontest.PartitionTest(t)
	a := require.New(t)
	interval := uint64(128)
	validPeriod := uint64((1<<8)*interval - 1)

	store := initTestDB(a)
	defer store.Close()
	firstValid := uint64(1000)
	lastValid := validPeriod + 1000
	s, err := New(firstValid, lastValid, interval, crypto.Ed25519Type, *store)
	a.NoError(err)
	err = s.Persist()
	a.NoError(err)
	a.Equal(1<<8, length(s, a))

	store = initTestDB(a)
	defer store.Close()
	firstValid = uint64(0)
	lastValid = validPeriod
	s, err = New(firstValid, lastValid, interval, crypto.Ed25519Type, *store)
	a.NoError(err)
	err = s.Persist()
	a.NoError(err)
	a.Equal((1<<8)-1, length(s, a))

	store = initTestDB(a)
	defer store.Close()
	firstValid = uint64(1000)
	lastValid = validPeriod + 1000 - (interval * 50)
	s, err = New(firstValid, lastValid, interval, crypto.Ed25519Type, *store)
	a.NoError(err)
	err = s.Persist()
	a.NoError(err)
	a.Equal((1<<8)-50, length(s, a))
}

//#region Helper Functions
func makeSig(signer *Signer, sigRound uint64, a *require.Assertions) (crypto.Hashable, Signature) {
	hashable := genHashableForTest()

	sig, err := signer.Sign(hashable, sigRound)
	a.NoError(err)
	a.NoError(signer.GetVerifier().Verify(signer.FirstValid, sigRound, 1, hashable, sig))
	return hashable, sig
}

func generateTestSignerAux(a *require.Assertions) (uint64, uint64, *Signer) {
	start, end := uint64(50), uint64(100)
	signer := generateTestSigner(crypto.FalconType, start, end, 1, a)
	return start, end, signer
}

func generateTestSigner(t crypto.AlgorithmType, firstValid, lastValid, interval uint64, a *require.Assertions) *Signer {
	store := initTestDB(a)
	signer, err := New(firstValid, lastValid, interval, t, *store)
	a.NoError(err)

	err = signer.Persist()
	a.NoError(err)

	return signer
}

func initTestDB(a *require.Assertions) *db.Accessor {
	tmpname := uuid.NewV4().String() // could this just be a constant string instead? does it even matter?
	store, err := db.MakeAccessor(tmpname, false, true)
	a.NoError(err)
	a.NotNil(store)

	err = store.Atomic(func(ctx context.Context, tx *sql.Tx) error {
		_, err = tx.Exec(`CREATE TABLE schema (
			tablename TEXT PRIMARY KEY,
			version INTEGER
		);`)
		return err
	})
	a.NoError(err)

	return &store
}

func length(s *Signer, a *require.Assertions) int {
	p := s.keyStore
	var count int
	err := p.store.Atomic(func(ctx context.Context, tx *sql.Tx) error {
		row := tx.QueryRow("SELECT COUNT(*) FROM StateProofKeys")
		err := row.Scan(&count)
		if err != nil {
			return fmt.Errorf("failed to count rows in table StateProofKeys : %w", err)
		}
		return nil
	})
	a.NoError(err)
	return count
}

//#endregion
