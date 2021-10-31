package cfalcon

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"testing"

	"github.com/algorand/go-algorand/test/partitiontest"
	"github.com/stretchr/testify/require"
)

func TestFalconSignAndVerify(t *testing.T) {
	partitiontest.PartitionTest(t)

	a := require.New(t)
	for i := 0; i < 100; i++ {
		sk, pk, err := GenerateKey([]byte("seed"))
		a.NoError(err)

		b := make([]byte, 8)
		binary.BigEndian.PutUint64(b, uint64(i))
		bs := sha256.Sum256(b)

		sig, err := sk.SignBytes(bs[:])
		a.NoError(err)

		err = pk.VerifyBytes(bs[:], sig[:])
		a.NoError(err)

	}
}

func TestFalconWrongSignature(t *testing.T) {
	partitiontest.PartitionTest(t)

	a := require.New(t)
	sk, pk, err := GenerateKey([]byte("seed"))
	a.NoError(err)

	b := make([]byte, 8)
	binary.BigEndian.PutUint64(b, uint64(0))
	bs := sha256.Sum256(b)

	sig, err := sk.SignBytes(bs[:])
	a.NoError(err)

	sig[0] = sig[0] + 1
	err = pk.VerifyBytes(bs[:], sig[:])
	a.Error(err)
}

func TestFalconSignDifferentSeed(t *testing.T) {
	partitiontest.PartitionTest(t)

	a := require.New(t)
	sk, pk, err := GenerateKey([]byte("seed2"))
	a.NoError(err)

	b := make([]byte, 8)
	binary.BigEndian.PutUint64(b, uint64(0))
	bs := sha256.Sum256(b)

	sig, err := sk.SignBytes(bs[:])
	a.NoError(err)

	err = pk.VerifyBytes(bs[:], sig[:])
	a.NoError(err)
}

func TestFalconSignEmptySeed(t *testing.T) {
	partitiontest.PartitionTest(t)

	a := require.New(t)
	sk, pk, err := GenerateKey([]byte{})
	a.NoError(err)

	b := make([]byte, 8)
	binary.BigEndian.PutUint64(b, uint64(0))
	bs := sha256.Sum256(b)

	sig, err := sk.SignBytes(bs[:])
	a.NoError(err)

	err = pk.VerifyBytes(bs[:], sig[:])
	a.NoError(err)
}

func TestFalconEmptySignature(t *testing.T) {
	partitiontest.PartitionTest(t)

	a := require.New(t)
	sk, pk, err := GenerateKey([]byte("seed"))
	a.NoError(err)

	var bs [0]byte

	sig, err := sk.SignBytes(bs[:])
	a.NoError(err)

	err = pk.VerifyBytes(bs[:], sig[:])
	a.NoError(err)
}

func TestFalconVerifySmallSignature(t *testing.T) {
	partitiontest.PartitionTest(t)

	a := require.New(t)
	sk, pk, err := GenerateKey([]byte("seed"))
	a.NoError(err)

	b := make([]byte, 8)
	binary.BigEndian.PutUint64(b, uint64(0))
	bs := sha256.Sum256(b)

	_, err = sk.SignBytes(bs[:])
	a.NoError(err)

	var sig [4]byte
	err = pk.VerifyBytes(bs[:], sig[:])
	a.EqualError(err, ErrBadFalconSignatureTooSmall.Error())
}

func BenchmarkFalconKeyGen(b *testing.B) {
	for i := 0; i < b.N; i++ {
		GenerateKey([]byte("seed"))
	}
}

func BenchmarkFalconSign(b *testing.B) {
	a := require.New(b)

	sk, _, err := GenerateKey([]byte("seed"))

	strs := make([][64]byte, b.N)

	for i := 0; i < b.N; i++ {
		var msg [64]byte
		rand.Read(msg[:])
		strs[i] = msg
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		sk.SignBytes(strs[i][:])
	}

	a.NoError(err)
}

func BenchmarkFalconVerify(b *testing.B) {
	a := require.New(b)

	sk, pk, err := GenerateKey([]byte("seed"))

	strs := make([][64]byte, b.N)
	sigs := make([][]byte, b.N)
	for i := 0; i < b.N; i++ {
		var msg [64]byte
		rand.Read(msg[:])
		strs[i] = msg
		sigs[i], err = sk.SignBytes(msg[:])
		a.NoError(err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = pk.VerifyBytes(strs[i][:], sigs[i][:])
	}

	a.NoError(err)
}
