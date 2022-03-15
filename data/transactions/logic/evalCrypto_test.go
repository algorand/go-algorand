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

package logic

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"fmt"
	"math/big"
	"strconv"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/crypto/secp256k1"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/transactions"
	"github.com/algorand/go-algorand/test/partitiontest"
)

func TestKeccak256(t *testing.T) {
	partitiontest.PartitionTest(t)

	t.Parallel()
	/*
		pip install sha3
		import sha3
		blob=b'fnord'
		sha3.keccak_256(blob).hexdigest()
	*/
	progText := `byte 0x666E6F7264
keccak256
byte 0xc195eca25a6f4c82bfba0287082ddb0d602ae9230f9cf1f1a40b68f8e2c41567
==`
	testAccepts(t, progText, 1)
}

func TestSHA3_256(t *testing.T) {
	partitiontest.PartitionTest(t)

	t.Parallel()
	/*
		pip install hashlib
		import hashlib
		hashlib.sha3_256(b"fnord").hexdigest()
	*/
	progText := `byte 0x666E6F7264
sha3_256
byte 0xd757297405c5c89f7ceca368ee76c2f1893ee24f654e60032e65fb53b01aae10
==`
	testAccepts(t, progText, 7)
}

func TestSHA512_256(t *testing.T) {
	partitiontest.PartitionTest(t)

	t.Parallel()
	/*
		pip cryptography
		from cryptography.hazmat.backends import default_backend
		from cryptography.hazmat.primitives import hashes
		import base64
		digest = hashes.Hash(hashes.SHA512_256(), backend=default_backend())
		digest.update(b'fnord')
		base64.b16encode(digest.finalize())
	*/
	progText := `byte 0x666E6F7264
sha512_256

byte 0x98D2C31612EA500279B6753E5F6E780CA63EBA8274049664DAD66A2565ED1D2A
==`
	testAccepts(t, progText, 1)
}

func TestEd25519verify(t *testing.T) {
	partitiontest.PartitionTest(t)

	t.Parallel()
	var s crypto.Seed
	crypto.RandBytes(s[:])
	c := crypto.GenerateSignatureSecrets(s)
	msg := "62fdfc072182654f163f5f0f9a621d729566c74d0aa413bf009c9800418c19cd"
	data, err := hex.DecodeString(msg)
	require.NoError(t, err)
	pk := basics.Address(c.SignatureVerifier)
	pkStr := pk.String()

	for v := uint64(1); v <= AssemblerMaxVersion; v++ {
		t.Run(fmt.Sprintf("v=%d", v), func(t *testing.T) {
			ops := testProg(t, fmt.Sprintf(`arg 0
arg 1
addr %s
ed25519verify`, pkStr), v)
			sig := c.Sign(Msg{
				ProgramHash: crypto.HashObj(Program(ops.Program)),
				Data:        data[:],
			})
			var txn transactions.SignedTxn
			txn.Lsig.Logic = ops.Program
			txn.Lsig.Args = [][]byte{data[:], sig[:]}
			testLogicBytes(t, ops.Program, defaultEvalParams(&txn))

			// short sig will fail
			txn.Lsig.Args[1] = sig[1:]
			testLogicBytes(t, ops.Program, defaultEvalParams(&txn), "invalid signature")

			// flip a bit and it should not pass
			msg1 := "52fdfc072182654f163f5f0f9a621d729566c74d0aa413bf009c9800418c19cd"
			data1, err := hex.DecodeString(msg1)
			require.NoError(t, err)
			txn.Lsig.Args = [][]byte{data1, sig[:]}
			testLogicBytes(t, ops.Program, defaultEvalParams(&txn), "REJECT")
		})
	}
}

func TestEd25519VerifyBare(t *testing.T) {
	partitiontest.PartitionTest(t)

	t.Parallel()
	var s crypto.Seed
	crypto.RandBytes(s[:])
	c := crypto.GenerateSignatureSecrets(s)
	msg := "62fdfc072182654f163f5f0f9a621d729566c74d0aa413bf009c9800418c19cd"
	data, err := hex.DecodeString(msg)
	require.NoError(t, err)
	pk := basics.Address(c.SignatureVerifier)
	pkStr := pk.String()

	for v := uint64(7); v <= AssemblerMaxVersion; v++ {
		t.Run(fmt.Sprintf("v=%d", v), func(t *testing.T) {
			ops := testProg(t, fmt.Sprintf(`arg 0
arg 1
addr %s
ed25519verify_bare`, pkStr), v)
			require.NoError(t, err)
			sig := c.SignBytes(data)
			var txn transactions.SignedTxn
			txn.Lsig.Logic = ops.Program
			txn.Lsig.Args = [][]byte{data[:], sig[:]}
			testLogicBytes(t, ops.Program, defaultEvalParams(&txn))

			// short sig will fail
			txn.Lsig.Args[1] = sig[1:]
			testLogicBytes(t, ops.Program, defaultEvalParams(&txn), "invalid signature")

			// flip a bit and it should not pass
			msg1 := "52fdfc072182654f163f5f0f9a621d729566c74d0aa413bf009c9800418c19cd"
			data1, err := hex.DecodeString(msg1)
			require.NoError(t, err)
			txn.Lsig.Args = [][]byte{data1, sig[:]}
			testLogicBytes(t, ops.Program, defaultEvalParams(&txn), "REJECT")
		})
	}
}

// bitIntFillBytes is a replacement for big.Int.FillBytes from future Go
func bitIntFillBytes(b *big.Int, buf []byte) []byte {
	for i := range buf {
		buf[i] = 0
	}
	bytes := b.Bytes()
	if len(bytes) > len(buf) {
		panic(fmt.Sprintf("bitIntFillBytes: has %d but got %d buffer", len(bytes), len(buf)))
	}
	copy(buf[len(buf)-len(bytes):], bytes)
	return buf
}

func keyToByte(tb testing.TB, b *big.Int) []byte {
	k := make([]byte, 32)
	require.NotPanics(tb, func() {
		k = bitIntFillBytes(b, k)
	})
	return k
}

func TestLeadingZeros(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	b := big.NewInt(0x100)
	r, err := leadingZeros(1, b)
	require.Error(t, err)
	require.Nil(t, r)

	b = big.NewInt(100)
	r, err = leadingZeros(1, b)
	require.NoError(t, err)
	require.Equal(t, []byte{100}, r)

	b = big.NewInt(100)
	r, err = leadingZeros(2, b)
	require.NoError(t, err)
	require.Equal(t, []byte{0, 100}, r)

	v32, err := hex.DecodeString("71a5910445820f57989c027bdf9391c80097874d249e0f38bf90834fdec2877f")
	require.NoError(t, err)
	b = new(big.Int).SetBytes(v32)
	r, err = leadingZeros(32, b)
	require.NoError(t, err)
	require.Equal(t, v32, r)

	v31 := v32[1:]
	b = new(big.Int).SetBytes(v31)
	r, err = leadingZeros(32, b)
	require.NoError(t, err)
	v31z := append([]byte{0}, v31...)
	require.Equal(t, v31z, r)

	require.Equal(t, v31z, keyToByte(t, b))
}

func TestEcdsaWithSecp256k1(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	key, err := ecdsa.GenerateKey(secp256k1.S256(), rand.Reader)
	require.NoError(t, err)
	pk := secp256k1.CompressPubkey(key.PublicKey.X, key.PublicKey.Y)
	sk := keyToByte(t, key.D)
	x := keyToByte(t, key.PublicKey.X)
	y := keyToByte(t, key.PublicKey.Y)

	// ecdsa decompress tests
	source := `
byte 0x%s
ecdsa_pk_decompress Secp256k1
store 0
byte 0x%s
==
load 0
byte 0x%s
==
&&`
	pkTampered1 := make([]byte, len(pk))
	copy(pkTampered1, pk)
	pkTampered1[0] = 0                     // first byte is a prefix of either 0x02 or 0x03
	pkTampered2 := make([]byte, len(pk)-1) // must be 33 bytes length
	copy(pkTampered2, pk)

	var decompressTests = []struct {
		key  []byte
		pass bool
	}{
		{pk, true},
		{pkTampered1, false},
		{pkTampered2, false},
	}
	for i, test := range decompressTests {
		t.Run(fmt.Sprintf("decompress/pass=%v", test.pass), func(t *testing.T) {
			t.Log("decompressTests i", i)
			src := fmt.Sprintf(source, hex.EncodeToString(test.key), hex.EncodeToString(x), hex.EncodeToString(y))
			if test.pass {
				testAccepts(t, src, 5)
			} else {
				testPanics(t, src, 5)
			}
		})
	}

	// ecdsa verify tests
	source = `
byte "%s"
sha512_256
byte 0x%s
byte 0x%s
byte 0x%s
byte 0x%s
ecdsa_verify Secp256k1
`
	data := []byte("testdata")
	msg := sha512.Sum512_256(data)

	sign, err := secp256k1.Sign(msg[:], sk)
	require.NoError(t, err)
	r := sign[:32]
	s := sign[32:64]
	v := int(sign[64])

	rTampered := make([]byte, len(r))
	copy(rTampered, r)
	rTampered[0] += byte(1) // intentional overflow

	var verifyTests = []struct {
		data string
		r    []byte
		pass bool
	}{
		{"testdata", r, true},
		{"testdata", rTampered, false},
		{"testdata1", r, false},
	}
	for _, test := range verifyTests {
		t.Run(fmt.Sprintf("verify/pass=%v", test.pass), func(t *testing.T) {
			src := fmt.Sprintf(source, test.data, hex.EncodeToString(test.r), hex.EncodeToString(s), hex.EncodeToString(x), hex.EncodeToString(y))
			if test.pass {
				testAccepts(t, src, 5)
			} else {
				testRejects(t, src, 5)
			}
		})
	}

	// ecdsa recover tests
	source = `
byte 0x%s
int %d
byte 0x%s
byte 0x%s
ecdsa_pk_recover Secp256k1
dup2
store 0
byte 0x%s
==
load 0
byte 0x%s
==
&&
store 1
concat // X + Y
byte 0x04
swap
concat // 0x04 + X + Y
byte 0x%s
==
load 1
&&`
	var recoverTests = []struct {
		v       int
		checker func(t *testing.T, program string, introduced uint64)
	}{
		{v, testAccepts},
		{v ^ 1, testRejects},
		{3, func(t *testing.T, program string, introduced uint64) {
			testPanics(t, program, introduced)
		}},
	}
	pkExpanded := secp256k1.S256().Marshal(key.PublicKey.X, key.PublicKey.Y)

	for i, test := range recoverTests {
		t.Run(fmt.Sprintf("recover/%d", i), func(t *testing.T) {
			src := fmt.Sprintf(source, hex.EncodeToString(msg[:]), test.v, hex.EncodeToString(r), hex.EncodeToString(s), hex.EncodeToString(x), hex.EncodeToString(y), hex.EncodeToString(pkExpanded))
			test.checker(t, src, 5)
		})
	}

	// sample sequencing: decompress + verify
	source = fmt.Sprintf(`#pragma version 5
byte "testdata"
sha512_256
byte 0x%s
byte 0x%s
byte 0x%s
ecdsa_pk_decompress Secp256k1
ecdsa_verify Secp256k1`, hex.EncodeToString(r), hex.EncodeToString(s), hex.EncodeToString(pk))
	ops := testProg(t, source, 5)
	var txn transactions.SignedTxn
	txn.Lsig.Logic = ops.Program
	pass, err := EvalSignature(0, defaultEvalParamsWithVersion(&txn, 5))
	require.NoError(t, err)
	require.True(t, pass)
}

// MarshalCompressed converts a point on the curve into the compressed form
// specified in section 4.3.6 of ANSI X9.62.
//
// TODO: replace with elliptic.MarshalCompressed when updating to go 1.15+
func marshalCompressed(curve elliptic.Curve, x, y *big.Int) []byte {
	byteLen := (curve.Params().BitSize + 7) / 8
	compressed := make([]byte, 1+byteLen)
	compressed[0] = byte(y.Bit(0)) | 2
	bitIntFillBytes(x, compressed[1:])
	return compressed
}

func TestEcdsaWithSecp256r1(t *testing.T) {
	if LogicVersion < fidoVersion {
		return
	}

	partitiontest.PartitionTest(t)
	t.Parallel()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	pk := marshalCompressed(elliptic.P256(), key.X, key.Y)
	x := keyToByte(t, key.PublicKey.X)
	y := keyToByte(t, key.PublicKey.Y)

	// ecdsa decompress tests
	source := `
byte 0x%s
ecdsa_pk_decompress Secp256r1
store 0
byte 0x%s
==
load 0
byte 0x%s
==
&&`
	pkTampered1 := make([]byte, len(pk))
	copy(pkTampered1, pk)
	pkTampered1[0] = 0                     // first byte is a prefix of either 0x02 or 0x03
	pkTampered2 := make([]byte, len(pk)-1) // must be 33 bytes length
	copy(pkTampered2, pk)

	var decompressTests = []struct {
		key  []byte
		pass bool
	}{
		{pk, true},
		{pkTampered1, false},
		{pkTampered2, false},
	}
	for i, test := range decompressTests {
		t.Run(fmt.Sprintf("decompress/pass=%v", test.pass), func(t *testing.T) {
			t.Log("decompressTests i", i)
			src := fmt.Sprintf(source, hex.EncodeToString(test.key), hex.EncodeToString(x), hex.EncodeToString(y))
			if test.pass {
				testAcceptsWithField(t, src, 5, fidoVersion)
			} else {
				testPanicsWithField(t, src, 5, fidoVersion)
			}
		})
	}

	// ecdsa verify tests
	source = `
byte "%s"
sha512_256
byte 0x%s
byte 0x%s
byte 0x%s
byte 0x%s
ecdsa_verify Secp256r1
`
	data := []byte("testdata")
	msg := sha512.Sum512_256(data)

	ri, si, err := ecdsa.Sign(rand.Reader, key, msg[:])
	require.NoError(t, err)
	r := ri.Bytes()
	s := si.Bytes()

	rTampered := make([]byte, len(r))
	copy(rTampered, r)
	rTampered[0] += byte(1) // intentional overflow

	var verifyTests = []struct {
		data string
		r    []byte
		pass bool
	}{
		{"testdata", r, true},
		{"testdata", rTampered, false},
		{"testdata1", r, false},
	}
	for _, test := range verifyTests {
		t.Run(fmt.Sprintf("verify/pass=%v", test.pass), func(t *testing.T) {
			src := fmt.Sprintf(source, test.data, hex.EncodeToString(test.r), hex.EncodeToString(s), hex.EncodeToString(x), hex.EncodeToString(y))
			if test.pass {
				testAcceptsWithField(t, src, 5, fidoVersion)
			} else {
				testRejectsWithField(t, src, 5, fidoVersion)
			}
		})
	}

	// sample sequencing: decompress + verify
	source = fmt.Sprintf(`#pragma version `+strconv.Itoa(fidoVersion)+`
byte "testdata"
sha512_256
byte 0x%s
byte 0x%s
byte 0x%s
ecdsa_pk_decompress Secp256r1
ecdsa_verify Secp256r1`, hex.EncodeToString(r), hex.EncodeToString(s), hex.EncodeToString(pk))
	ops := testProg(t, source, fidoVersion)
	var txn transactions.SignedTxn
	txn.Lsig.Logic = ops.Program
	pass, err := EvalSignature(0, defaultEvalParamsWithVersion(&txn, fidoVersion))
	require.NoError(t, err)
	require.True(t, pass)
}

// test compatibility with ethereum signatures
func TestEcdsaEthAddress(t *testing.T) {
	/*
		pip install eth-keys pycryptodome
		from eth_keys import keys
		pk = keys.PrivateKey(b"\xb2\\}\xb3\x1f\xee\xd9\x12''\xbf\t9\xdcv\x9a\x96VK-\xe4\xc4rm\x03[6\xec\xf1\xe5\xb3d")
		msg=b"hello from ethereum"
		print("msg: '{}'".format(msg.decode()))
		signature = pk.sign_msg(msg)
		print("v:", signature.v)
		print("r:", signature.r.to_bytes(32, byteorder="big").hex())
		print("s:", signature.s.to_bytes(32, byteorder="big").hex())
		print("addr:", pk.public_key.to_address())
	*/
	progText := `byte "hello from ethereum" // msg
keccak256
int 0 // v
byte 0x745e8f55ac6189ee89ed707c36694868e3903988fbf776c8096c45da2e60c638 // r
byte 0x30c8e4a9b5d2eb53ddc6294587dd00bed8afe2c45dd72f6b4cf752e46d5ba681 // s
ecdsa_pk_recover Secp256k1
concat // convert public key X and Y to ethereum addr
keccak256
substring 12 32
byte 0x5ce9454909639d2d17a3f753ce7d93fa0b9ab12e // addr
==`
	testAccepts(t, progText, 5)
}

func BenchmarkHash(b *testing.B) {
	for _, hash := range []string{"sha256", "keccak256", "sha512_256"} {
		b.Run(hash+"-small", func(b *testing.B) { // hash 32 bytes
			benchmarkOperation(b, "int 32; bzero", hash, "pop; int 1")
		})
		b.Run(hash+"-med", func(b *testing.B) { // hash 128 bytes
			benchmarkOperation(b, "int 32; bzero",
				"dup; concat; dup; concat;"+hash, "pop; int 1")
		})
		b.Run(hash+"-big", func(b *testing.B) { // hash 512 bytes
			benchmarkOperation(b, "int 32; bzero",
				"dup; concat; dup; concat; dup; concat; dup; concat;"+hash, "pop; int 1")
		})
	}
}

func BenchmarkSha256Raw(b *testing.B) {
	addr, _ := basics.UnmarshalChecksumAddress("OC6IROKUJ7YCU5NV76AZJEDKYQG33V2CJ7HAPVQ4ENTAGMLIOINSQ6EKGE")
	a := addr[:]
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		t := sha256.Sum256(a)
		a = t[:]
	}
}

func BenchmarkEd25519Verifyx1(b *testing.B) {
	//benchmark setup
	var data [][32]byte
	var programs [][]byte
	var signatures []crypto.Signature

	for i := 0; i < b.N; i++ {
		var buffer [32]byte //generate data to be signed
		crypto.RandBytes(buffer[:])
		data = append(data, buffer)

		var s crypto.Seed //generate programs and signatures
		crypto.RandBytes(s[:])
		secret := crypto.GenerateSignatureSecrets(s)
		pk := basics.Address(secret.SignatureVerifier)
		pkStr := pk.String()
		ops, err := AssembleStringWithVersion(fmt.Sprintf(`arg 0
arg 1
addr %s
ed25519verify`, pkStr), AssemblerMaxVersion)
		require.NoError(b, err)
		programs = append(programs, ops.Program)
		sig := secret.Sign(Msg{
			ProgramHash: crypto.HashObj(Program(ops.Program)),
			Data:        buffer[:],
		})
		signatures = append(signatures, sig)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		var txn transactions.SignedTxn
		txn.Lsig.Logic = programs[i]
		txn.Lsig.Args = [][]byte{data[i][:], signatures[i][:]}
		ep := defaultEvalParams(&txn)
		pass, err := EvalSignature(0, ep)
		if !pass {
			b.Log(hex.EncodeToString(programs[i]))
			b.Log(ep.Trace.String())
		}
		if err != nil {
			require.NoError(b, err)
		}
		if !pass {
			require.True(b, pass)
		}
	}
}

type benchmarkEcdsaData struct {
	x        []byte
	y        []byte
	pk       []byte
	msg      [32]byte
	r        []byte
	s        []byte
	v        int
	programs []byte
}

func benchmarkEcdsaGenData(b *testing.B, curve EcdsaCurve) (data []benchmarkEcdsaData) {
	data = make([]benchmarkEcdsaData, b.N)
	for i := 0; i < b.N; i++ {
		var key *ecdsa.PrivateKey
		if curve == Secp256k1 {
			var err error
			key, err = ecdsa.GenerateKey(secp256k1.S256(), rand.Reader)
			require.NoError(b, err)
		} else if curve == Secp256r1 {
			var err error
			key, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			require.NoError(b, err)
		}
		sk := keyToByte(b, key.D)
		data[i].x = keyToByte(b, key.PublicKey.X)
		data[i].y = keyToByte(b, key.PublicKey.Y)
		if curve == Secp256k1 {
			data[i].pk = secp256k1.CompressPubkey(key.PublicKey.X, key.PublicKey.Y)
		} else if curve == Secp256r1 {
			data[i].pk = marshalCompressed(elliptic.P256(), key.PublicKey.X, key.PublicKey.Y)
		}

		d := []byte("testdata")
		data[i].msg = sha512.Sum512_256(d)

		if curve == Secp256k1 {
			sign, err := secp256k1.Sign(data[i].msg[:], sk)
			require.NoError(b, err)
			data[i].r = sign[:32]
			data[i].s = sign[32:64]
			data[i].v = int(sign[64])
		} else if curve == Secp256r1 {
			r, s, err := ecdsa.Sign(rand.Reader, key, data[i].msg[:])
			require.NoError(b, err)
			data[i].r = r.Bytes()
			data[i].s = s.Bytes()
		}
	}
	return data
}

func benchmarkEcdsa(b *testing.B, source string, curve EcdsaCurve) {
	data := benchmarkEcdsaGenData(b, curve)
	var version uint64
	if curve == Secp256k1 {
		version = 5
	} else if curve == Secp256r1 {
		version = 6
	}
	ops, err := AssembleStringWithVersion(source, version)
	require.NoError(b, err)
	for i := 0; i < b.N; i++ {
		data[i].programs = ops.Program
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		var txn transactions.SignedTxn
		txn.Lsig.Logic = data[i].programs
		txn.Lsig.Args = [][]byte{data[i].msg[:], data[i].r, data[i].s, data[i].x, data[i].y, data[i].pk, {uint8(data[i].v)}}
		ep := defaultEvalParams(&txn)
		pass, err := EvalSignature(0, ep)
		if !pass {
			b.Log(hex.EncodeToString(data[i].programs))
			b.Log(ep.Trace.String())
		}
		if err != nil {
			require.NoError(b, err)
		}
		if !pass {
			require.True(b, pass)
		}
	}
}

func BenchmarkEcdsa(b *testing.B) {
	b.Run("ecdsa_verify secp256k1", func(b *testing.B) {
		source := `#pragma version 5
arg 0
arg 1
arg 2
arg 3
arg 4
ecdsa_verify Secp256k1`
		benchmarkEcdsa(b, source, Secp256k1)
	})

	if LogicVersion >= fidoVersion {
		b.Run("ecdsa_verify secp256r1", func(b *testing.B) {
			source := `#pragma version ` + strconv.Itoa(fidoVersion) + `
	arg 0d
	arg 1
	arg 2
	arg 3
	arg 4
	ecdsa_verify Secp256r1`
			benchmarkEcdsa(b, source, Secp256r1)
		})
	}

	b.Run("ecdsa_pk_decompress Secp256k1", func(b *testing.B) {
		source := `#pragma version 5
arg 5
ecdsa_pk_decompress Secp256k1
pop
pop
int 1`
		benchmarkEcdsa(b, source, Secp256k1)
	})

	if LogicVersion >= fidoVersion {
		b.Run("ecdsa_pk_decompress Secp256r1", func(b *testing.B) {
			source := `#pragma version ` + strconv.Itoa(fidoVersion) + `
	arg 5
	ecdsa_pk_decompress Secp256r1
	pop
	pop
	int 1`
			benchmarkEcdsa(b, source, Secp256r1)
		})
	}

	b.Run("ecdsa_pk_recover Secp256k1", func(b *testing.B) {
		source := `#pragma version 5
arg 0
arg 6
btoi
arg 1
arg 2
ecdsa_pk_recover Secp256k1
pop
pop
int 1`
		benchmarkEcdsa(b, source, Secp256k1)
	})
}
