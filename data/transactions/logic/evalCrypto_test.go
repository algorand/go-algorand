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
	mrand "math/rand"
	"strconv"
	"testing"

	"github.com/consensys/gnark-crypto/ecc/bn254"
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

// This is patterned off vrf_test.go, but we don't create proofs here, we only
// check that the output is correct, given the proof.
func testVrfApp(pubkey, proof, data string, output string) string {
	source := `
byte 0x%s
byte 0x%s
byte 0x%s
vrf_verify VrfAlgorand
assert
byte 0x%s
==
`
	return fmt.Sprintf(source, data, proof, pubkey, output)
}

func TestVrfVerify(t *testing.T) {
	ep, _, _ := makeSampleEnv()
	testApp(t, notrack("int 1; int 2; int 3; vrf_verify VrfAlgorand"), ep, "arg 0 wanted")
	testApp(t, notrack("byte 0x1122; int 2; int 3; vrf_verify VrfAlgorand"), ep, "arg 1 wanted")
	testApp(t, notrack("byte 0x1122; byte 0x2233; int 3; vrf_verify VrfAlgorand"), ep, "arg 2 wanted")
	testLogic(t, "byte 0x1122; byte 0x2233; byte 0x3344; vrf_verify VrfAlgorand", LogicVersion, ep, "vrf proof wrong size")
	// 80 byte proof
	testLogic(t, "byte 0x1122; int 80; bzero; byte 0x3344; vrf_verify VrfAlgorand", LogicVersion, ep, "vrf pubkey wrong size")
	// 32 byte pubkey
	testLogic(t, "byte 0x3344; int 80; bzero; int 32; bzero; vrf_verify VrfAlgorand", LogicVersion, ep, "stack len is 2")

	// working app, but the verify itself fails
	testLogic(t, "byte 0x3344; int 80; bzero; int 32; bzero; vrf_verify VrfAlgorand; !; assert; int 64; bzero; ==", LogicVersion, ep)

	source := testVrfApp(
		"d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",                                                                                                 //pubkey
		"b6b4699f87d56126c9117a7da55bd0085246f4c56dbc95d20172612e9d38e8d7ca65e573a126ed88d4e30a46f80a666854d675cf3ba81de0de043c3774f061560f55edc256a787afe701677c0f602900", // proof
		"", // data
		"5b49b554d05c0cd5a5325376b3387de59d924fd1e13ded44648ab33c21349a603f25b84ec5ed887995b33da5e3bfcb87cd2f64521c4c62cf825cffabbe5d31cc", // output
	)
	testLogic(t, source, LogicVersion, ep)

	source = testVrfApp(
		"3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",                                                                                                 //pk
		"ae5b66bdf04b4c010bfe32b2fc126ead2107b697634f6f7337b9bff8785ee111200095ece87dde4dbe87343f6df3b107d91798c8a7eb1245d3bb9c5aafb093358c13e6ae1111a55717e895fd15f99f07", // pi
		"72", // alpha
		"94f4487e1b2fec954309ef1289ecb2e15043a2461ecc7b2ae7d4470607ef82eb1cfa97d84991fe4a7bfdfd715606bc27e2967a6c557cfb5875879b671740b7d8", // beta
	)
	testLogic(t, source, LogicVersion, ep)
}

// BenchMarkVerify is useful to see relative speeds of various crypto verify functions
func BenchmarkVerify(b *testing.B) {
	benches := [][]string{
		{"pop", "", "int 1234576; int 6712; pop; pop", "int 1"},
		{"add", "", "int 1234576; int 6712; +; pop", "int 1"},
		/*
					{"ed25519verify_bare", "", `byte 0x
			byte 0x
			addr
			ed25519verify_bare
			assert`, "int 1"},*/
		{"ecdsa_verify", "", `byte 0x71a5910445820f57989c027bdf9391c80097874d249e0f38bf90834fdec2877f
byte 0x5eb27782eb1a5df8de9a5d51613ad5ca730840ddf4af919c6feb15cde14f9978
byte 0x0cb3c0d636ed991ee030d09c295de3121eb166cb9e1552cf0ef0fb2358f35f0f
byte 0x79de0699673571df1de8486718d06a3e7838f6831ec4ef3fb963788fbfb773b7
byte 0xd76446a3393af3e2eefada16df80cc6a881a56f4cf41fa2ab4769c5708ce878d
ecdsa_verify Secp256k1
assert`, "int 1"},
		{"vrf_verify", "", `byte 0x3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c
byte 0xae5b66bdf04b4c010bfe32b2fc126ead2107b697634f6f7337b9bff8785ee111200095ece87dde4dbe87343f6df3b107d91798c8a7eb1245d3bb9c5aafb093358c13e6ae1111a55717e895fd15f99f07
byte 0x72
vrf_verify VrfAlgorand
assert							// make sure we're testing success
pop								// output`, "int 1"},
	}
	for _, bench := range benches {
		b.Run(bench[0], func(b *testing.B) {
			benchmarkOperation(b, bench[1], bench[2], bench[3])
		})
	}
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

func keyToByte(tb testing.TB, b *big.Int) []byte {
	k := make([]byte, 32)
	require.NotPanics(tb, func() {
		b.FillBytes(k)
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

func TestEcdsaWithSecp256r1(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	pk := elliptic.MarshalCompressed(elliptic.P256(), key.X, key.Y)
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
				testAccepts(t, src, fidoVersion)
			} else {
				testPanics(t, src, fidoVersion)
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
				testAccepts(t, src, fidoVersion)
			} else {
				testRejects(t, src, fidoVersion)
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
	partitiontest.PartitionTest(t)

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

func TestEcdsaCostVariation(t *testing.T) {
	partitiontest.PartitionTest(t)

	// Doesn't matter if the actual verify returns true or false. Just confirm the cost depends on curve.
	source := `
global ZeroAddress				// need 32 bytes
byte "signature r"
byte "signature s"
byte "PK x"
byte "PK y"
ecdsa_verify Secp256k1
!
assert
global OpcodeBudget
int ` + fmt.Sprintf("%d", 20_000-1700-8) + `
==
`
	testAccepts(t, source, 6) // Secp256k1 was 5, but OpcodeBudget is 6

	source = `
global ZeroAddress				// need 32 bytes
byte "signature r"
byte "signature s"
byte "PK x"
byte "PK y"
ecdsa_verify Secp256r1
!
assert
global OpcodeBudget
int ` + fmt.Sprintf("%d", 20_000-2500-8) + `
==
`
	testAccepts(t, source, fidoVersion)
}

func BenchmarkHash(b *testing.B) {
	for _, hash := range []string{"sha256", "keccak256", "sha512_256"} {
		b.Run(hash+"-0w", func(b *testing.B) { // hash 0 bytes
			benchmarkOperation(b, "", "byte 0x; "+hash+"; pop", "int 1")
		})
		b.Run(hash+"-32", func(b *testing.B) { // hash 32 bytes
			benchmarkOperation(b, "int 32; bzero", hash, "pop; int 1")
		})
		b.Run(hash+"-128", func(b *testing.B) { // hash 128 bytes
			benchmarkOperation(b, "int 32; bzero",
				"dup; concat; dup; concat;"+hash, "pop; int 1")
		})
		b.Run(hash+"-512", func(b *testing.B) { // hash 512 bytes
			benchmarkOperation(b, "int 32; bzero",
				"dup; concat; dup; concat; dup; concat; dup; concat;"+hash, "pop; int 1")
		})
		b.Run(hash+"-4096", func(b *testing.B) { // hash 4k bytes
			benchmarkOperation(b, "int 32; bzero",
				"dup; concat; dup; concat; dup; concat; dup; concat; dup; concat; dup; concat; dup; concat;"+hash, "pop; int 1")
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
			data[i].pk = elliptic.MarshalCompressed(elliptic.P256(), key.PublicKey.X, key.PublicKey.Y)
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
		version = fidoVersion
	}
	ops := testProg(b, source, version)
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
	arg 0
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

type benchmarkBn256Data struct {
	a        []byte
	k        []byte
	g1       []byte
	g2       []byte
	programs []byte
}

func benchmarkBn256DataGenData(b *testing.B) (data []benchmarkBn256Data) {
	data = make([]benchmarkBn256Data, b.N)
	var g1Gen bn254.G1Jac
	var g1GenAff bn254.G1Affine
	g1Gen.X.SetString("1")
	g1Gen.Y.SetString("2")
	g1Gen.Z.SetString("1")
	g1GenAff.FromJacobian(&g1Gen)
	var a bn254.G1Affine
	a.ScalarMultiplication(&g1GenAff, new(big.Int).SetUint64(mrand.Uint64()))

	for i := 0; i < b.N; i++ {
		var a bn254.G1Affine
		a.ScalarMultiplication(&g1GenAff, new(big.Int).SetUint64(mrand.Uint64()))

		data[i].a = bN254G1ToBytes(&a)
		data[i].k = new(big.Int).SetUint64(mrand.Uint64()).Bytes()

		// Pair one g1 and one g2
		data[i].g1, _ = hex.DecodeString("0ebc9fc712b13340c800793386a88385e40912a21bacad2cc7db17d36e54c802238449426931975cced7200f08681ab9a86a2e5c2336cf625451cf2413318e32")
		data[i].g2, _ = hex.DecodeString("217fbd9a9db5719cfbe3580e3d8750cada058fdfffe95c440a0528ffc608f36e05d6a67604658d40b3e4cac3c46150f2702d87739b7774d79a8147f7271773b420f9429ee13c1843404bfd70e75efa886c173e57dde32970274d8bc53dfd562403f6276318990d053785b4ca342ebc4581a23a39285804bb74e079aa2ef3ba66")
	}
	return data
}

func benchmarkBn256(b *testing.B, source string) {
	data := benchmarkBn256DataGenData(b)
	ops, err := AssembleStringWithVersion(source, 7)
	require.NoError(b, err)
	for i := 0; i < b.N; i++ {
		data[i].programs = ops.Program
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		var txn transactions.SignedTxn
		txn.Lsig.Logic = data[i].programs
		txn.Lsig.Args = [][]byte{data[i].a, data[i].k, data[i].g1, data[i].g2}
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

func BenchmarkBn256AddRaw(b *testing.B) {
	data := benchmarkBn256DataGenData(b)
	a1 := bytesToBN254G1(data[0].g1)
	a2 := bytesToBN254G1(data[0].g1)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = new(bn254.G1Affine).Add(&a1, &a2)
	}
}

func BenchmarkBn256AddWithMarshal(b *testing.B) {
	b.ResetTimer()
	var v [][]byte
	v = make([][]byte, b.N)
	g1, _ := hex.DecodeString("0ebc9fc712b13340c800793386a88385e40912a21bacad2cc7db17d36e54c802238449426931975cced7200f08681ab9a86a2e5c2336cf625451cf2413318e32")

	for i := 0; i < b.N; i++ {
		a1 := bytesToBN254G1(g1)
		a2 := bytesToBN254G1(g1)
		r := new(bn254.G1Affine).Add(&a1, &a2)
		v[i] = r.Marshal()
	}
}

func BenchmarkBn256PairingRaw(b *testing.B) {
	data := benchmarkBn256DataGenData(b)
	g1s := bytesToBN254G1s(data[0].g1)
	g2s := bytesToBN254G2s(data[0].g2)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ok, _ := bn254.PairingCheck(g1s, g2s)
		require.False(b, ok)
	}
}

func BenchmarkBn256(b *testing.B) {
	b.Run("bn256 add", func(b *testing.B) {
		benchmarkOperation(b, "byte 0x0ebc9fc712b13340c800793386a88385e40912a21bacad2cc7db17d36e54c802238449426931975cced7200f08681ab9a86a2e5c2336cf625451cf2413318e32", "dup; bn256_add", "pop; int 1")
	})

	b.Run("bn256 scalar mul", func(b *testing.B) {
		source := `#pragma version 7
arg 0
arg 1
bn256_scalar_mul
pop
int 1
`
		benchmarkBn256(b, source)
	})

	b.Run("bn256 pairing", func(b *testing.B) {
		source := `#pragma version 7
arg 2
arg 3
bn256_pairing
pop
int 1
`
		benchmarkBn256(b, source)
	})
}
