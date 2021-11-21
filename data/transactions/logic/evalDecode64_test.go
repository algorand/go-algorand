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

package logic

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/crypto/secp256k1"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/transactions"
	"github.com/algorand/go-algorand/test/partitiontest"
)

type b64decTestCase struct {
	Encoded string
	IsURL   bool
	Decoded string
	Error   error
}

var testCases = []b64decTestCase{
	{"TU9CWS1ESUNLOwoKb3IsIFRIRSBXSEFMRS4KCgpCeSBIZXJtYW4gTWVsdmlsbGU=",
		false,
		`MOBY-DICK;

or, THE WHALE.


By Herman Melville`,
		nil,
	},
	{"TU9CWS1ESUNLOwoKb3IsIFRIRSBXSEFMRS4KCgpCeSBIZXJtYW4gTWVsdmlsbGU=",
		true,
		`MOBY-DICK;

or, THE WHALE.


By Herman Melville`,
		nil,
	},
	{"YWJjMTIzIT8kKiYoKSctPUB+", false, "abc123!?$*&()'-=@~", nil},
	{"YWJjMTIzIT8kKiYoKSctPUB-", true, "abc123!?$*&()'-=@~", nil},
	{"YWJjMTIzIT8kKiYoKSctPUB+", true, "", base64.CorruptInputError(23)},
	{"YWJjMTIzIT8kKiYoKSctPUB-", false, "", base64.CorruptInputError(23)},
}

func TestBase64DecodeFunc(t *testing.T) {
	partitiontest.PartitionTest(t) // do I need this?
	t.Parallel()                   // do I need this

	for _, testCase := range testCases {
		encoding := base64.StdEncoding
		if testCase.IsURL {
			encoding = base64.URLEncoding
		}
		encoding = encoding.Strict()
		decoded, err := base64Decode([]byte(testCase.Encoded), encoding)
		require.Equal(t, []byte(testCase.Decoded), decoded)
		require.Equal(t, testCase.Error, err)
	}
}

type b64TestArgs struct {
	Raw     []byte
	Encoded []byte
	IsURL   bool
	Program []byte
}

func testB64DecodeAssembleWithArgs(t *testing.T) []b64TestArgs {
	sourceTmpl := `#pragma version 5
	arg 0
	arg 1
	base64_decode %s
	==`
	args := []b64TestArgs{}
	for _, testCase := range testCases {
		if testCase.Error == nil {
			field := "StdAlph"
			if testCase.IsURL {
				field = "URLAlph"
			}
			source := fmt.Sprintf(sourceTmpl, field)
			ops, err := AssembleStringWithVersion(source, 5)
			require.NoError(t, err)

			arg := b64TestArgs{
				Raw:     []byte(testCase.Decoded),
				Encoded: []byte(testCase.Encoded),
				IsURL:   testCase.IsURL,
				Program: ops.Program,
			}
			args = append(args, arg)
		}
	}
	return args
}

func testB64DecodeEval(tb testing.TB, args []b64TestArgs) {
	for _, data := range args {
		var txn transactions.SignedTxn
		txn.Lsig.Logic = data.Program
		txn.Lsig.Args = [][]byte{data.Raw[:], data.Encoded[:]}
		ep := defaultEvalParams(&strings.Builder{}, &txn)
		pass, err := Eval(data.Program, ep)
		if err != nil {
			require.NoError(tb, err)
		}
		if !pass {
			fmt.Printf("FAILING WITH data = %#v", data)
			require.True(tb, pass)
		}
	}
}
func TestOpBase64Decode(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()
	args := testB64DecodeAssembleWithArgs(t)
	testB64DecodeEval(t, args)
}

func benchmarkB64DecodeGenData(b *testing.B, source string, isURL bool, msgLen int) (args []b64TestArgs, err error) {
	var ops *OpStream
	ops, err = AssembleStringWithVersion(source, 5)
	if err != nil {
		require.NoError(b, err)
		return
	}

	encoding := base64.StdEncoding
	if isURL {
		encoding = base64.URLEncoding
	}
	encoding = encoding.Strict()

	msg := make([]byte, msgLen)
	for i := 0; i < b.N; i++ {
		_, err = rand.Read(msg)
		if err != nil {
			require.NoError(b, err)
			return
		}
		args = append(args, b64TestArgs{
			Raw:     msg[:],
			Encoded: []byte(encoding.EncodeToString(msg[:])),
			IsURL:   isURL,
			Program: ops.Program[:],
		})
	}
	return
}

func benchmarkB64Decode(b *testing.B, scenario string, msgLen int) {
	var source string
	isURL := false

	switch scenario {
	case "base64url":
		isURL = true
		source = `#pragma version 5
arg 0
arg 1
base64_decode URLAlph
==`
	case "base64std":
		isURL = false
		source = `#pragma version 5
arg 0
arg 1
base64_decode StdAlph
==`
	default:
		source = `#pragma version 5
arg 0
arg 1
pop
pop
int 1`
	}
	args, err := benchmarkB64DecodeGenData(b, source, isURL, msgLen)
	if err != nil {
		require.NoError(b, err)
		return
	}
	benchmarkB64DecodeSanity(b, args)
	b.ResetTimer()
	testB64DecodeEval(b, args)
}

func benchmarkB64DecodeSanity(b *testing.B, args []b64TestArgs) {
	for _, data := range args {
		encoding := base64.StdEncoding
		if data.IsURL {
			encoding = base64.URLEncoding
		}
		decoded, err := base64Decode(data.Encoded, encoding)
		require.NoError(b, err)
		require.Equal(b, data.Raw, decoded)
	}
}

var b64msgLengths = []int{50, 1050, 2050, 3050}

func benchmarkB64DecodeScenario(b *testing.B, scenario string) {
	for _, msgLen := range b64msgLengths {
		b.Run(fmt.Sprintf("%s_%d", scenario, msgLen), func(b *testing.B) {
			benchmarkB64Decode(b, scenario, msgLen)
		})
	}
}

func TestInvestigation(t *testing.T) {
	data := b64TestArgs{
		Raw:     []uint8{0x1b, 0x66, 0x1d, 0x29, 0x5e, 0x8e, 0x95, 0x79, 0x36, 0xf7, 0xd5, 0xd3, 0x0, 0x35, 0x7b, 0x25, 0x1f, 0x1e, 0x57, 0x78, 0x58, 0x63, 0x26, 0xae, 0x29, 0xcc, 0x96, 0xee, 0x6c, 0x63, 0xc6, 0x88, 0x7b, 0x26, 0xb0, 0x41, 0x77, 0x5, 0xd6, 0xd3, 0x1f, 0x7f, 0x89, 0x94, 0x3a, 0x12, 0xab, 0xe3, 0x70, 0x73},
		Encoded: []uint8{0x6e, 0x53, 0x46, 0x73, 0x7a, 0x7a, 0x74, 0x55, 0x4e, 0x70, 0x6d, 0x6c, 0x4b, 0x65, 0x39, 0x52, 0x33, 0x2d, 0x6f, 0x72, 0x64, 0x38, 0x66, 0x7a, 0x58, 0x32, 0x79, 0x64, 0x6b, 0x79, 0x37, 0x6e, 0x4b, 0x6d, 0x79, 0x51, 0x73, 0x52, 0x4f, 0x66, 0x6f, 0x43, 0x46, 0x69, 0x70, 0x76, 0x4b, 0x46, 0x48, 0x72, 0x49, 0x77, 0x66, 0x5a, 0x57, 0x48, 0x59, 0x48, 0x63, 0x53, 0x36, 0x54, 0x4a, 0x43, 0x72, 0x33, 0x73, 0x3d},
		IsURL:   true,
		Program: []uint8{0x5, 0x2d, 0x2e, 0x5c, 0x0, 0x12},
	}
	require.Equal(t, uint8(0x1b), data.Raw[0])
	testB64DecodeEval(t, []b64TestArgs{data})
}
func BenchmarkBase64DecodeVanillaBase(b *testing.B) {
	benchmarkB64DecodeScenario(b, "vanilla baseline")
}

func BenchmarkBase64DecodeURL(b *testing.B) {
	benchmarkB64DecodeScenario(b, "base64url")
}

func TestCoverZZ(t *testing.T) {
	t.Parallel()
	testAccepts(t, "byte base64 YWJjMTIzIT8kKiYoKSctPUB+; byte base64 YWJjMTIzIT8kKiYoKSctPUB+; ==", 1)
	testAccepts(t, "byte base64 abc123!?$*&(); byte base64 abc123!?$*&(); ==", 1)
	// testAccepts(t, "int 4; int 3; int 2; int 1; cover 2; pop; pop; int 1; ==; return", 5)
	// testPanics(t, obfuscate("int 4; int 3; int 2; int 1; cover 11; int 2; ==; return"), 5)
	// testPanics(t, obfuscate("int 4; int 3; int 2; int 1; cover 4; int 2; ==; return"), 5)
}

// OLDER
func TestKeccak256_Z(t *testing.T) {
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

func TestSHA512_256_Z(t *testing.T) {
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

func TestEd25519verify_Z(t *testing.T) {
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
			ops, err := AssembleStringWithVersion(fmt.Sprintf(`arg 0
arg 1
addr %s
ed25519verify`, pkStr), v)
			require.NoError(t, err)
			sig := c.Sign(Msg{
				ProgramHash: crypto.HashObj(Program(ops.Program)),
				Data:        data[:],
			})
			var txn transactions.SignedTxn
			txn.Lsig.Logic = ops.Program
			txn.Lsig.Args = [][]byte{data[:], sig[:]}
			sb := strings.Builder{}
			pass, err := Eval(ops.Program, defaultEvalParams(&sb, &txn))
			if !pass {
				t.Log(hex.EncodeToString(ops.Program))
				t.Log(sb.String())
			}
			require.True(t, pass)
			require.NoError(t, err)

			// short sig will fail
			txn.Lsig.Args[1] = sig[1:]
			pass, err = Eval(ops.Program, defaultEvalParams(nil, &txn))
			require.False(t, pass)
			require.Error(t, err)
			isNotPanic(t, err)

			// flip a bit and it should not pass
			msg1 := "52fdfc072182654f163f5f0f9a621d729566c74d0aa413bf009c9800418c19cd"
			data1, err := hex.DecodeString(msg1)
			require.NoError(t, err)
			txn.Lsig.Args = [][]byte{data1, sig[:]}
			sb1 := strings.Builder{}
			pass1, err := Eval(ops.Program, defaultEvalParams(&sb1, &txn))
			require.False(t, pass1)
			require.NoError(t, err)
			isNotPanic(t, err)
		})
	}
}

func TestEcdsa_Z(t *testing.T) {
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
	pkTampered1[0] = 0
	pkTampered2 := make([]byte, len(pk))
	copy(pkTampered2, pk[1:])

	var decompressTests = []struct {
		key  []byte
		pass bool
	}{
		{pk, true},
		{pkTampered1, false},
		{pkTampered2, false},
	}
	for _, test := range decompressTests {
		t.Run(fmt.Sprintf("decompress/pass=%v", test.pass), func(t *testing.T) {
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
	copy(rTampered, pk)
	rTampered[0] = 0

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
	pass, err := Eval(ops.Program, defaultEvalParamsWithVersion(nil, &txn, 5))
	require.NoError(t, err)
	require.True(t, pass)
}

// test compatibility with ethereum signatures
func TestEcdsaEthAddress_Z(t *testing.T) {
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

func BenchmarkHash_Z(b *testing.B) {
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

func BenchmarkSha256Raw_Z(b *testing.B) {
	addr, _ := basics.UnmarshalChecksumAddress("OC6IROKUJ7YCU5NV76AZJEDKYQG33V2CJ7HAPVQ4ENTAGMLIOINSQ6EKGE")
	a := addr[:]
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		t := sha256.Sum256(a)
		a = t[:]
	}
}

func BenchmarkEd25519Verifyx1_Z(b *testing.B) {
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
		sb := strings.Builder{}
		ep := defaultEvalParams(&sb, &txn)
		pass, err := Eval(programs[i], ep)
		if !pass {
			b.Log(hex.EncodeToString(programs[i]))
			b.Log(sb.String())
		}
		if err != nil {
			require.NoError(b, err)
		}
		if !pass {
			require.True(b, pass)
		}
	}
}

// type benchmarkEcdsaData struct {
// 	x        []byte
// 	y        []byte
// 	pk       []byte
// 	msg      [32]byte
// 	r        []byte
// 	s        []byte
// 	v        int
// 	programs []byte
// }

func benchmarkEcdsaGenData_Z(b *testing.B) (data []benchmarkEcdsaData) {
	data = make([]benchmarkEcdsaData, b.N)
	for i := 0; i < b.N; i++ {
		key, err := ecdsa.GenerateKey(secp256k1.S256(), rand.Reader)
		require.NoError(b, err)
		sk := keyToByte(b, key.D)
		data[i].x = keyToByte(b, key.PublicKey.X)
		data[i].y = keyToByte(b, key.PublicKey.Y)
		data[i].pk = secp256k1.CompressPubkey(key.PublicKey.X, key.PublicKey.Y)

		d := []byte("testdata")
		data[i].msg = sha512.Sum512_256(d)

		sign, err := secp256k1.Sign(data[i].msg[:], sk)
		require.NoError(b, err)
		data[i].r = sign[:32]
		data[i].s = sign[32:64]
		data[i].v = int(sign[64])
	}
	return data
}

func benchmarkEcdsa_Z(b *testing.B, source string) {
	data := benchmarkEcdsaGenData_Z(b)
	ops, err := AssembleStringWithVersion(source, 5)
	require.NoError(b, err)
	for i := 0; i < b.N; i++ {
		data[i].programs = ops.Program
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		var txn transactions.SignedTxn
		txn.Lsig.Logic = data[i].programs
		txn.Lsig.Args = [][]byte{data[i].msg[:], data[i].r, data[i].s, data[i].x, data[i].y, data[i].pk, {uint8(data[i].v)}}
		sb := strings.Builder{}
		ep := defaultEvalParams(&sb, &txn)
		pass, err := Eval(data[i].programs, ep)
		if !pass {
			b.Log(hex.EncodeToString(data[i].programs))
			b.Log(sb.String())
		}
		if err != nil {
			require.NoError(b, err)
		}
		if !pass {
			require.True(b, pass)
		}
	}
}

func BenchmarkVariety(b *testing.B) {
	b.Run("ecdsa_verify", func(b *testing.B) {
		source := `#pragma version 5
arg 0
arg 1
arg 2
arg 3
arg 4
ecdsa_verify Secp256k1`
		benchmarkEcdsa_Z(b, source)
	})
	b.Run("ecdsa_pk_decompress", func(b *testing.B) {
		source := `#pragma version 5
arg 5
ecdsa_pk_decompress Secp256k1
pop
pop
int 1`
		benchmarkEcdsa_Z(b, source)
	})

	b.Run("ecdsa_pk_recover", func(b *testing.B) {
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
		benchmarkEcdsa_Z(b, source)
	})

	b.Run("add", func(b *testing.B) {
		source := `#pragma version 5
int 1300
int 37
+
int 0
>`
		benchmarkEcdsa_Z(b, source)
	})
}
