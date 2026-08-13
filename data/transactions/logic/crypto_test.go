// Copyright (C) 2019-2026 Algorand Foundation Ltd.
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
	"slices"
	"strconv"
	"strings"
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

func TestSumhash(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	/* tests extracted from test vector in go-algorand/sumhash	*/
	testVectors := []struct{ in, out string }{
		{
			"",
			"591591c93181f8f90054d138d6fa85b63eeeb416e6fd201e8375ba05d3cb55391047b9b64e534042562cc61944930c0075f906f16710cdade381ee9dd47d10a0",
		},
		{
			"a",
			"ea067eb25622c633f5ead70ab83f1d1d76a7def8d140a587cb29068b63cb6407107aceecfdffa92579ed43db1eaa5bbeb4781223a6e07dd5b5a12d5e8bde82c6",
		},
		{
			"I think, therefore I am. – Rene Descartes.",
			"2d4583cdb18710898c78ec6d696a86cc2a8b941bb4d512f9d46d96816d95cbe3f867c9b8bd31964406c847791f5669d60b603c9c4d69dadcb87578e613b60b7a",
		},
	}

	for _, v := range testVectors {
		testAccepts(t, fmt.Sprintf(`byte "%s"; sumhash512; byte 0x%s; ==`, v.in, v.out), sumhashVersion)
	}
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

func TestSHA512(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	// echo -n "hello" | sha512sum
	progText := `
byte "hello"; sha512
byte 0x9b71d224bd62f3785d96d46ad3ea3d73319bfbc2890caadae2dff72519673ca72323c3d99ba5c11d7c7acc6e14b8c5da0c4663475c2e5c3adef46f73bcdec043
==`
	testAccepts(t, progText, 13)
}

func TestMimc(t *testing.T) {
	// We created test vectors for the MiMC hash function by defining a set of preimages for different
	// input sizes and calling gnark-crypto's MiMC implementation to compute the expected hash values.
	// E.g.:
	//		import "github.com/consensys/gnark-crypto/ecc/bn254/fr/mimc"
	//		hasher := mimc.NewMiMC()
	//		hasher.Write(inputBytes)
	//		hashBytes := hasher.Sum(nil)
	// Since we are hardcoding the expected hash values, we are also testing that gnark-crypto's MiMC
	// output does not change under the hood with new versions.
	//
	// We test that malformed inputs panic, in particular we test malfornmed inputs of:
	// 0 length, lengths not multiple of 32 bytes, chunks representing values greater than the modulus.
	// We test that well formed inputs hash correctly, testing both single chunk inputs (32-byte) and
	// multiple chunk inputs (96 bytes).
	partitiontest.PartitionTest(t)
	t.Parallel()

	type PreImageTestVector struct {
		PreImage      string
		ShouldSucceed bool
	}
	preImageTestVectors := []PreImageTestVector{
		{"0x",
			false}, // zero-length input
		{"0x23a950068dd3d1e21cee48e7919be7ae32cdef70311fc486336ea9d4b5042535",
			true}, // 32 bytes, less than modulus
		{"0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000002",
			false}, // 32 bytes, more than modulus
		{"0xdeadf00d",
			false}, // less than 32 byte
		{"0x183de351a72141d79c51a27d10405549c98302cb2536c5968deeb3cba635121723a950068dd3d1e21cee48e7919be7ae32cdef70311fc486336ea9d4b504253530644e72e131a029b85045b68181585d2833e84879b9709143e1f593ef676981",
			true}, // 32 bytes, less than modulus | 32 bytes, less than modulus | 32 bytes, less than modulus
		{"0x183de351a72141d79c51a27d10405549c98302cb2536c5968deeb3cba635121723a950068dd3d1e21cee48e7919be7ae32cdef70311fc486336ea9d4b504253573eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000002",
			false}, //  32 bytes, less than modulus | 32 bytes, less than modulus | 32 bytes, more than modulus
		{"0x183de351a72141d79c51a27d10405549c98302cb2536c5968deeb3cba635121723a950068dd3d1e21cee48e7919be7ae32cdef70311fc486336ea9d4b5042535abba",
			false}, // 32 bytes, less than modulus | 32 bytes, less than modulus | less than 32 bytes
	}

	circuitHashTestVectors := map[string][]string{
		"BN254Mp110": {
			"20104241803663641422577121134203490505137011783614913652735802145961801733870",
			"12886436712380113721405259596386800092738845035233065858332878701083870690753",
			"19565877911319815535452130675266047290072088868113536892077808700068649624391",
			"1037254799353855871006189384309576393135431139055333626960622147300727796413",
			"6040222623731283351958201178122781676432899642144860863024149088913741383362",
			"21691351735381703396517600859480938764038501053226864452091917666642352837076",
			"10501393540371963307040960561318023073151272109639330842515119353134949995409",
		},
		"BLS12_381Mp111": {
			"17991912493598890696181760734961918471863781118188078948205844982816313445306",
			"8791766422525455185980675814845076441443662947059416063736889106252015893524",
			"35137972692771717943992759113612269767581262500164574105059686144346651628747",
			"15039173432183897369859775531867817848264266283034981501223857291379142522368",
			"12964111614552580241101202600014316932811348627866250816177200046290462797607",
			"21773894974440411325489312534417904228129169539217646609523079291104496302656",
			"9873666029497961930790892458408217321483390383568592297687427911011295910871",
		},
	}

	for _, config := range []string{"BN254Mp110", "BLS12_381Mp111"} {
		for i, preImageTestVector := range preImageTestVectors {
			var n big.Int
			n.SetString(circuitHashTestVectors[config][i], 10)
			circuitHash := n.Bytes()
			progText := fmt.Sprintf(`byte %s
mimc %s
byte 0x%x
==`, preImageTestVector.PreImage, config, circuitHash)
			if preImageTestVector.ShouldSucceed {
				testAccepts(t, progText, 11)
			} else {
				testPanics(t, progText, 11)
			}
		}
	}
}

func TestPoseidon2(t *testing.T) {
	// We created test vectors for the Poseidon2 hash function by defining a set of preimages for different
	// input sizes and calling gnark-crypto's Poseidon2 implementation to compute the expected hash values.
	// E.g.:
	//		import "github.com/consensys/gnark-crypto/ecc/bn254/fr/poseidon2"
	//		hasher := poseidon2.NewMerkleDamgardHasher()
	//		hasher.Write(inputBytes)
	//		hashBytes := hasher.Sum(nil)
	// Since we are hardcoding the expected hash values, we are also testing that gnark-crypto's Poseidon2
	// output does not change under the hood with new versions.
	//
	// We test that malformed inputs panic, in particular we test malformed inputs of:
	// 0 length, lengths not multiple of 32 bytes, chunks representing values greater than the modulus.
	// We test that well formed inputs hash correctly, testing both single chunk inputs (32-byte) and
	// multiple chunk inputs (96 bytes).
	partitiontest.PartitionTest(t)
	t.Parallel()

	type PreImageTestVector struct {
		PreImage      string
		ShouldSucceed bool
	}
	preImageTestVectors := []PreImageTestVector{
		{"0x",
			false}, // zero-length input
		{"0x23a950068dd3d1e21cee48e7919be7ae32cdef70311fc486336ea9d4b5042535",
			true}, // 32 bytes, less than modulus
		{"0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000002",
			false}, // 32 bytes, more than modulus
		{"0xdeadf00d",
			false}, // less than 32 byte
		{"0x183de351a72141d79c51a27d10405549c98302cb2536c5968deeb3cba635121723a950068dd3d1e21cee48e7919be7ae32cdef70311fc486336ea9d4b504253530644e72e131a029b85045b68181585d2833e84879b9709143e1f593ef676981",
			true}, // 32 bytes, less than modulus | 32 bytes, less than modulus | 32 bytes, less than modulus
		{"0x183de351a72141d79c51a27d10405549c98302cb2536c5968deeb3cba635121723a950068dd3d1e21cee48e7919be7ae32cdef70311fc486336ea9d4b504253573eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000002",
			false}, //  32 bytes, less than modulus | 32 bytes, less than modulus | 32 bytes, more than modulus
		{"0x183de351a72141d79c51a27d10405549c98302cb2536c5968deeb3cba635121723a950068dd3d1e21cee48e7919be7ae32cdef70311fc486336ea9d4b5042535abba",
			false}, // 32 bytes, less than modulus | 32 bytes, less than modulus | less than 32 bytes
	}

	circuitHashTestVectors := map[string][]string{
		"BN254t2": {
			"0",
			"9508867777362231262564394485161648897131889139474639535709054689562539246209",
			"0",
			"0",
			"6791735139456093729163685856803485582211494197517701835714118539027901440151",
			"0",
			"0",
		},
		"BLS12_381t2": {
			"0",
			"34960972753749415790402211978912014226528569245540044525901549350192685584856",
			"0",
			"0",
			"42428992405405528150674275794637337448740652553021708843638392031995718438793",
			"0",
			"0",
		},
	}

	for _, config := range []string{"BN254t2", "BLS12_381t2"} {
		for i, preImageTestVector := range preImageTestVectors {
			var n big.Int
			n.SetString(circuitHashTestVectors[config][i], 10)
			circuitHash := n.Bytes()
			progText := fmt.Sprintf(`byte %s
poseidon2 %s
byte 0x%x
==`, preImageTestVector.PreImage, config, circuitHash)
			if preImageTestVector.ShouldSucceed {
				testAccepts(t, progText, poseidon2Version)
			} else {
				testPanics(t, progText, poseidon2Version)
			}
		}
	}
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
	partitiontest.PartitionTest(t)
	t.Parallel()

	ep := defaultAppParams()
	testApp(t, notrack("int 1; int 2; int 3; vrf_verify VrfAlgorand"), ep, "arg 0 wanted")
	testApp(t, notrack("byte 0x1122; int 2; int 3; vrf_verify VrfAlgorand"), ep, "arg 1 wanted")
	testApp(t, notrack("byte 0x1122; byte 0x2233; int 3; vrf_verify VrfAlgorand"), ep, "arg 2 wanted")

	ep = defaultSigParams()
	testLogic(t, notrack("byte 0x1122; byte 0x2233; byte 0x3344; vrf_verify VrfAlgorand"), LogicVersion, ep, "vrf proof wrong size")
	// 80 byte proof
	testLogic(t, notrack("byte 0x1122; int 80; bzero; byte 0x3344; vrf_verify VrfAlgorand"), LogicVersion, ep, "vrf pubkey wrong size")
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

func falconVerifyBench(b *testing.B, config FalconConfig, msg []byte) string {
	var seed crypto.FalconSeed
	var pk, sig []byte
	switch config {
	case FalconDet1024:
		fs, err := crypto.GenerateFalcon1024Signer(seed)
		require.NoError(b, err)
		signature, err := fs.SignBytes(msg)
		require.NoError(b, err)
		pk, sig = fs.PublicKey[:], signature
	case FalconDet512:
		fs, err := crypto.GenerateFalcon512Signer(seed)
		require.NoError(b, err)
		signature, err := fs.SignBytes(msg)
		require.NoError(b, err)
		pk, sig = fs.PublicKey[:], signature
	default:
		b.Fatalf("unknown falcon config %s", config)
	}
	return fmt.Sprintf("byte 0x%x; byte 0x%x; byte 0x%x; falcon_verify %s; assert",
		msg, sig, pk, config)
}

// BenchmarkVerify is useful to see relative speeds of various crypto verify functions
// falconVerifyBench builds the body of a falcon_verify benchmark for one Falcon
// variant. The key and signature are generated from a fixed seed rather than
// hardcoded, so that the `assert` measures, and confirms, a verification that
// actually succeeds for whichever variant the immediate names.
func BenchmarkVerify(b *testing.B) {
	benchMsg, err := hex.DecodeString("62fdfc072182654f163f5f0f9a621d729566c74d0aa413bf009c9800418c19cd")
	require.NoError(b, err)

	benches := [][]string{
		{"pop", "", "int 1234576; int 6712; pop; pop", "int 1"},
		{"add", "", "int 1234576; int 6712; +; pop", "int 1"},
		{"ed25519verify_bare", "", `
byte 0x62fdfc072182654f163f5f0f9a621d729566c74d0aa413bf009c9800418c19cd
byte 0xaab40a8b4f1f386504af2473804abbc03bbd94506e8e0c8db881fc2b2c3aee65b867b25caa47fa25ae2105bf1731398df336213707f2d25f9b1d31b3dc133307;
addr C7ZCK6N2AJQMVEP4FRTK2UW45UFR6DKPRJHJVWB5O4VQOZMFPK2KCMR7M4
ed25519verify_bare; assert
`, "int 1"},
		{"ecdsa_verify k1", "", `
byte 0x71a5910445820f57989c027bdf9391c80097874d249e0f38bf90834fdec2877f
byte 0x5eb27782eb1a5df8de9a5d51613ad5ca730840ddf4af919c6feb15cde14f9978
byte 0x0cb3c0d636ed991ee030d09c295de3121eb166cb9e1552cf0ef0fb2358f35f0f
byte 0x79de0699673571df1de8486718d06a3e7838f6831ec4ef3fb963788fbfb773b7
byte 0xd76446a3393af3e2eefada16df80cc6a881a56f4cf41fa2ab4769c5708ce878d
ecdsa_verify Secp256k1
assert`, "int 1"},
		{"ecdsa_verify r1", "", `
byte 0x71a5910445820f57989c027bdf9391c80097874d249e0f38bf90834fdec2877f
byte 0xc010fc83ea196d6f5ce8a44637060bdcfb5bf1199cfc5bb893684d450c4f160c
byte 0x8e391a7b9cd75a99e8ebfe703036caebd9e91ae8339bd7e2abfb0f273eb8e972
byte 0x13e49a19378bbfa8d55ac81a35b87d7bae456c79fcf04a78803d8eb45b253fab
byte 0xa2d237cd897ca70787abf04d2155c6dc2fbe26fd642e0472cd75c13dc919ef1a
ecdsa_verify Secp256r1
assert`, "int 1"},
		{"falcon_verify FalconDet1024", "", falconVerifyBench(b, FalconDet1024, benchMsg), "int 1"},
		{"falcon_verify FalconDet512", "", falconVerifyBench(b, FalconDet512, benchMsg), "int 1"},
		{"vrf_verify", "", `byte 0x72
byte 0xae5b66bdf04b4c010bfe32b2fc126ead2107b697634f6f7337b9bff8785ee111200095ece87dde4dbe87343f6df3b107d91798c8a7eb1245d3bb9c5aafb093358c13e6ae1111a55717e895fd15f99f07
byte 0x3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c
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

func randSeed() crypto.Seed {
	var s crypto.Seed
	crypto.RandBytes(s[:])
	return s
}

func TestEd25519verify(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	c := crypto.GenerateSignatureSecrets(randSeed())
	msg := "62fdfc072182654f163f5f0f9a621d729566c74d0aa413bf009c9800418c19cd"
	data, err := hex.DecodeString(msg)
	require.NoError(t, err)

	for v := uint64(1); v <= AssemblerMaxVersion; v++ {
		t.Run(fmt.Sprintf("v=%d", v), func(t *testing.T) {
			ops := testProg(t, fmt.Sprintf("arg 0; arg 1; arg 2; ed25519verify"), v)
			sig := c.Sign(Msg{
				ProgramHash: crypto.HashObj(Program(ops.Program)),
				Data:        data[:],
			})
			var txn transactions.SignedTxn
			txn.Lsig.Logic = ops.Program
			txn.Lsig.Args = [][]byte{data[:], sig[:], c.SignatureVerifier[:]}
			testLogicBytes(t, ops.Program, defaultSigParams(txn))

			// short sig will fail
			txn.Lsig.Args = [][]byte{data[:], sig[1:], c.SignatureVerifier[:]}
			testLogicBytes(t, ops.Program, defaultSigParams(txn), "invalid signature")

			// short pk will fail
			txn.Lsig.Args = [][]byte{data[:], sig[:], c.SignatureVerifier[1:]}
			testLogicBytes(t, ops.Program, defaultSigParams(txn), "invalid public key")

			// flip a bit and it should not pass
			msg1 := "5" + msg[1:]
			data1, err := hex.DecodeString(msg1)
			require.NoError(t, err)
			txn.Lsig.Args = [][]byte{data1, sig[:], c.SignatureVerifier[:]}
			testLogicBytes(t, ops.Program, defaultSigParams(txn), "REJECT")
		})
	}
}

func TestEd25519VerifyBare(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	c := crypto.GenerateSignatureSecrets(randSeed())
	msg := "62fdfc072182654f163f5f0f9a621d729566c74d0aa413bf009c9800418c19cd"
	data, err := hex.DecodeString(msg)
	require.NoError(t, err)

	for v := uint64(7); v <= AssemblerMaxVersion; v++ {
		t.Run(fmt.Sprintf("v=%d", v), func(t *testing.T) {
			ops := testProg(t, "arg 0; arg 1; arg 2; ed25519verify_bare", v)
			require.NoError(t, err)
			sig := c.SignBytes(data)
			var txn transactions.SignedTxn
			txn.Lsig.Logic = ops.Program
			txn.Lsig.Args = [][]byte{data[:], sig[:], c.SignatureVerifier[:]}
			testLogicBytes(t, ops.Program, defaultSigParams(txn))

			// short sig will fail
			txn.Lsig.Args = [][]byte{data[:], sig[1:], c.SignatureVerifier[:]}
			testLogicBytes(t, ops.Program, defaultSigParams(txn), "invalid signature")

			// short pk will fail
			txn.Lsig.Args = [][]byte{data[:], sig[:], c.SignatureVerifier[1:]}
			testLogicBytes(t, ops.Program, defaultSigParams(txn), "invalid public key")

			// flip a bit and it should not pass
			msg1 := "5" + msg[1:]
			data1, err := hex.DecodeString(msg1)
			require.NoError(t, err)
			txn.Lsig.Args = [][]byte{data1, sig[:], c.SignatureVerifier[:]}
			testLogicBytes(t, ops.Program, defaultSigParams(txn), "REJECT")
		})
	}
}

func TestFalconVerify(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	var s crypto.FalconSeed
	fs1024, err := crypto.GenerateFalcon1024Signer(s)
	require.NoError(t, err)
	fs512, err := crypto.GenerateFalcon512Signer(s)
	require.NoError(t, err)

	msg := "62fdfc072182654f163f5f0f9a621d729566c74d0aa413bf009c9800418c19cd"
	data, err := hex.DecodeString(msg)
	require.NoError(t, err)
	// same as data, with the first byte altered
	altered, err := hex.DecodeString("52fdfc072182654f163f5f0f9a621d729566c74d0aa413bf009c9800418c19cd")
	require.NoError(t, err)

	sig1024, err := fs1024.SignBytes(data)
	require.NoError(t, err)
	sig512, err := fs512.SignBytes(data)
	require.NoError(t, err)

	// exercise assembles a falcon_verify against pk (spelled for version v, with
	// the given config immediate) and checks that it accepts sig over data, but
	// rejects a truncated signature or altered data.
	exercise := func(t *testing.T, v uint64, config string, pk []byte, sig []byte) {
		verify := fmt.Sprintf("arg 0; arg 1; byte 0x%s; falcon_verify %s",
			hex.EncodeToString(pk), config)
		yes := testProg(t, verify, v)
		no := testProg(t, verify+"; !", v)

		var txn transactions.SignedTxn
		txn.Lsig.Args = [][]byte{data, sig}
		testLogicBytes(t, yes.Program, defaultSigParams(txn))
		testLogicBytes(t, no.Program, defaultSigParams(txn), "REJECT")

		txn.Lsig.Args = [][]byte{data, sig[1:]} // short sig will fail
		testLogicBytes(t, yes.Program, defaultSigParams(txn), "REJECT")
		testLogicBytes(t, no.Program, defaultSigParams(txn))

		txn.Lsig.Args = [][]byte{altered, sig} // flipped bit will fail
		testLogicBytes(t, yes.Program, defaultSigParams(txn), "REJECT")
		testLogicBytes(t, no.Program, defaultSigParams(txn))
	}

	for v := uint64(12); v <= AssemblerMaxVersion; v++ {
		t.Run(fmt.Sprintf("v=%d", v), func(t *testing.T) {
			if v < f512Version { // no immediate, always deterministic Falcon-1024
				exercise(t, v, "", fs1024.PublicKey[:], sig1024)
				return
			}
			exercise(t, v, "FalconDet1024", fs1024.PublicKey[:], sig1024)
			exercise(t, v, "FalconDet512", fs512.PublicKey[:], sig512)
		})
	}
}

// TestFalconVerifyNeedsImmediate confirms that the falcon_verify opcode cannot
// be used without an immediate (seems like a plausible regression since it used
// to be allowed).
func TestFalconVerifyNeedsImmediate(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	testProg(t, "arg 0; arg 1; arg 3; falcon_verify",
		f512Version, exp(1, "falcon_verify expects 1 immediate argument"))

}

// TestFalconVerifyConfigMismatch confirms that a public key whose length belongs
// to the other Falcon variant is caught, at assembly time when its length is
// known, and at runtime otherwise.
func TestFalconVerifyConfigMismatch(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	pk1024 := strings.Repeat("aa", crypto.Falcon1024PublicKeySize)
	pk512 := strings.Repeat("bb", crypto.Falcon512PublicKeySize)

	testProg(t, fmt.Sprintf("arg 0; arg 1; byte 0x%s; falcon_verify FalconDet512", pk1024),
		f512Version, exp(1, "...wanted type [897]byte got [1793]byte"))
	testProg(t, fmt.Sprintf("arg 0; arg 1; byte 0x%s; falcon_verify FalconDet1024", pk512),
		f512Version, exp(1, "...wanted type [1793]byte got [897]byte"))

	// A key of unknown length passes assembly, and is rejected during eval.
	source := "arg 0; arg 1; arg 2; falcon_verify FalconDet512"
	ops := testProg(t, source, f512Version)
	var txn transactions.SignedTxn
	txn.Lsig.Args = [][]byte{nil, nil, make([]byte, crypto.Falcon1024PublicKeySize)}
	testLogicBytes(t, ops.Program, defaultSigParams(txn), "invalid public key size 1793 != 897")
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
	pkTampered1 := slices.Clone(pk)
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
		innerSource := source
		t.Run(fmt.Sprintf("decompress/pass=%v", test.pass), func(t *testing.T) {
			t.Parallel()
			t.Log("decompressTests i", i)
			src := fmt.Sprintf(innerSource, hex.EncodeToString(test.key), hex.EncodeToString(x), hex.EncodeToString(y))
			if test.pass {
				testAccepts(t, src, 5)
			} else {
				testPanics(t, notrack(src), 5)
			}
		})
	}

	// ecdsa verify tests
	source = `byte "%s"; sha512_256; byte 0x%s; byte 0x%s; byte 0x%s; byte 0x%s; ecdsa_verify Secp256k1`
	data := []byte("testdata")
	msg := sha512.Sum512_256(data)

	sign, err := secp256k1.Sign(msg[:], sk)
	require.NoError(t, err)
	r := sign[:32]
	s := sign[32:64]
	v := int(sign[64])

	rTampered := slices.Clone(r)
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
		innerSource := source
		t.Run(fmt.Sprintf("verify/pass=%v", test.pass), func(t *testing.T) {
			t.Parallel()
			src := fmt.Sprintf(innerSource, test.data, hex.EncodeToString(test.r), hex.EncodeToString(s), hex.EncodeToString(x), hex.EncodeToString(y))
			if test.pass {
				testAccepts(t, src, 5)
			} else {
				testRejects(t, src, 5)
			}
		})
	}

	// coverage for pk length check
	testPanics(t, notrack(`int 31; bzero; byte 0x; byte 0x; byte 0x; byte 0x; ecdsa_verify Secp256k1`), 5, "must be 32")

	// we did not implement arg length checks for x,y & r,s, so we must simply fail to verify, not panic
	testAccepts(t, notrack(`int 32; bzero; byte 0x; byte 0x; byte 0x; byte 0x; ecdsa_verify Secp256k1; !`), 5)

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
			testPanics(t, program, introduced, "recover failed")
		}},
		{4, func(t *testing.T, program string, introduced uint64) {
			testPanics(t, program, introduced, "invalid recovery id")
		}},
	}
	pkExpanded := secp256k1.S256().Marshal(key.PublicKey.X, key.PublicKey.Y)

	for i, test := range recoverTests {
		innerSource := source
		t.Run(fmt.Sprintf("recover/%d", i), func(t *testing.T) {
			t.Parallel()
			src := fmt.Sprintf(innerSource, hex.EncodeToString(msg[:]), test.v, hex.EncodeToString(r), hex.EncodeToString(s), hex.EncodeToString(x), hex.EncodeToString(y), hex.EncodeToString(pkExpanded))
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
	pass, err := EvalSignature(0, defaultSigParamsWithVersion(5, txn))
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
	pkTampered1 := slices.Clone(pk)
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
		innerSource := source
		t.Run(fmt.Sprintf("decompress/pass=%v", test.pass), func(t *testing.T) {
			t.Parallel()
			t.Log("decompressTests i", i)
			src := fmt.Sprintf(innerSource, hex.EncodeToString(test.key), hex.EncodeToString(x), hex.EncodeToString(y))
			if test.pass {
				testAccepts(t, src, fidoVersion)
			} else {
				testPanics(t, notrack(src), fidoVersion)
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
	r := ri.FillBytes(make([]byte, 32))
	s := si.FillBytes(make([]byte, 32))

	rTampered := slices.Clone(r)
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
		innerSource := source
		t.Run(fmt.Sprintf("verify/pass=%v", test.pass), func(t *testing.T) {
			t.Parallel()
			src := fmt.Sprintf(innerSource, test.data, hex.EncodeToString(test.r), hex.EncodeToString(s), hex.EncodeToString(x), hex.EncodeToString(y))
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
	pass, err := EvalSignature(0, defaultSigParamsWithVersion(fidoVersion, txn))
	require.NoError(t, err)
	require.True(t, pass)
}

// test compatibility with ethereum signatures
func TestEcdsaEthAddress(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

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
	t.Parallel()

	// Doesn't matter if the actual verify returns true or false. Just confirm the cost depends on curve.
	source := `
global ZeroAddress				// need 32 bytes for all 5 args
dup; dup; dup; dup;
ecdsa_verify Secp256k1
!
assert
global OpcodeBudget
int ` + fmt.Sprintf("%d", testLogicBudget-1700-8) + `
==
`
	testAccepts(t, source, 6) // Secp256k1 was 5, but OpcodeBudget is 6

	source = `
global ZeroAddress				// need 32 bytes for all 5 args
dup; dup; dup; dup
ecdsa_verify Secp256r1
!
assert
global OpcodeBudget
int ` + fmt.Sprintf("%d", testLogicBudget-2500-8) + `
==
`
	testAccepts(t, source, fidoVersion)
}

func testHashCost(t *testing.T, hash string, size int, expected int, intro uint64) {
	hashCostCheck := `
pushint %d
bzero
%s
pop
pushint ` + strconv.Itoa(testLogicBudget-5) + ` // 5 non sha instructions
global OpcodeBudget
-
pushint %d
==
`
	t.Helper()
	testAccepts(t, fmt.Sprintf(hashCostCheck, size, hash, expected), intro)
}

func TestHashCosts(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	testHashCost(t, "sha512", 0, 15, 13)
	testHashCost(t, "sha512", 1, 17, 13)
	testHashCost(t, "sha512", 64, 19, 13)
	testHashCost(t, "sha512", 1000, 79, 13)

	testHashCost(t, "sumhash512", 0, 150, sumhashVersion)
	testHashCost(t, "sumhash512", 1, 154, sumhashVersion)
	testHashCost(t, "sumhash512", 64, 190, sumhashVersion)
	testHashCost(t, "sumhash512", 1000, 722, sumhashVersion)
}

func BenchmarkHashes(b *testing.B) {
	for _, hash := range []string{"sha256", "keccak256" /* skip, same as keccak "sha3_256", */, "sha512_256", "sumhash512", "mimc BN254Mp110", "mimc BLS12_381Mp111", "poseidon2 BN254t2", "poseidon2 BLS12_381t2", "sha512"} {
		for _, size := range []int{0, 32, 128, 512, 1024, 4096} {
			if size == 0 && (hash == "mimc BN254Mp110" || hash == "mimc BLS12_381Mp111" || hash == "poseidon2 BN254t2" || hash == "poseidon2 BLS12_381t2") {
				continue
			}
			b.Run(hash+"-"+strconv.Itoa(size), func(b *testing.B) {
				benchmarkOperation(b, "", fmt.Sprintf("int %d; bzero; %s; pop", size, hash), "int 1")
			})
		}
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

		secret := crypto.GenerateSignatureSecrets(randSeed()) //generate programs and signatures
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
		ep := defaultSigParams(txn)
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
			data[i].r = r.FillBytes(make([]byte, 32))
			data[i].s = s.FillBytes(make([]byte, 32))
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
		ep := defaultSigParams(txn)
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
