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
	"bytes"
	"compress/gzip"
	"context"
	stdcrypto "crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/mldsa"
	"crypto/rand"
	"crypto/sha256"
	stdsha3 "crypto/sha3"
	"crypto/sha512"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"os"
	"os/exec"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/crypto/secp256k1"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/transactions"
	"github.com/algorand/go-algorand/protocol"
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
		PreImage string
		Error    string // expected in the panic, or empty if the hash should succeed
	}
	preImageTestVectors := []PreImageTestVector{
		{"0x",
			"the input data cannot be empty"}, // zero-length input
		{"0x23a950068dd3d1e21cee48e7919be7ae32cdef70311fc486336ea9d4b5042535",
			""}, // 32 bytes, less than modulus
		{"0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000002",
			"invalid mimc input"}, // 32 bytes, more than modulus
		{"0xdeadf00d",
			"the input data must be a multiple of 32 bytes"}, // less than 32 byte
		{"0x183de351a72141d79c51a27d10405549c98302cb2536c5968deeb3cba635121723a950068dd3d1e21cee48e7919be7ae32cdef70311fc486336ea9d4b504253530644e72e131a029b85045b68181585d2833e84879b9709143e1f593ef676981",
			""}, // 32 bytes, less than modulus | 32 bytes, less than modulus | 32 bytes, less than modulus
		{"0x183de351a72141d79c51a27d10405549c98302cb2536c5968deeb3cba635121723a950068dd3d1e21cee48e7919be7ae32cdef70311fc486336ea9d4b504253573eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000002",
			"invalid mimc input"}, //  32 bytes, less than modulus | 32 bytes, less than modulus | 32 bytes, more than modulus
		{"0x183de351a72141d79c51a27d10405549c98302cb2536c5968deeb3cba635121723a950068dd3d1e21cee48e7919be7ae32cdef70311fc486336ea9d4b5042535abba",
			"the input data must be a multiple of 32 bytes"}, // 32 bytes, less than modulus | 32 bytes, less than modulus | less than 32 bytes
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
			if preImageTestVector.Error == "" {
				testAccepts(t, progText, 11)
			} else {
				testPanics(t, progText, 11, preImageTestVector.Error)
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
		PreImage string
		Error    string // expected in the panic, or empty if the hash should succeed
	}
	preImageTestVectors := []PreImageTestVector{
		{"0x",
			"the input data cannot be empty"}, // zero-length input
		{"0x23a950068dd3d1e21cee48e7919be7ae32cdef70311fc486336ea9d4b5042535",
			""}, // 32 bytes, less than modulus
		{"0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000002",
			"invalid poseidon2 input"}, // 32 bytes, more than modulus
		{"0xdeadf00d",
			"the input data must be a multiple of 32 bytes"}, // less than 32 byte
		{"0x183de351a72141d79c51a27d10405549c98302cb2536c5968deeb3cba635121723a950068dd3d1e21cee48e7919be7ae32cdef70311fc486336ea9d4b504253530644e72e131a029b85045b68181585d2833e84879b9709143e1f593ef676981",
			""}, // 32 bytes, less than modulus | 32 bytes, less than modulus | 32 bytes, less than modulus
		{"0x183de351a72141d79c51a27d10405549c98302cb2536c5968deeb3cba635121723a950068dd3d1e21cee48e7919be7ae32cdef70311fc486336ea9d4b504253573eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000002",
			"invalid poseidon2 input"}, //  32 bytes, less than modulus | 32 bytes, less than modulus | 32 bytes, more than modulus
		{"0x183de351a72141d79c51a27d10405549c98302cb2536c5968deeb3cba635121723a950068dd3d1e21cee48e7919be7ae32cdef70311fc486336ea9d4b5042535abba",
			"the input data must be a multiple of 32 bytes"}, // 32 bytes, less than modulus | 32 bytes, less than modulus | less than 32 bytes
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
			if preImageTestVector.Error == "" {
				testAccepts(t, progText, poseidon2Version)
			} else {
				testPanics(t, progText, poseidon2Version, preImageTestVector.Error)
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

// falconVerifyBench builds the body of a falcon_verify benchmark for one Falcon
// variant. The key and signature are generated from a fixed seed rather than
// hardcoded, so that the `assert` measures, and confirms, a verification that
// actually succeeds for whichever variant the immediate names.
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

// mldsaVerifyBench builds a BenchmarkVerify entry for mldsa_verify, with its
// inputs in a bytecblock, since benchmarkOperation repeats the operation 2000
// times.
func mldsaVerifyBench(b *testing.B, config MLDSAConfig, msg []byte) []string {
	pk, sig := mldsaTestSign(b, config, msg, nil)
	return []string{"mldsa_verify " + config.String(),
		fmt.Sprintf("bytecblock 0x%x 0x%x 0x%x 0x", msg, sig, pk),
		fmt.Sprintf("bytec_0; bytec_1; bytec_2; bytec_3; mldsa_verify %s; assert", config),
		"int 1"}
}

// BenchmarkVerify is useful to see relative speeds of various crypto verify functions
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
		mldsaVerifyBench(b, MLDSA44, benchMsg),
		mldsaVerifyBench(b, MLDSA65, benchMsg),
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
		key []byte
		err string // expected in the panic, or empty if decompression should succeed
	}{
		{pk, ""},
		{pkTampered1, "invalid pubkey"},
		{pkTampered2, "invalid pubkey"},
	}
	for i, test := range decompressTests {
		innerSource := source
		t.Run(fmt.Sprintf("decompress/pass=%v", test.err == ""), func(t *testing.T) {
			t.Parallel()
			t.Log("decompressTests i", i)
			src := fmt.Sprintf(innerSource, hex.EncodeToString(test.key), hex.EncodeToString(x), hex.EncodeToString(y))
			if test.err == "" {
				testAccepts(t, src, 5)
			} else {
				testPanics(t, notrack(src), 5, test.err)
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
	pass, _, err := EvalSignatureProgram(txn.Lsig.Logic, nil, 0, defaultSigParamsWithVersion(5, txn))
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
		key []byte
		err string // expected in the panic, or empty if decompression should succeed
	}{
		{pk, ""},
		{pkTampered1, "invalid compressed pubkey"},
		{pkTampered2, "invalid compressed pubkey"},
	}
	for i, test := range decompressTests {
		innerSource := source
		t.Run(fmt.Sprintf("decompress/pass=%v", test.err == ""), func(t *testing.T) {
			t.Parallel()
			t.Log("decompressTests i", i)
			src := fmt.Sprintf(innerSource, hex.EncodeToString(test.key), hex.EncodeToString(x), hex.EncodeToString(y))
			if test.err == "" {
				testAccepts(t, src, fidoVersion)
			} else {
				testPanics(t, notrack(src), fidoVersion, test.err)
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
	pass, _, err := EvalSignatureProgram(txn.Lsig.Logic, nil, 0, defaultSigParamsWithVersion(fidoVersion, txn))
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
		pass, _, err := EvalSignatureProgram(txn.Lsig.Logic, txn.Lsig.Args, 0, ep)
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
		pass, _, err := EvalSignatureProgram(txn.Lsig.Logic, txn.Lsig.Args, 0, ep)
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

// mldsaTestKey returns a fixed key for config.
func mldsaTestKey(tb testing.TB, config MLDSAConfig) *mldsa.PrivateKey {
	fs, ok := mldsaConfigSpecByField(config)
	require.True(tb, ok)
	sk, err := mldsa.NewPrivateKey(fs.params, slices.Repeat([]byte{byte(config) + 1}, mldsa.PrivateKeySize))
	require.NoError(tb, err)
	return sk
}

// mldsaTestSign signs msg under ctx, deterministically, with a fixed key for
// config.
func mldsaTestSign(tb testing.TB, config MLDSAConfig, msg, ctx []byte) (pk, sig []byte) {
	sk := mldsaTestKey(tb, config)
	sig, err := sk.SignDeterministic(msg, &mldsa.Options{Context: string(ctx)})
	require.NoError(tb, err)
	return sk.PublicKey().Bytes(), sig
}

// mldsaArgsProgram takes mldsa_verify's inputs from LogicSig args, so that
// their lengths are not known at assembly time.
func mldsaArgsProgram(config MLDSAConfig) string {
	return "arg 0; arg 1; arg 2; arg 3; mldsa_verify " + config.String()
}

func TestMLDSAVerify(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	for _, config := range []MLDSAConfig{MLDSA44, MLDSA65} {
		t.Run(config.String(), func(t *testing.T) {
			t.Parallel()
			yes := testProg(t, mldsaArgsProgram(config), mldsaVersion)
			no := testProg(t, mldsaArgsProgram(config)+"; !", mldsaVersion)
			for _, msgLen := range []int{0, 1, 32, maxStringSize} {
				for _, ctxLen := range []int{0, 1, mldsaMaxContextSize} {
					msg := make([]byte, msgLen)
					crypto.RandBytes(msg)
					ctx := make([]byte, ctxLen)
					crypto.RandBytes(ctx)
					pk, sig := mldsaTestSign(t, config, msg, ctx)
					randomized, err := mldsaTestKey(t, config).Sign(nil, msg, &mldsa.Options{Context: string(ctx)})
					require.NoError(t, err)

					for _, sig := range [][]byte{sig, randomized} {
						var txn transactions.SignedTxn
						txn.Lsig.Args = [][]byte{msg, sig, pk, ctx}
						testLogicBytes(t, yes.Program, defaultSigParams(txn))
						testLogicBytes(t, no.Program, defaultSigParams(txn), "REJECT")

						// Flipping a bit of any input, at the same length,
						// fails verification.
						for _, arg := range txn.Lsig.Args {
							if len(arg) == 0 {
								continue
							}
							arg[0] ^= 1
							testLogicBytes(t, yes.Program, defaultSigParams(txn), "REJECT")
							testLogicBytes(t, no.Program, defaultSigParams(txn))
							arg[0] ^= 1
						}
					}
				}
			}
		})
	}
}

// TestMLDSAVerifyExternalMu checks that a signature made through the
// external-mu interface (RFC 9881), with mu computed here from FIPS 204's
// definition, verifies against the original message.
func TestMLDSAVerifyExternalMu(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	for _, config := range []MLDSAConfig{MLDSA44, MLDSA65} {
		sk := mldsaTestKey(t, config)
		pk := sk.PublicKey().Bytes()
		msg := []byte("signed by a remote signer that only sees mu")
		ctx := []byte("context")

		// tr = H(pk, 64), and mu = H(tr || M', 64) where M' = 0 || |ctx| || ctx || M.
		h := stdsha3.NewSHAKE256()
		h.Write(stdsha3.SumSHAKE256(pk, 64))
		h.Write([]byte{0, byte(len(ctx))})
		h.Write(ctx)
		h.Write(msg)
		mu := make([]byte, 64)
		h.Read(mu)
		sig, err := sk.Sign(nil, mu, stdcrypto.MLDSAMu)
		require.NoError(t, err)

		ops := testProg(t, mldsaArgsProgram(config), mldsaVersion)
		var txn transactions.SignedTxn
		txn.Lsig.Args = [][]byte{msg, sig, pk, ctx}
		testLogicBytes(t, ops.Program, defaultSigParams(txn))
		txn.Lsig.Args = [][]byte{msg, sig, pk, nil}
		testLogicBytes(t, ops.Program, defaultSigParams(txn), "REJECT")
	}
}

// TestMLDSAVerifyStack checks that mldsa_verify consumes exactly its four
// arguments, in both modes.
func TestMLDSAVerifyStack(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	msg := []byte("stack")
	ctx := []byte("ctx")
	pk, sig := mldsaTestSign(t, MLDSA44, msg, ctx)
	source := fmt.Sprintf(`int 7; byte 0x%x; byte 0x%x; byte 0x%x; byte 0x%x; mldsa_verify MLDSA44
assert; int 7; ==`, msg, sig, pk, ctx)
	testLogic(t, source, mldsaVersion, defaultSigParams())

	// An app call has a 700 budget, so it takes six pooled calls.
	call := transactions.SignedTxn{Txn: transactions.Transaction{Type: protocol.ApplicationCallTx}}
	apps := func(n int) ([]string, []transactions.SignedTxn) {
		return append([]string{source}, make([]string, n-1)...), slices.Repeat([]transactions.SignedTxn{call}, n)
	}
	programs, group := apps(5)
	testApps(t, programs, group, nil, nil, exp(0, "dynamic cost budget exceeded, executing mldsa_verify"))
	programs, group = apps(6)
	testApps(t, programs, group, nil, nil)
}

// TestMLDSAVerifyCost pins mldsa_verify's costs, which grow with the message
// but not the context, and checks that eval charges exactly that, whether or
// not the signature is valid.
func TestMLDSAVerifyCost(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	// cost by message length
	costs := map[MLDSAConfig]map[int]int{
		MLDSA44: {0: 3700, 1: 3705, 64: 3705, 65: 3710, maxStringSize: 4020},
		MLDSA65: {0: 5850, 1: 5855, 64: 5855, 65: 5860, maxStringSize: 6170},
	}
	for cfg, byLength := range costs {
		// End the program at mldsa_verify, so that the four arg opcodes,
		// costing 1 each, are its only other cost.
		program := testProg(t, mldsaArgsProgram(cfg), mldsaVersion).Program
		program = program[:bytes.IndexByte(program, 0xe8)+2]

		for msgLen, cost := range byLength {
			for _, ctxLen := range []int{0, mldsaMaxContextSize} {
				msg := make([]byte, msgLen)
				ctx := make([]byte, ctxLen)
				pk, sig := mldsaTestSign(t, cfg, msg, ctx)
				invalid := slices.Clone(sig)
				invalid[0] ^= 1
				for _, s := range [][]byte{sig, invalid} {
					args := [][]byte{msg, s, pk, ctx}
					withBudget := func(budget int) *EvalParams {
						var txn transactions.SignedTxn
						txn.Lsig.Logic = program
						txn.Lsig.Args = args
						return optSigParams(func(p *config.ConsensusParams) { p.LogicSigMaxCost = uint64(budget) }, txn)
					}
					name := fmt.Sprintf("%s msg=%d ctx=%d", cfg, msgLen, ctxLen)
					pass, cx, err := EvalSignatureProgram(program, args, 0, withBudget(4+cost))
					require.NoError(t, err, name)
					require.Equal(t, bytes.Equal(s, sig), pass, name)
					require.Equal(t, 4+cost, cx.Cost(), name)

					_, _, err = EvalSignatureProgram(program, args, 0, withBudget(4+cost-1))
					require.ErrorContains(t, err, fmt.Sprintf("dynamic cost budget exceeded, executing mldsa_verify (%d): local program cost was 4", cost), name)
				}
			}
		}
	}
}

func TestMLDSAVerifyInputs(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	testProg(t, "arg 0; arg 1; arg 2; arg 3; mldsa_verify", mldsaVersion,
		exp(1, "mldsa_verify expects 1 immediate argument"))
	testProg(t, "arg 0; arg 1; arg 2; arg 3; mldsa_verify MLDSA87", mldsaVersion,
		exp(1, "mldsa_verify unknown field: \"MLDSA87\""))
	testProg(t, mldsaArgsProgram(MLDSA44), mldsaVersion-1,
		exp(1, "mldsa_verify opcode was introduced in v14"))

	for _, config := range []MLDSAConfig{MLDSA44, MLDSA65} {
		fs, ok := mldsaConfigSpecByField(config)
		require.True(t, ok)
		pkLen, sigLen := fs.params.PublicKeySize(), fs.params.SignatureSize()
		msg := []byte("inputs")
		pk, sig := mldsaTestSign(t, config, msg, nil)

		// Constants of the wrong length are caught by the assembler.
		constants := func(sigLen, pkLen, ctxLen int) string {
			return fmt.Sprintf("byte 0x01; byte 0x%s; byte 0x%s; byte 0x%s; mldsa_verify %s",
				strings.Repeat("aa", sigLen), strings.Repeat("bb", pkLen), strings.Repeat("cc", ctxLen), config)
		}
		testProg(t, constants(sigLen, pkLen, mldsaMaxContextSize), mldsaVersion)
		testProg(t, constants(sigLen-1, pkLen, 0), mldsaVersion,
			exp(1, fmt.Sprintf("...wanted type [%d]byte got [%d]byte", sigLen, sigLen-1)))
		testProg(t, constants(sigLen, pkLen+1, 0), mldsaVersion,
			exp(1, fmt.Sprintf("...wanted type [%d]byte got [%d]byte", pkLen, pkLen+1)))
		testProg(t, constants(sigLen, pkLen, mldsaMaxContextSize+1), mldsaVersion,
			exp(1, "...wanted type [<=255]byte got [256]byte"))

		// Inputs of unknown length are checked when the opcode runs.
		ops := testProg(t, mldsaArgsProgram(config), mldsaVersion)
		run := func(sig, pk, ctx []byte, problem string) {
			var txn transactions.SignedTxn
			txn.Lsig.Args = [][]byte{msg, sig, pk, ctx}
			testLogicBytes(t, ops.Program, defaultSigParams(txn), problem)
		}
		run(sig, pk, nil, "")
		run(sig[:sigLen-1], pk, nil, fmt.Sprintf("invalid signature size %d != %d", sigLen-1, sigLen))
		run(append(slices.Clone(sig), 0), pk, nil, fmt.Sprintf("invalid signature size %d != %d", sigLen+1, sigLen))
		run(sig, pk[:pkLen-1], nil, fmt.Sprintf("invalid public key size %d != %d", pkLen-1, pkLen))
		run(sig, append(slices.Clone(pk), 0), nil, fmt.Sprintf("invalid public key size %d != %d", pkLen+1, pkLen))
		run(sig, pk, make([]byte, mldsaMaxContextSize+1), "context too long 256 > 255")

		// A parameter set the opcode does not know has no cost, so a program
		// that names one is rejected before mldsa_verify runs.
		bad := slices.Clone(ops.Program)
		imm := bytes.IndexByte(bad, 0xe8) + 1
		require.Equal(t, byte(config), bad[imm])
		bad[imm] = byte(invalidMLDSAConfig)
		var txn transactions.SignedTxn
		txn.Lsig.Args = [][]byte{msg, sig, pk, nil}
		testLogicBytes(t, bad, defaultSigParams(txn), "mldsa_verify reported non-positive cost", "mldsa_verify returned 0 cost")
	}
}

// TestMLDSAVerifyVectors runs a selection of Wycheproof and NIST ACVP vectors,
// described in testdata/mldsa_vectors.json.gz, through the opcode. Vectors
// whose message exceeds the AVM's value size are skipped. Go's own tests run
// the full sets against crypto/mldsa; these check how the opcode uses it.
func TestMLDSAVerifyVectors(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	f, err := os.Open("testdata/mldsa_vectors.json.gz")
	require.NoError(t, err)
	defer f.Close()
	gz, err := gzip.NewReader(f)
	require.NoError(t, err)
	var vectors struct {
		Cases []struct {
			ParameterSet string `json:"parameterSet"`
			Source       string `json:"source"`
			TcID         int    `json:"tcId"`
			Expect       string `json:"expect"`
			PK           string `json:"pk"`
			Msg          string `json:"msg"`
			Ctx          string `json:"ctx"`
			Sig          string `json:"sig"`
		} `json:"cases"`
	}
	require.NoError(t, json.NewDecoder(gz).Decode(&vectors))
	unhex := func(s string) []byte {
		b, err := hex.DecodeString(s)
		require.NoError(t, err)
		return b
	}

	configs := map[string]MLDSAConfig{"ML-DSA-44": MLDSA44, "ML-DSA-65": MLDSA65}
	ran := 0
	for _, v := range vectors.Cases {
		config, ok := configs[v.ParameterSet]
		msg := unhex(v.Msg)
		if !ok || len(msg) > maxStringSize {
			continue
		}
		ran++
		desc := fmt.Sprintf("%s %s tcId %d", v.ParameterSet, v.Source, v.TcID)
		program := testProg(t, mldsaArgsProgram(config), mldsaVersion).Program
		args := [][]byte{msg, unhex(v.Sig), unhex(v.PK), unhex(v.Ctx)}
		var txn transactions.SignedTxn
		txn.Lsig.Logic = program
		txn.Lsig.Args = args
		pass, _, err := EvalSignatureProgram(program, args, 0, defaultSigParams(txn))
		switch v.Expect {
		case "valid":
			require.NoError(t, err, desc)
			require.True(t, pass, desc)
		case "invalid":
			require.NoError(t, err, desc)
			require.False(t, pass, desc)
		case "malformed":
			require.Error(t, err, desc)
		default:
			require.Fail(t, "unknown expectation", desc)
		}
	}
	require.Equal(t, 25, ran)
}

// TestMLDSAFIPS140v1 checks that a binary built against the FIPS 140-3 Go
// Cryptographic Module v1.0.0, which has no ML-DSA, refuses to start instead of
// rejecting every mldsa_verify signature.
func TestMLDSAFIPS140v1(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()
	if testing.Short() {
		t.Skip("builds a binary against the FIPS 140-3 v1.0.0 module")
	}
	gocmd, err := exec.LookPath("go")
	if err != nil {
		t.Skip("no go command")
	}

	// GOFLAGS could hold flags, like -modfile, whose paths only make sense
	// where the parent test was started, so the child does without them.
	var env []string
	for _, kv := range os.Environ() {
		if !strings.HasPrefix(kv, "GOFLAGS=") && !strings.HasPrefix(kv, "GOFIPS140=") {
			env = append(env, kv)
		}
	}
	run := func(fips string) (string, error) {
		ctx, cancel := context.WithTimeout(t.Context(), 10*time.Minute)
		defer cancel()
		cmd := exec.CommandContext(ctx, gocmd, "run", "./testdata/fips140v1")
		cmd.Env = append(env, "GOFIPS140="+fips)
		out, err := cmd.CombinedOutput()
		require.NoError(t, ctx.Err(), "go run timed out")
		return string(out), err
	}
	out, err := run("off")
	require.NoError(t, err, out)
	require.Contains(t, out, "started")

	out, err = run("v1.0.0")
	require.Error(t, err, out)
	require.Contains(t, out, "mldsa_verify: mldsa: unavailable")
	require.NotContains(t, out, "started")
}
