// Copyright (C) 2019-2025 Algorand, Inc.
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
		testAccepts(t, fmt.Sprintf(`byte "%s"; sumhash512; byte 0x%s; ==`, v.in, v.out), 13)
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
	// 0 length, lenghts not multiple of 32 bytes, chunks representing values greater than the modulus.
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

// BenchMarkVerify is useful to see relative speeds of various crypto verify functions
func BenchmarkVerify(b *testing.B) {
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
		{"falcon_verify", "", `
byte 0x62fdfc072182654f163f5f0f9a621d729566c74d0aa413bf009c9800418c19cd // msg
// public key
byte 0xba00a5222fbaa5e2a1a61f708198a4dbc3de94b60d925042d9fa5a299ebb4be27156b1d86a174df4939342f11b776dffb8a0e874714f23318ca9acb823e9aeb14a926ed5cf76e736faa0b22e4bdedf7910decd19329f353b926ae4b404653dbc6db1885c010052b94675d4cc209ef2cf3cfe910c4ef51b6af16d8c7ab6651e57934ab19c89f771058f389ad80474740c529d59a3ea9ab9db228415fb9315dee23e8c7229398c4b0a2b7c5d6eff6e7d8cf1a776ae37f6272082796c0b2a0af637f7ce8fa7f1675dfbd1766543cbf3f19544d635298ea1fafe96ad1bb06fcc6ae9ff9c34acacb88653555c37f2ad6c4eb408478b0d2b6269841243f29b18fa8e0d5050f4f93878e53aac466dc4eb5a7194cb2213c26a2b8c7ccea06f89af26ae85315454da1b15952be639bb94fe3e99236291c4a1edfbe9faf8f32589bf47eb536b28e2cfbdea799d9cf4c88ef85ae45d451e1ab3431c247b796cbf12e63b737cc4894ad7a204f680a449cbbd2e86deca1069b3592977bd8ac7c5b5e1c1b436cde65177b6e82b2e666117a8e37b58122d1a31307ca112311e665b32c68bd42531b4e6bc79957d3d865f6470b8213db8175e5c7115f4ad520a4711b12d9004e661346c4da4cb3e95954ac58e075a320b862a6a317e0988d8fc376fb14562773b9d35d5a44ba951d866a3a06ac93a55e1a26fa91718db49a53e78d9e61d6120dfadd2b4929579ac56ccaac0f8e704826b55b4ca6d8020e42a6e62b5e41708e2e6848cd047385fa1df4f51733df35dbee25c96c4176eae332ca4df31c695fff8be31b4be62e63c3e049483c89384fb1d802e58db5514a59eb96e527b202d0cf45dc760fa0439afbc661868b9408e67254c8cf7c689c50d2f29bccd59c71ea7b6dd368de68669fdf889ac1f8cd390ea17894dd0538ff6e7c740bbf03b4fe32ad66c483c823548eea84f85826da44016bd8cdf2315b07a96a9737ebc7cb244547be3f759bdf50b467552c58333ed7e61cde799346bccc29d5d377d9d5364c369ffd88a83f90a699b3622184436b518e9196524ac9b55385b39ec099d9c18386e06b9dcad2499ddb9673cb87c652209ee60511c9249f1b7ab2b948b5e8b9115c218d5b793d65b96e2fc9e2c6c40ba63791bb89d7d96c33536ad7e6668a85e52ec7e1450a69f25766deeaeb41bcd249394b8ab65a286312db461c363cebe431c4dd5fd3b6bb5d26ae2c597799f400abb3ba160522e2e6da5ebd170a45c9ce80b135a5b330656aab26399bcacd857a7f237dfd2b14ecbfbcaabc7291ba78fe19ac2ecf005b66bb9771bf64f090269a2341967e79702733dc617b469ac12123faeb4c70d6fffac25f9fcd7dbd12ca363985b9bd845e939e6caf328e2bf8e53725bae94fbe30bfdbbc21e584ba72d7badbc2a0915c9faf9c69ad3703cf99a16399b38df157be8ec3a78f20d24b2131f9c25b3c1da70fc6c0c7aa9e9da3108368ca6211dcfa4988b1ace3c28b15b0559224570fbe3cde364734c7a66a0525c1d41e26788cd1c8a3888f344c9385804364f8430ca7d22338cc941917da3dc47a00aae13e3e972af49940c8fa179574694e369a3d5e67db6c91bf843151ca0fff512d9c322c690063ae9bd671815e9d03b3a841952ce04683509e415b8d5aebfcdbd6bd55efbffb2463cf2b96ccb8650a6cee732c8d4ce6409b9a747317866759553f1c5bcc392c98d14a034ccaaa6df5723bb88c38e80
// sig
byte 0x0a85ea3bb342a95a3941a4c2280c686729c76bc164092c0e203388460c556273e6f0a92640650c37e9d5b08fbd8d6bcca940acac9964e64a9e78bd28086b52898812264985e19c3d26318be2ec8852ca2ae2380746428cd08124cf792790d127d3dad09fe891cbadefef36269ae7d584b77ec428d794a6c3b7555956db00314d14a0aa14936830c8622623916639743b218243344224472240cfd158819190ede108394063c3df9c474eb16aa750e48663515d8229d3849670e30891142b632a6a282d915273a5f219d65ebe6b9e6c88170ac62c16a44895a950bfec82819221dab1358861bf0aa6b6342477016d50502a298840ddc42b3ade784b643c63c5e47993ada37dfdc0d56a1c7e4690b5a1d6485900b84f0b61425383b14d4b7ccc0abe8284a47a6f22050838b0482ad8ad389151c25e790ad670d5530f9b3dc518bb0a410f64346a74dc824238026daaa4ad97518d93670a48cf8f86ece593d23ab3a0d601d49a975db291f0d76263551e9f0b8a1b42396a27d9a122210330c692d5545d67c808b50560fc3d4933fa70c463513d7183e8aa091f34dd4426272620fe4b357deea710c687bb7a475d0ed0a40a26ae8f2a357e7a8fa5d5434050c1a36beaa7a90ee4db213a126db8151f2f4bbb4889d4e42bbd19f62dd7285def148071fb7f4f16b28c1d145d2e621fee275161a3d5b9319e7a59527c3d5c2838ef503e4166f2c22118b22bf80e8a1fc1bbbba00f231d2b1a8d3e592bdcc5fd40a2ecebb5ad27a51e7867715b54185a3e62951a5d808d80c31a59e6a3ca53a51eadc34c76dfd6aac22a6e805163b5e9ac8090869a9cd1e2972af7192bcd1da39c30f423ebc86d1976e8f52052262521d3b8ae7eb99d0ad623d811bac636f447e7dc9dcef6f52befd95861f1917116517b0e9b56a85967ab701ff8f1d4de443efce1b2a3d85b592df7a8c87814e8981575ef4e72757c5afa6bec4358e2f29966ad2830e4782f9a293351dfcaac1d0ca30ec1b5fd08a40a6e82938427a68641b96252a85443141c081982ba4d3c8ab05a1a545ea49c23ee07643ec5f013c2676db09cb834ef61817e615ad19c5829216026e5635dc13cad5ffb8bc267bf58d4ebbf100c3045e250c02c10772e96c580db049c80fdd3188e19ad893d16ac100052c557378416929319c9c262c21b768e6058a09b4e4800ae624c892117ec71504a283f558c623a212d048d5d401b00448b18ac25e1c99ab35d91f78badebcd651e86f3465ef99a0afa1721d2153e4a7b51d22b344a8dd102e7411abfe4bd5b8e2d62015edc08fc461fa90cfa666a9a42a0a86e11d6988913ba0259096cb846a1fd311c4cb693c4e3e1ed2ab57e2a5e0bd4616a79e22b28caa6d10dd09225e44bbdbfa1b7b23887055a90918220252777d5a620351cb013cc28346fc69d348165a39d03243a84a9c9bcd4d557a8e9607256baab893a0a5644520686be935e9ead84501f743a489a431cf10b8c27d3901c87b8771ce65e3130a7fe6ad62b709c23bbef1381b1ed49222f487db16af3c9d6779c01c986ea9f823be017fb8bce8e00f2b32840d54e8f656139a4c492257ee8743a8c5f51450c0366655e2b02d27619d07e556001430b04454891247813c8bc31bdee926d039a5038bfca8dc35e57789950442ad7ab3cfc031a8354bd9c462a37052d0b62066bcee0c292b890a71f4ea65895a7d837283404842c59f08414b20ec1b4fda6cc0c4d62216e8ead74ba90196168bc449a2050b442181ea57b915581bc387ed412e4cd5970fd0fb83c94fbbf960d05ffe6d0a26171c249809604a0b2b411e2d6622145c936e31258baf2b7d3c413a9a1d67bc4026d01b47a10b6c5b87f6a36ba1cedd681ca55b9c042bf9afcfcb636040793e08158dd877c49c16658f819129e26237427a1d80b941fbabb4abd4f1da0b6d428a59fbc450620eeb1651849e5972fb12e6dc8092a9fda70206a48d9dc2645641a147626350cf45b1a7d57724fcab0a594df7c023928a3c7a2fc3c9d33e9af10ae5ed282c475a611671d20d90752f2a28db48b7e5d9184212432fa948fbc885f866c93a0b7f510329aea4d53ecf9482f42974beaf289086afdb4797aa129d10639948f46a805ea4000cf1554505f4bd9d775d5894da115f5840913d5070c860b3a623eb261f5f928a31cbcec17c4274b5d1b28fdb231cc8f606c9dc324db5c12f97518fd03466541f7881762c25d711976c6d4f9271d29fa51dc263f650a32010343a51e7dab344e2f6d768864072ddb5df58486434998a280aad94886ea7a11132184e6274d4cd59a5deabf8a4dbbe29e9c234a52d3972608d0a3ea92a78e08531bb938384444246be5bc594ed4d06168e870924e8913f8242bd35f7c9d5ee238cb6db17496047acce0183f2d10a4cf2bbc8e39daf44e630393a0473b8983863b1998c17026ff35ec32a8058fd603ec369b80a94cb7b555cb469f6468de3909b21293b8d0a53a5c813d218d7c630f4d47bb1eb88253e6e1af721ba8a4453e
falcon_verify
assert`, "int 1"},
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
	fs, err := crypto.GenerateFalconSigner(s)
	require.NoError(t, err)

	msg := "62fdfc072182654f163f5f0f9a621d729566c74d0aa413bf009c9800418c19cd"
	data, err := hex.DecodeString(msg)
	require.NoError(t, err)

	yes := testProg(t, fmt.Sprintf(`arg 0; arg 1; byte 0x%s; falcon_verify`,
		hex.EncodeToString(fs.PublicKey[:])), 12)
	require.NoError(t, err)
	no := testProg(t, fmt.Sprintf(`arg 0; arg 1; byte 0x%s; falcon_verify; !`,
		hex.EncodeToString(fs.PublicKey[:])), 12)
	require.NoError(t, err)

	for v := uint64(12); v <= AssemblerMaxVersion; v++ {
		t.Run(fmt.Sprintf("v=%d", v), func(t *testing.T) {
			yes.Program[0] = byte(v)
			sig, err := fs.SignBytes(data)
			require.NoError(t, err)

			var txn transactions.SignedTxn
			txn.Lsig.Args = [][]byte{data[:], sig[:]}
			testLogicBytes(t, yes.Program, defaultSigParams(txn))
			testLogicBytes(t, no.Program, defaultSigParams(txn), "REJECT")

			// short sig will fail
			txn.Lsig.Args[1] = sig[1:]
			testLogicBytes(t, yes.Program, defaultSigParams(txn), "REJECT")
			testLogicBytes(t, no.Program, defaultSigParams(txn))

			// flip a bit and it should not pass
			msg1 := "52fdfc072182654f163f5f0f9a621d729566c74d0aa413bf009c9800418c19cd"
			data1, err := hex.DecodeString(msg1)
			require.NoError(t, err)
			txn.Lsig.Args = [][]byte{data1, sig[:]}
			testLogicBytes(t, yes.Program, defaultSigParams(txn), "REJECT")
			testLogicBytes(t, no.Program, defaultSigParams(txn))
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

func BenchmarkHashes(b *testing.B) {
	for _, hash := range []string{"sha256", "keccak256" /* skip, same as keccak "sha3_256", */, "sha512_256", "sumhash512", "mimc BN254Mp110", "mimc BLS12_381Mp111", "sha512"} {
		for _, size := range []int{0, 32, 128, 512, 1024, 4096} {
			if size == 0 && (hash == "mimc BN254Mp110" || hash == "mimc BLS12_381Mp111") {
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
