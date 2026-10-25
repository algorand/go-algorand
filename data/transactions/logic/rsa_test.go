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
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math"
	"math/big"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/algorand/go-algorand/crypto/secp256k1"
	"github.com/algorand/go-algorand/data/transactions"
	"github.com/algorand/go-algorand/test/partitiontest"
)

// rsaTestPrimes holds fixed prime pairs, keyed by the bit length of their
// product, so that tests are fast and reproducible. Each p-1 and q-1 is
// coprime to 3, 5, 17, 257, 65537 and 65539, so every pair serves every
// exponent the tests use: 3, 17, 65535 (3*5*17*257), 65537 and 65539.
var rsaTestPrimes = map[int][2]string{
	512: {
		"e0c1fb7f2293407e885a381ebd260f451cb260eb1e329221acc98a02a1b8fad1",
		"fd44e211a839c4556706d1b38109310530fd12b171680222b159341d2a92658f",
	},
	1017: {
		"1e56799ac36960f5e23a28d1c3836fc081c56967770bb383c68a37344939a759b5b5a3574d53ea10c0357c922aa88fccf949981d311be4f98a421dcc3ce0fc09",
		"dd2fbb0995c8f5eafc2e644b493c45613ce4bba19103f2c7557d95a1bf134339bbf4ce306cfb0bf69b0ba5ded4216bbf5a4a2e69985aa0669e3113f2453a68b",
	},
	1023: {
		"dab9d429ae9d00f38691abd75edc5a8847fb7ad63967d9045aeef22efb88db7d2b4b7fb733eb6ed9884d767c835a1019b16ae0c1f6123a5469d08e5f9f159905",
		"77bd097d1cc849668bd2a171d7cd9eeda6fe157172d7e38aa8328d80d4b7df582ea5dde4bd542a3b572782f36a3c340da8fd80ba66cf7e667b8b849c39a25bdf",
	},
	1024: {
		"ca087d2460587e7a1d92d116090107c79ba5407057ea1e34905ee9c37a7cec3ace5ddcde5dff69bd72cc1893c1fde0ce0cd9450032037b886b81315802a4167d",
		"e3447fda07246af015374116deb37afc5ec0738f8bd6abf6dc931eb3c5b434d27c3e57d9436cf370c9e0a4723fb8d8fa6c6eae90a824f052761daa55215f92cb",
	},
	1025: {
		"1f4e9ab2c96415b17957f2778bf57bf6707af22c8025bc707c97a53c57bd080082f4bd54691f19a4a5b495856b8c19cc14e5e874ef6ced312c26731ea533f007d",
		"c581f84372e5aa23203e0336cbc3a8da562e648a6ecf5d7e0ca848c586c988d3a7ce171c935f60dc2a468e09af7b53d93e1b703035c71a2e452747c58526591f",
	},
	1033: {
		"e4bdfa0e33cc69651a00880d8c34f845b616e674ec9acc4f93a3b3232fa0b76b3f96226f39f0a28cf4b4ed9a1596a81aaabb678bc761a17c011d3ff5c9e29603d",
		"1b6b39d59d9db61fc23897e5515d5bb9277dd905d9b606ec1d6d80c3f036d724aa823b357b4ad78c5484715c0adb0c387e2b615092c195987079dcef26c7205b23",
	},
	1034: {
		"1cee95ddfd60218175bd0da8b06adb5c1285662e30f4c45325d961251cc1c4cff3dee93faf64df29abf7c0954bfda725de397aea7f634e0c587f046340bec774b9",
		"1f979d23664f0f2d660a2ff2467b1e1df8b50cb4d25a17094ce34dd6abf9129c7488129c35877b8451f42a7a8bf74a5d99386921bd5cf0248d47a2b8ddca2ecaf1",
	},
	2047: {
		"f2d5bb63188a6714f565f35ca58d6e600f35f12a6e1622dc7b20d646e3695f3312a37ae3bab8e2da35303291069bac283f47dbba7ea9b2ef6d44cad8e89b63e2871e04d62be2f30bca8b167bd7aee4e358c80fb74675e752b09a6e3bda794e3c6b90714f2aaeaf203ab52440d2bb4d19c47ee44d23ae28a723bf5ad2d803794f",
		"799b7eafe9c86fca9208f685e0194bf50fe64158c8a13d2a372f22bfdd7a228ca55ede5d3af719a5b72fa69e86674f45207dd3f478df2109e0371a136373aea29e5d3174d65c5341188056955375b89c329207afcedc0c2a0e2bb19bd8b4126b4d539c1acfdf2f07170deb2f1bf36231b46d22ea7693e854cf15af149ec656c1",
	},
	2048: {
		"cc5bfc55564f09761e8c5c288461eaa40f3dc646425dc101e880070eefd951a243bd66adbdbb457cf10fd18e20643a987dc86fea425c0d67334df2caced1ca614aa2c6480f09dfe246c778b0bc3a87331b87b3ad8beaac61a6d80d3fb8ff8ec2bf0ee5e02b9648fe06933a0d93c1142d87803127f1a168b8c7882229b16a4285",
		"e77c42f95d630d62b94eb4267afca10805aaf0825763bbf8157e413b394c2f34a79a3cc1c9bc5033fcebaf4b9f650a98366ef3faf5a9a596b116d2d69c942a8d25f351d614805627c0e332e0dd954142af8bb0179284ec9d8ecae272eaee12c56fd8aef842386a1e8faf7c2e860045f24a247d6d4bf648a5cf0f150a57165b0f",
	},
	2049: {
		"f90aca7020be40ad10d3b086a64abd26ac0745393c1fbdb0a01e674e8281fb7a9236f2554e80b89c5f696ee82ccac8070f0a231d695f0952b497a5a77f414ac53ad1eedc62bf310a341a80cb469114834a5677c02db2d39343f757b17b5e48171cc53d41f1452694030b83a032683d0693364cd404ec5dee9ce4e1ebaceb678d",
		"190d3a63d39a7e45782a2c45e4b2ef505cacc1d6ea3c29960fdedff4726f098ab4d370f3f17190a4e1121fed709cc4c247addcdf365f6850a3f3ec16a8066707b4bacd07c02ceb0cf797745f097b795ae3a50a2083881fcc5302bd8e6748555c14a8a8328fd9bbf2d75427ce5b032208b1390b8f53fc9740bc522cf77cb5b9aeb",
	},
	3072: {
		"fca0965f3f03a7a362d7843e0f609ff124ae93a07e66ab1c87f4597755b1b053267ef2bc3a057b626de0a4cf2cc6f0be1af2bf9d9486326e6fb91000d3804a9b8eb1c711e03150077354188062d1d8e9b775bdbe9b7db29ea18fc542bc3c2709d6b9c72d96f73774fd467df14191a722e5c77d0637ebf6940c101fca714216824d327ad915bf379c678ef789f5b85352aba823b834f08a1113a7568ca993160565a420f90823e7b4df23e9ce970c5f0e8ce24445a13becb26226a75631410e1b",
		"e7fc0251a27c53ef515d1f5a0ad788d408b96073dad71afd53a08f243ecbac5c7c86dbdf70052b5384ef4757b59f224eba9404efdf4a22c7867a70e1313a9265fb72017c6a48322cd1305fe2ce7735998f3d891d7b250f56765c65d5323d291927008e9e3449ddd5ed52141428766fbabebf297c2ac1c462f5f6d876c78835a19fa10b9b18ad608794bb1df2cf1d7f914c6e48498bbd4b17a2f61f1cfd738fa830d15ed4acc76c201b4325c34ecad8cc74eaf0e8c204ce7a2516c70a664d3737",
	},
	4096: {
		"f2ccc9efb2bad5f0f1845efa247ac4f61fffc90385c2321769ef04aa57a4215127ad084bb1f0d789d0b6dcc6b71398671f3bb937289ccfc4b9cd1a6a4640515c77592401f073a2d9592426ebb67dfea462c60857bf9631e55388e88cac1d7ce9f66b25c7d1c71c11cf73f75589642f715ba1dfed678126e8c09dee6e979834f563144edcd45f4c06bfd1a89b6ef39cb47ed1f0c26252a3b1b0b405691bf5828a30535d43facc0a734df15a07356710d88e7fcc0128de18c2c55379776b985927ac41e4720347387e502034574c0147bbcb20a0ac00f7b05fc36229905880429fd82b7e08cec7b741035fa832fe9b7f6c05511ed096e20e8da8a4151d1643e307",
		"d956cf793fed07894dbe2ca9d5ccc901c68201abbc19645f907d3f3c6358c3f1d6846551dadd98dc6ec9840c5a6abae800835885fbeb08fdb76dd376e04d0dcee0e318096952c6cbf2b6eb35795835485d791b0177b8b05f30d69f35b1377a7892f82afe4c50f7a4052d49f139beca61b4240b50c9fd65e0b06c42f913aff3a4fbc291cb92c77f3cbebe25712555e629c07199fb8c0dd0eb010d61d193ecbe4f082533afd3cbfa6ec7e181ee4d5dc3f8ddcec92b51aabc5afd9309fd24a35565a9acf5d699f50854e9b992ccd175a71ed1d3428668f642806a9ad60edae796c1b3bcbd93d5e55f165229c21bde9d07f295d91cd320d62d183cad46050f42c49d",
	},
}

type rsaTestKey struct {
	p, q, n *big.Int
}

func newRsaTestKey(t testing.TB, bits int) rsaTestKey {
	t.Helper()
	primes, ok := rsaTestPrimes[bits]
	require.True(t, ok, "no %d bit test key", bits)
	p, okp := new(big.Int).SetString(primes[0], 16)
	q, okq := new(big.Int).SetString(primes[1], 16)
	require.True(t, okp && okq)
	n := new(big.Int).Mul(p, q)
	require.Equal(t, bits, n.BitLen())
	return rsaTestKey{p, q, n}
}

// modulus returns n, big-endian, with no leading zero byte.
func (k rsaTestKey) modulus() []byte {
	return k.n.Bytes()
}

// d returns the private exponent for public exponent e: e^-1 mod lcm(p-1, q-1).
func (k rsaTestKey) d(e int) *big.Int {
	p1 := new(big.Int).Sub(k.p, big.NewInt(1))
	q1 := new(big.Int).Sub(k.q, big.NewInt(1))
	gcd := new(big.Int).GCD(nil, nil, p1, q1)
	lcm := new(big.Int).Div(new(big.Int).Mul(p1, q1), gcd)
	return new(big.Int).ModInverse(big.NewInt(int64(e)), lcm)
}

// privateKey returns the crypto/rsa private key for public exponent e.
func (k rsaTestKey) privateKey(t testing.TB, e int) *rsa.PrivateKey {
	t.Helper()
	priv := &rsa.PrivateKey{
		PublicKey: rsa.PublicKey{N: k.n, E: e},
		D:         k.d(e),
		Primes:    []*big.Int{k.p, k.q},
	}
	priv.Precompute()
	require.NoError(t, priv.Validate())
	return priv
}

// sign signs digest with crypto/rsa, an encoder independent of rsa_verify's.
func (k rsaTestKey) sign(t testing.TB, e int, hash crypto.Hash, digest []byte) []byte {
	t.Helper()
	sig, err := rsa.SignPKCS1v15(nil, k.privateKey(t, e), hash, digest)
	require.NoError(t, err)
	return sig
}

// signPSS signs digest with crypto/rsa under RSASSA-PSS, with a random salt as
// long as the digest.
func (k rsaTestKey) signPSS(t testing.TB, e int, hash crypto.Hash, digest []byte) []byte {
	t.Helper()
	opts := &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash}
	sig, err := rsa.SignPSS(rand.Reader, k.privateKey(t, e), hash, digest, opts)
	require.NoError(t, err)
	return sig
}

// rawSign signs em, an already encoded message, under exponent e.
func (k rsaTestKey) rawSign(e int, em []byte) []byte {
	return rsaRawSign(k.n, k.d(e), em)
}

// rsaRawSign returns em^d mod n, as long as n. Unlike crypto/rsa, it accepts
// any modulus, including a short or even one.
func rsaRawSign(n *big.Int, d *big.Int, em []byte) []byte {
	s := new(big.Int).Exp(new(big.Int).SetBytes(em), d, n)
	return s.FillBytes(make([]byte, len(n.Bytes())))
}

// rsaTestEM returns the k byte EMSA-PKCS1-v1_5 encoding of the concatenation
// of parts, normally a DigestInfo and its digest:
// 0x00 || 0x01 || 0xff... || 0x00 || parts.
func rsaTestEM(k int, parts ...[]byte) []byte {
	t := slices.Concat(parts...)
	em := make([]byte, k)
	em[1] = 0x01
	for i := 2; i < k-len(t)-1; i++ {
		em[i] = 0xff
	}
	copy(em[k-len(t):], t)
	return em
}

// rsaArith reports whether sig^e mod modulus, as len(em) bytes, is em. That is
// the whole check rsa_verify would make if none of its rules about the key and
// signature applied.
func rsaArith(sig, modulus []byte, e uint64, em []byte) bool {
	n := new(big.Int).SetBytes(modulus)
	m := new(big.Int).Exp(new(big.Int).SetBytes(sig), new(big.Int).SetUint64(e), n)
	return bytes.Equal(m.FillBytes(make([]byte, len(em))), em)
}

func rsaBytes(b []byte) string {
	if len(b) == 0 {
		return `byte ""`
	}
	return fmt.Sprintf("byte 0x%x", b)
}

func rsaProgram(scheme string, digest, sig, modulus []byte, e uint64) string {
	return fmt.Sprintf("%s; %s; %s; int %d; rsa_verify %s",
		rsaBytes(digest), rsaBytes(sig), rsaBytes(modulus), e, scheme)
}

func TestRsaVerify(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	msg := []byte("rsa_verify")
	sum256 := sha256.Sum256(msg)
	sum512 := sha512.Sum512(msg)
	schemes := []struct {
		name   string
		pss    bool
		hash   crypto.Hash
		digest []byte
	}{
		{"PKCS1v15_SHA256", false, crypto.SHA256, sum256[:]},
		{"PKCS1v15_SHA512", false, crypto.SHA512, sum512[:]},
		{"PSS_SHA256", true, crypto.SHA256, sum256[:]},
		{"PSS_SHA512", true, crypto.SHA512, sum512[:]},
	}

	// Under a modulus of 1025, 1033 or 2049 bits, the PSS encoding is one byte
	// shorter than the modulus. PSS_SHA512 fits under 2049 bits only.
	for _, bits := range []int{1024, 1025, 1033, 1034, 2047, 2048, 2049, 3072, 4096} {
		key := newRsaTestKey(t, bits)
		n := key.modulus()
		for _, e := range []int{3, 17, 65535, 65537} {
			for _, scheme := range schemes {
				if scheme.name == "PSS_SHA512" && bits < 1034 {
					continue // too short for the encoding, see TestRsaVerifyPSS
				}
				t.Run(fmt.Sprintf("bits=%d/e=%d/%s", bits, e, scheme.name), func(t *testing.T) {
					t.Parallel()
					var sig []byte
					if scheme.pss {
						sig = key.signPSS(t, e, scheme.hash, scheme.digest)
					} else {
						sig = key.sign(t, e, scheme.hash, scheme.digest)
					}
					testAccepts(t, rsaProgram(scheme.name, scheme.digest, sig, n, uint64(e)), rsaVersion)

					digest := slices.Clone(scheme.digest)
					digest[0] ^= 0x01
					testRejects(t, rsaProgram(scheme.name, digest, sig, n, uint64(e)), rsaVersion)

					tampered := slices.Clone(sig)
					tampered[len(tampered)-1] ^= 0x01
					testRejects(t, rsaProgram(scheme.name, scheme.digest, tampered, n, uint64(e)), rsaVersion)

					// Every other scheme rejects the signature, given a digest
					// of its own length.
					for _, other := range schemes {
						if other.name != scheme.name {
							testRejects(t, rsaProgram(other.name, other.digest, sig, n, uint64(e)), rsaVersion)
						}
					}
				})
			}
		}
	}
}

// TestRsaVerifyLengths checks the inputs that fail the program, rather than
// return 0.
func TestRsaVerifyLengths(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	sum256 := sha256.Sum256([]byte("rsa_verify"))
	sum512 := sha512.Sum512([]byte("rsa_verify"))
	key := newRsaTestKey(t, 1024)
	n := key.modulus()
	sig := key.sign(t, 65537, crypto.SHA256, sum256[:])
	testAccepts(t, rsaProgram("PKCS1v15_SHA256", sum256[:], sig, n, 65537), rsaVersion)

	const digest256 = "the digest must be 32 bytes long for PKCS1v15_SHA256"
	testPanics(t, rsaProgram("PKCS1v15_SHA256", sum256[:31], sig, n, 65537), rsaVersion, digest256+", not 31")
	testPanics(t, rsaProgram("PKCS1v15_SHA256", append(sum256[:], 0), sig, n, 65537), rsaVersion, digest256+", not 33")
	testPanics(t, rsaProgram("PKCS1v15_SHA256", sum512[:], sig, n, 65537), rsaVersion, digest256+", not 64")
	testPanics(t, rsaProgram("PKCS1v15_SHA256", nil, sig, n, 65537), rsaVersion, digest256+", not 0")
	testPanics(t, rsaProgram("PKCS1v15_SHA512", sum256[:], sig, n, 65537), rsaVersion,
		"the digest must be 64 bytes long for PKCS1v15_SHA512, not 32")

	long := bytes.Repeat([]byte{0xff}, 513)
	testPanics(t, rsaProgram("PKCS1v15_SHA256", sum256[:], long, long, 65537), rsaVersion,
		"the modulus must be at most 512 bytes long, not 513")

	// Leading zero bytes are never added to or removed from the signature.
	const sigLen = "the signature must be as long as the modulus (128 bytes)"
	testPanics(t, rsaProgram("PKCS1v15_SHA256", sum256[:], append([]byte{0}, sig...), n, 65537), rsaVersion, sigLen+", not 129")
	testPanics(t, rsaProgram("PKCS1v15_SHA256", sum256[:], sig[1:], n, 65537), rsaVersion, sigLen+", not 127")
	testPanics(t, rsaProgram("PKCS1v15_SHA256", sum256[:], nil, n, 65537), rsaVersion, sigLen+", not 0")

	// The PSS schemes fail on the same lengths.
	testPanics(t, rsaProgram("PSS_SHA256", sum512[:], sig, n, 65537), rsaVersion,
		"the digest must be 32 bytes long for PSS_SHA256, not 64")
	testPanics(t, rsaProgram("PSS_SHA512", sum256[:], sig, n, 65537), rsaVersion,
		"the digest must be 64 bytes long for PSS_SHA512, not 32")
	testPanics(t, rsaProgram("PSS_SHA256", sum256[:], long, long, 65537), rsaVersion,
		"the modulus must be at most 512 bytes long, not 513")
	testPanics(t, rsaProgram("PSS_SHA256", sum256[:], sig[1:], n, 65537), rsaVersion, sigLen+", not 127")
}

// TestRsaVerifyRejects checks the inputs that return 0. Where it can, each case
// is built to verify arithmetically, so that only the rule under test rejects it.
func TestRsaVerifyRejects(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	const scheme = "PKCS1v15_SHA256"
	sum := sha256.Sum256([]byte("rsa_verify"))
	digest := sum[:]
	encoded := slices.Concat(rsaSHA256DigestInfo, digest)

	// rejects checks that rsa_verify returns 0. If em is not nil, it first
	// checks that sig^e mod modulus is em.
	rejects := func(t *testing.T, sig, modulus []byte, e uint64, em []byte) {
		t.Helper()
		if em != nil {
			require.True(t, rsaArith(sig, modulus, e, em))
		}
		testRejects(t, rsaProgram(scheme, digest, sig, modulus, e), rsaVersion)
	}

	key := newRsaTestKey(t, 1024)
	n := key.modulus()
	em := rsaTestEM(len(n), encoded)
	sig := key.rawSign(65537, em)
	// rsaTestEM and rawSign agree with crypto/rsa, and are accepted, so the
	// cases they build below are rejected only for the rule they break.
	require.Equal(t, key.sign(t, 65537, crypto.SHA256, digest), sig)
	testAccepts(t, rsaProgram(scheme, digest, sig, n, 65537), rsaVersion)

	t.Run("leading zero", func(t *testing.T) {
		t.Parallel()
		em := rsaTestEM(len(n)+1, encoded)
		sig := append([]byte{0}, key.rawSign(65537, em)...)
		rejects(t, sig, append([]byte{0}, n...), 65537, em)
	})

	t.Run("short modulus", func(t *testing.T) {
		t.Parallel()
		for _, bits := range []int{512, 1017, 1023} {
			short := newRsaTestKey(t, bits)
			em := rsaTestEM(len(short.modulus()), encoded)
			rejects(t, short.rawSign(65537, em), short.modulus(), 65537, em)
		}
	})

	t.Run("even modulus", func(t *testing.T) {
		t.Parallel()
		// 2pq is squarefree, and lcm(p-1, q-1) is its Carmichael function, so
		// the private exponent of pq signs for it too.
		base := newRsaTestKey(t, 1023)
		even := new(big.Int).Lsh(base.n, 1)
		require.Equal(t, 1024, even.BitLen())
		em := rsaTestEM(len(even.Bytes()), encoded)
		rejects(t, rsaRawSign(even, base.d(65537), em), even.Bytes(), 65537, em)
	})

	t.Run("exponent", func(t *testing.T) {
		t.Parallel()
		// Under e = 1, an encoded message is its own signature.
		rejects(t, em, n, 1, em)
		rejects(t, key.sign(t, 65539, crypto.SHA256, digest), n, 65539, em)
		for _, e := range []uint64{0, 2, 4, 65536, 65538, math.MaxUint64} {
			rejects(t, sig, n, e, nil)
		}
	})

	t.Run("even exponent", func(t *testing.T) {
		t.Parallel()
		// e = 4 passes every other exponent rule. Find a message whose encoding
		// has a fourth root modulo both primes, and join the roots by CRT.
		root4 := func(x, p *big.Int) *big.Int {
			r := new(big.Int).ModSqrt(x, p)
			if r == nil {
				return nil
			}
			for _, c := range []*big.Int{r, new(big.Int).Sub(p, r)} {
				if s := new(big.Int).ModSqrt(c, p); s != nil {
					return s
				}
			}
			return nil
		}
		for i := 0; ; i++ {
			require.Less(t, i, 100, "no message with a fourth root")
			sum := sha256.Sum256([]byte(fmt.Sprintf("rsa_verify %d", i)))
			em := rsaTestEM(len(n), rsaSHA256DigestInfo, sum[:])
			x := new(big.Int).SetBytes(em)
			a, b := root4(x, key.p), root4(x, key.q)
			if a == nil || b == nil {
				continue
			}
			// s = a + p * ((b - a) * p^-1 mod q)
			h := new(big.Int).Sub(b, a)
			h.Mul(h, new(big.Int).ModInverse(key.p, key.q))
			h.Mod(h, key.q)
			s := new(big.Int).Add(a, h.Mul(h, key.p))
			sig := s.FillBytes(make([]byte, len(n)))
			require.True(t, rsaArith(sig, n, 4, em))
			testRejects(t, rsaProgram(scheme, sum[:], sig, n, 4), rsaVersion)
			return
		}
	})

	t.Run("signature too large", func(t *testing.T) {
		t.Parallel()
		// A 2047 bit modulus leaves room for sig + n in the same length.
		key := newRsaTestKey(t, 2047)
		n := key.modulus()
		em := rsaTestEM(len(n), encoded)
		sig := key.rawSign(65537, em)
		testAccepts(t, rsaProgram(scheme, digest, sig, n, 65537), rsaVersion)
		plusN := new(big.Int).Add(new(big.Int).SetBytes(sig), key.n).FillBytes(make([]byte, len(n)))
		rejects(t, plusN, n, 65537, em)
		rejects(t, n, n, 65537, nil)
		rejects(t, bytes.Repeat([]byte{0xff}, len(n)), n, 65537, nil)
	})

	t.Run("padding", func(t *testing.T) {
		t.Parallel()
		k := len(n)
		set := func(i int, b byte) []byte {
			variant := slices.Clone(em)
			variant[i] = b
			return variant
		}
		noNull := []byte{0x30, 0x2f, 0x30, 0x0b, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x04, 0x20}
		wrongHash := slices.Clone(rsaSHA256DigestInfo)
		wrongHash[14] = 0x02 // SHA-384's OID
		// A short PS, then garbage after the digest
		garbage := bytes.Repeat([]byte{0x42}, k)
		copy(garbage, rsaTestEM(11+len(encoded), encoded))
		for name, variant := range map[string][]byte{
			"DigestInfo without NULL": rsaTestEM(k, noNull, digest),
			"DigestInfo of SHA-384":   rsaTestEM(k, wrongHash, digest),
			"first byte":              set(0, 0x01),
			"block type 2":            set(1, 0x02),
			"zero in PS":              set(10, 0x00),
			"0xfe in PS":              set(10, 0xfe),
			"no separator":            set(k-len(encoded)-1, 0xff),
			"garbage after digest":    garbage,
		} {
			t.Run(name, func(t *testing.T) {
				t.Parallel()
				require.NotEqual(t, em, variant)
				rejects(t, key.rawSign(65537, variant), n, 65537, variant)
			})
		}
	})

	t.Run("degenerate", func(t *testing.T) {
		t.Parallel()
		rejects(t, nil, nil, 65537, nil)
		rejects(t, make([]byte, len(n)), n, 65537, nil)
		one := make([]byte, len(n))
		one[len(one)-1] = 1
		rejects(t, one, n, 65537, nil)
	})
}

// rsaTestMGF1 returns length bytes of MGF1 of seed over hash (RFC 8017,
// appendix B.2.1).
func rsaTestMGF1(hash crypto.Hash, seed []byte, length int) []byte {
	var out []byte
	for c := uint32(0); len(out) < length; c++ {
		h := hash.New()
		h.Write(seed)
		h.Write(binary.BigEndian.AppendUint32(nil, c))
		out = h.Sum(out)
	}
	return out[:length]
}

// rsaTestPSSEM returns the emBits bit EMSA-PSS encoding (RFC 8017, section
// 9.1.1) of digest and salt: maskedDB || H || 0xbc, where
// H = hash(0x00 * 8 || digest || salt), DB = 0x00... || 0x01 || salt, and the
// mask is MGF1 of H over mgfHash. If edit is not nil, it edits DB before DB is
// masked.
func rsaTestPSSEM(hash, mgfHash crypto.Hash, emBits int, digest, salt []byte, edit func(db []byte)) []byte {
	emLen := (emBits + 7) / 8
	h := hash.New()
	h.Write(make([]byte, 8))
	h.Write(digest)
	h.Write(salt)
	hh := h.Sum(nil)
	db := make([]byte, emLen-len(hh)-1)
	db[len(db)-len(salt)-1] = 0x01
	copy(db[len(db)-len(salt):], salt)
	if edit != nil {
		edit(db)
	}
	for i, b := range rsaTestMGF1(mgfHash, hh, len(db)) {
		db[i] ^= b
	}
	db[0] &= 0xff >> (8*emLen - emBits)
	return slices.Concat(db, hh, []byte{0xbc})
}

// TestRsaVerifyPSS checks the PSS encodings that rsa_verify rejects. Each case
// is built to verify arithmetically, so that only the rule under test rejects
// it.
func TestRsaVerifyPSS(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	sum256 := sha256.Sum256([]byte("rsa_verify"))
	sum512 := sha512.Sum512([]byte("rsa_verify"))
	digest := sum256[:]
	salt64 := sha512.Sum512([]byte("rsa_verify salt"))
	salt := salt64[:32]

	// program signs em under key, checks that the signature verifies
	// arithmetically, and returns a program that checks it with rsa_verify.
	program := func(t *testing.T, scheme string, digest []byte, key rsaTestKey, em []byte) string {
		t.Helper()
		sig := key.rawSign(65537, em)
		require.True(t, rsaArith(sig, key.modulus(), 65537, em))
		return rsaProgram(scheme, digest, sig, key.modulus(), 65537)
	}
	// fit returns the first variant, made with successive salts, that is less
	// than the modulus of key, so that it can be signed.
	fit := func(t *testing.T, key rsaTestKey, variant func(salt []byte) []byte) []byte {
		t.Helper()
		for i := 0; i < 1000; i++ {
			salt := sha256.Sum256([]byte(fmt.Sprintf("rsa_verify salt %d", i)))
			if v := variant(salt[:]); new(big.Int).SetBytes(v).Cmp(key.n) < 0 {
				return v
			}
		}
		require.Fail(t, "no variant is less than the modulus")
		return nil
	}

	key := newRsaTestKey(t, 1024)
	n := key.modulus()
	encode := func(salt []byte, edit func(db []byte)) []byte {
		return rsaTestPSSEM(crypto.SHA256, crypto.SHA256, 1023, digest, salt, edit)
	}
	em := encode(salt, nil)
	// rsaTestPSSEM agrees with crypto/rsa, and is accepted, so the cases built
	// with it below are rejected only for the rule they break.
	pub := &rsa.PublicKey{N: key.n, E: 65537}
	require.NoError(t, rsa.VerifyPSS(pub, crypto.SHA256, digest, key.rawSign(65537, em), &rsa.PSSOptions{SaltLength: 32}))
	testAccepts(t, program(t, "PSS_SHA256", digest, key, em), rsaVersion)

	t.Run("encoding", func(t *testing.T) {
		t.Parallel()
		psLen := len(em) - 2*sha256.Size - 2
		trailer := func(b byte) []byte {
			variant := slices.Clone(em)
			variant[len(variant)-1] = b
			return variant
		}
		for name, variant := range map[string][]byte{
			"trailer 0xbd":       trailer(0xbd),
			"trailer 0x00":       trailer(0x00),
			"first byte of PS":   encode(salt, func(db []byte) { db[0] = 0x01 }),
			"last byte of PS":    encode(salt, func(db []byte) { db[psLen-1] = 0x01 }),
			"separator 0x00":     encode(salt, func(db []byte) { db[psLen] = 0x00 }),
			"separator 0x02":     encode(salt, func(db []byte) { db[psLen] = 0x02 }),
			"salt of 0 bytes":    encode(nil, nil),
			"salt of 20 bytes":   encode(salt[:20], nil),
			"salt of 31 bytes":   encode(salt[:31], nil),
			"salt of 33 bytes":   encode(salt64[:33], nil),
			"MGF1 with SHA-384":  rsaTestPSSEM(crypto.SHA256, crypto.SHA384, 1023, digest, salt, nil),
			"MGF1 with SHA-512":  rsaTestPSSEM(crypto.SHA256, crypto.SHA512, 1023, digest, salt, nil),
			"H with SHA-512/256": rsaTestPSSEM(crypto.SHA512_256, crypto.SHA256, 1023, digest, salt, nil),
		} {
			t.Run(name, func(t *testing.T) {
				t.Parallel()
				require.NotEqual(t, em, variant)
				testRejects(t, program(t, "PSS_SHA256", digest, key, variant), rsaVersion)
			})
		}
	})

	t.Run("leftmost bit", func(t *testing.T) {
		t.Parallel()
		// emBits is 1023, so the leftmost bit of EM must be zero, though DB
		// would be valid with it cleared.
		variant := fit(t, key, func(salt []byte) []byte {
			em := encode(salt, nil)
			em[0] |= 0x80
			return em
		})
		testRejects(t, program(t, "PSS_SHA256", digest, key, variant), rsaVersion)
		variant[0] &^= 0x80
		testAccepts(t, program(t, "PSS_SHA256", digest, key, variant), rsaVersion)
	})

	t.Run("too long for EM", func(t *testing.T) {
		t.Parallel()
		// Under a 1025 bit modulus, emBits is 1024 and EM is 128 bytes, one
		// less than the modulus. The decrypted signature must fit in EM,
		// though its last 128 bytes would be a valid EM.
		key := newRsaTestKey(t, 1025)
		variant := fit(t, key, func(salt []byte) []byte {
			return append([]byte{0x01}, rsaTestPSSEM(crypto.SHA256, crypto.SHA256, 1024, digest, salt, nil)...)
		})
		testRejects(t, program(t, "PSS_SHA256", digest, key, variant), rsaVersion)
		testAccepts(t, program(t, "PSS_SHA256", digest, key, variant[1:]), rsaVersion)
	})

	t.Run("PSS_SHA512 floor", func(t *testing.T) {
		t.Parallel()
		// EM must hold H, a salt as long as H, and two more bytes. For SHA-512
		// that is 130 bytes, so emBits must be at least 1033. Under a shorter
		// modulus, a signature with the longest salt that fits verifies under
		// crypto/rsa, but not under rsa_verify.
		for _, bits := range []int{1024, 1033} {
			key := newRsaTestKey(t, bits)
			emBits := bits - 1
			sLen := (emBits+7)/8 - sha512.Size - 2
			em := rsaTestPSSEM(crypto.SHA512, crypto.SHA512, emBits, sum512[:], salt64[:sLen], nil)
			pub := &rsa.PublicKey{N: key.n, E: 65537}
			opts := &rsa.PSSOptions{SaltLength: sLen}
			require.NoError(t, rsa.VerifyPSS(pub, crypto.SHA512, sum512[:], key.rawSign(65537, em), opts))
			testRejects(t, program(t, "PSS_SHA512", sum512[:], key, em), rsaVersion)
		}
		// Under a 1034 bit modulus, EM is 130 bytes, and PS is empty.
		key := newRsaTestKey(t, 1034)
		em := rsaTestPSSEM(crypto.SHA512, crypto.SHA512, 1033, sum512[:], salt64[:], nil)
		require.Len(t, em, 130)
		testAccepts(t, program(t, "PSS_SHA512", sum512[:], key, em), rsaVersion)
	})

	t.Run("key rules", func(t *testing.T) {
		t.Parallel()
		// The rules about the key and the signature are the same for every
		// scheme. TestRsaVerifyRejects covers them in full.
		rejects := func(t *testing.T, sig, modulus []byte, e uint64, em []byte) {
			t.Helper()
			require.True(t, rsaArith(sig, modulus, e, em))
			testRejects(t, rsaProgram("PSS_SHA256", digest, sig, modulus, e), rsaVersion)
		}
		sig := key.rawSign(65537, em)
		rejects(t, append([]byte{0}, sig...), append([]byte{0}, n...), 65537, em)

		short := newRsaTestKey(t, 1023)
		shortEM := rsaTestPSSEM(crypto.SHA256, crypto.SHA256, 1022, digest, salt, nil)
		rejects(t, short.rawSign(65537, shortEM), short.modulus(), 65537, shortEM)

		even := new(big.Int).Lsh(short.n, 1)
		rejects(t, rsaRawSign(even, short.d(65537), em), even.Bytes(), 65537, em)

		rejects(t, em, n, 1, em)
		rejects(t, key.rawSign(65539, em), n, 65539, em)

		long := newRsaTestKey(t, 2047)
		longEM := rsaTestPSSEM(crypto.SHA256, crypto.SHA256, 2046, digest, salt, nil)
		longSig := long.rawSign(65537, longEM)
		testAccepts(t, rsaProgram("PSS_SHA256", digest, longSig, long.modulus(), 65537), rsaVersion)
		plusN := new(big.Int).Add(new(big.Int).SetBytes(longSig), long.n).FillBytes(make([]byte, len(long.modulus())))
		rejects(t, plusN, long.modulus(), 65537, longEM)
	})
}

// TestRsaVerifyWycheproof runs the RSASSA-PKCS1-v1_5 and RSASSA-PSS
// verification vectors of Project Wycheproof, which aim at known verifier bugs:
// BER encodings, altered DigestInfo, short padding, wrong hashes, malleable
// signatures, altered PSS padding, other salt lengths and MGF1 hashes, and
// more. The files in testdata/wycheproof are unmodified, gzipped copies of
// testvectors_v1/rsa_signature_*_test.json and some of
// testvectors_v1/rsa_pss_*_test.json from https://github.com/C2SP/wycheproof
// at commit 3fa63dd0344abb611f1fb1d77e119938603ea230, under the Apache
// License 2.0 in the same directory.
func TestRsaVerifyWycheproof(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	files, err := filepath.Glob("testdata/wycheproof/rsa_*_test.json.gz")
	require.NoError(t, err)
	require.NotEmpty(t, files)
	for _, file := range files {
		t.Run(filepath.Base(file), func(t *testing.T) {
			t.Parallel()
			f, err := os.Open(file)
			require.NoError(t, err)
			defer f.Close()
			rd, err := gzip.NewReader(f)
			require.NoError(t, err)
			var vectors struct {
				Algorithm  string
				TestGroups []struct {
					Sha       string
					Mgf       string // RSASSA-PSS only
					MgfSha    string // RSASSA-PSS only
					SLen      int    // RSASSA-PSS only
					PublicKey struct {
						Modulus        string
						PublicExponent string
					}
					Tests []struct {
						TcID    int
						Comment string
						Msg     string
						Sig     string
						Result  string
						Flags   []string
					}
				}
			}
			require.NoError(t, json.NewDecoder(rd).Decode(&vectors))
			require.Contains(t, []string{"RSASSA-PKCS1-v1_5", "RSASSA-PSS"}, vectors.Algorithm)
			pss := vectors.Algorithm == "RSASSA-PSS"

			tested := 0
			for _, group := range vectors.TestGroups {
				var hash crypto.Hash
				switch group.Sha {
				case "SHA-256":
					hash = crypto.SHA256
				case "SHA-512":
					hash = crypto.SHA512
				default:
					// rsa_pss_misc_test.json has groups for other hashes too.
					require.True(t, pss, "unexpected hash %s", group.Sha)
					continue
				}
				scheme := "PKCS1v15_" + strings.ReplaceAll(group.Sha, "-", "")
				// supported is whether rsa_verify supports the parameters of
				// the group. For PSS, it supports only MGF1 with the hash of
				// the digest, and a salt as long as the digest.
				supported := true
				if pss {
					scheme = "PSS_" + strings.ReplaceAll(group.Sha, "-", "")
					supported = group.Mgf == "MGF1" && group.MgfSha == group.Sha && group.SLen == hash.Size()
				}
				// The modulus is an ASN.1 INTEGER, with a leading zero byte when
				// its top bit is set. rsa_verify takes it without one.
				modulus, err := hex.DecodeString(group.PublicKey.Modulus)
				require.NoError(t, err)
				modulus = bytes.TrimLeft(modulus, "\x00")
				e, err := strconv.ParseUint(group.PublicKey.PublicExponent, 16, 64)
				require.NoError(t, err)

				ops := testProg(t, fmt.Sprintf("arg 0; arg 1; arg 2; int %d; rsa_verify %s", e, scheme), rsaVersion)
				for _, test := range group.Tests {
					msg, err := hex.DecodeString(test.Msg)
					require.NoError(t, err)
					sig, err := hex.DecodeString(test.Sig)
					require.NoError(t, err)

					h := hash.New()
					h.Write(msg)
					var txn transactions.SignedTxn
					txn.Lsig.Logic = ops.Program
					txn.Lsig.Args = [][]byte{h.Sum(nil), sig, modulus}
					pass, err := EvalSignature(0, defaultSigParams(txn))

					id := fmt.Sprintf("tcId %d (%s) %v", test.TcID, test.Comment, test.Flags)
					switch {
					case test.Result == "valid" && supported:
						require.NoError(t, err, id)
						require.True(t, pass, id)
					case test.Result == "invalid" && len(sig) != len(modulus):
						require.ErrorContains(t, err, "the signature must be as long as the modulus", id)
					case test.Result == "invalid",
						// valid, under PSS parameters that rsa_verify does not
						// support
						test.Result == "valid",
						// Some verifiers accept a DigestInfo without NULL
						// parameters. rsa_verify does not.
						test.Result == "acceptable" && slices.Equal(test.Flags, []string{"MissingNull"}):
						require.NoError(t, err, id)
						require.False(t, pass, id)
					default:
						require.Fail(t, "unexpected result", id+" "+test.Result)
					}
					tested++
				}
			}
			require.NotZero(t, tested)
		})
	}
}

func TestRsaVerifyCost(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	spec := OpsByName[rsaVersion]["rsa_verify"]
	require.Equal(t, "1050 if len(C) <= 128; 2650 if len(C) <= 256; 5200 if len(C) <= 384; 8250 otherwise",
		spec.DocCost(rsaVersion))

	// A zero modulus returns 0 without exponentiating, but the cost depends on
	// its length alone.
	source := `byte 0x0000000000000000000000000000000000000000000000000000000000000000
int %d; bzero; dup
int 65537
rsa_verify PKCS1v15_SHA256
!; assert
global OpcodeBudget
int %d
==`
	for _, c := range []struct{ length, cost int }{
		{0, 1050}, {128, 1050},
		{129, 2650}, {256, 2650},
		{257, 5200}, {384, 5200},
		{385, 8250}, {512, 8250},
	} {
		testAccepts(t, fmt.Sprintf(source, c.length, testLogicBudget-c.cost-8), rsaVersion)
	}
	testPanics(t, fmt.Sprintf(source, 513, 0), rsaVersion, "at most 512 bytes")
}

// TestBracketCost ensures that costs are calculated right for an opcode whose
// cost is set by brackets of the length of an arg.
func TestBracketCost(t *testing.T) { //nolint:paralleltest // manipulates opcode table
	partitiontest.PartitionTest(t)

	xxx := OpSpec{
		Opcode:    106,
		Name:      "xxx",
		op:        opPop,
		Proto:     proto("b:"),
		OpDetails: detDefault().costByBracket(0, []int{2, 4}, []int{3, 5, 9}),
	}
	require.Equal(t, "3 if len(A) <= 2; 5 if len(A) <= 4; 9 otherwise", xxx.DocCost(LogicVersion))

	withOpcode(t, LogicVersion, xxx, func(opcode byte) {
		for _, c := range []struct{ length, cost int }{
			{0, 3}, {2, 3}, {3, 5}, {4, 5}, {5, 9}, {100, 9},
		} {
			testApp(t, fmt.Sprintf("int %d; bzero; xxx; global OpcodeBudget; int %d; ==", c.length, 697-c.cost), nil)
		}
	})
}

func TestBracketCostChecks(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	require.Panics(t, func() { detDefault().costByBracket(0, nil, []int{1}) })
	require.Panics(t, func() { detDefault().costByBracket(0, []int{2}, []int{1}) })
	require.Panics(t, func() { detDefault().costByBracket(0, []int{2}, []int{1, 2, 3}) })
	require.Panics(t, func() { detDefault().costByBracket(0, []int{4, 2}, []int{1, 2, 3}) })
	require.Panics(t, func() { detDefault().costByBracket(0, []int{2, 2}, []int{1, 2, 3}) })
	require.Panics(t, func() { detDefault().costByBracket(0, []int{2}, []int{1, 0}) })
	require.Panics(t, func() { detDefault().costByBracket(-1, []int{2}, []int{1, 2}) })
	require.Panics(t, func() { detDefault().costByBracket(0, []int{maxStringSize + 1}, []int{1, 2}) })

	// bracket costs do not combine with other costs
	require.Panics(t, func() {
		costByField("g", &EcGroups, []int{1, 2, 3, 4}).costByBracket(0, []int{2}, []int{1, 2})
	})
	require.Panics(t, func() { detDefault().costByBracket(0, []int{2}, []int{1, 2}).costs(5) })
	require.Panics(t, func() { detDefault().costByBracket(0, []int{2}, []int{1, 2}).costByLength(1, 1, 1, 0) })
}

// rsaBenchBytes returns k pseudo-random bytes that begin with top.
func rsaBenchBytes(k int, top byte) []byte {
	var out []byte
	block := sha512.Sum512([]byte("rsa_verify benchmark"))
	for len(out) < k {
		out = append(out, block[:]...)
		block = sha512.Sum512(block[:])
	}
	out = out[:k]
	out[0] = top
	return out
}

func rsaBenchEval(b *testing.B, source string, args [][]byte) {
	ops := testProg(b, source, rsaVersion)
	var txn transactions.SignedTxn
	txn.Lsig.Logic = ops.Program
	txn.Lsig.Args = args
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		pass, err := EvalSignature(0, benchmarkSigParams(txn))
		if err != nil || !pass {
			require.NoError(b, err)
			require.True(b, pass)
		}
	}
}

// BenchmarkRsaVerify times rsa_verify at the top of each cost bracket, and
// ecdsa_verify, whose costs are established, evaluated the same way. Along
// with a real key, under each scheme, it tries moduli of extreme shape, since
// any odd modulus is accepted and big.Int division time depends on its
// operands. Signatures under those are invalid, and rejected right after the
// exponentiation. A valid PSS signature under the same moduli, were one known,
// would take their time plus the time of the real key under PSS, minus that of
// the real key under PKCS1v15_SHA256.
func BenchmarkRsaVerify(b *testing.B) {
	type rsaBenchCase struct {
		name, scheme   string
		digest, n, sig []byte
		valid          bool
	}
	sum := sha256.Sum256([]byte("rsa_verify"))
	sum512 := sha512.Sum512([]byte("rsa_verify"))

	b.Run("reference/ecdsa_verify Secp256k1", func(b *testing.B) {
		key, err := ecdsa.GenerateKey(secp256k1.S256(), rand.Reader)
		require.NoError(b, err)
		sig, err := secp256k1.Sign(sum[:], keyToByte(b, key.D))
		require.NoError(b, err)
		rsaBenchEval(b, "arg 0; arg 1; arg 2; arg 3; arg 4; ecdsa_verify Secp256k1", [][]byte{
			sum[:], sig[:32], sig[32:64], keyToByte(b, key.X), keyToByte(b, key.Y)})
	})
	b.Run("reference/ecdsa_verify Secp256r1", func(b *testing.B) {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(b, err)
		r, s, err := ecdsa.Sign(rand.Reader, key, sum[:])
		require.NoError(b, err)
		rsaBenchEval(b, "arg 0; arg 1; arg 2; arg 3; arg 4; ecdsa_verify Secp256r1", [][]byte{
			sum[:], keyToByte(b, r), keyToByte(b, s), keyToByte(b, key.X), keyToByte(b, key.Y)})
	})

	for _, bits := range []int{1024, 2048, 3072, 4096} {
		key := newRsaTestKey(b, bits)
		k := bits / 8
		sparse := make([]byte, k) // 2^(8k-1) + 1
		sparse[0], sparse[k-1] = 0x80, 0x01
		for _, e := range []int{3, 65537, 65535} {
			cases := []rsaBenchCase{
				{"key", "PKCS1v15_SHA256", sum[:], key.modulus(), key.sign(b, e, crypto.SHA256, sum[:]), true},
				{"key", "PSS_SHA256", sum[:], key.modulus(), key.signPSS(b, e, crypto.SHA256, sum[:]), true},
				{"ones", "PKCS1v15_SHA256", sum[:], bytes.Repeat([]byte{0xff}, k), rsaBenchBytes(k, 0xfe), false},
				{"sparse", "PKCS1v15_SHA256", sum[:], sparse, rsaBenchBytes(k, 0x7f), false},
			}
			if bits >= 1034 { // a shorter modulus cannot hold a PSS_SHA512 encoding
				cases = append(cases, rsaBenchCase{"key", "PSS_SHA512", sum512[:], key.modulus(), key.signPSS(b, e, crypto.SHA512, sum512[:]), true})
			}
			for _, c := range cases {
				b.Run(fmt.Sprintf("bits=%d/e=%d/%s/%s", bits, e, c.name, c.scheme), func(b *testing.B) {
					source := fmt.Sprintf("arg 0; arg 1; arg 2; int %d; rsa_verify %s", e, c.scheme)
					if !c.valid {
						source += "; !"
					}
					rsaBenchEval(b, source, [][]byte{c.digest, c.sig, c.n})
				})
			}
		}
	}
}
