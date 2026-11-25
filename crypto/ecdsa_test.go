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

package crypto

import (
	stdcrypto "crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/asn1"
	"encoding/hex"
	"math/big"
	"slices"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/algorand/go-algorand/crypto/secp256k1"
	"github.com/algorand/go-algorand/test/partitiontest"
)

var ecdsaSchemeTests = []struct {
	name string
	// order is the group order, and gx, gy the base point.
	order, gx, gy *big.Int
	publicKey     func(privateKey []byte) ([]byte, error)
	sign          func(privateKey []byte, message Hashable) ([]byte, error)
	verifier      SigSchemeVerifier
	// uncompress converts a compressed public key to the 65-byte SEC 1 form.
	uncompress func(publicKey []byte) []byte
}{
	{
		name:  "secp256k1",
		order: secp256k1.S256().N, gx: secp256k1.S256().Gx, gy: secp256k1.S256().Gy,
		publicKey: Secp256k1PublicKey, sign: SignSecp256k1, verifier: Secp256k1SchemeVerifier{},
		uncompress: func(publicKey []byte) []byte {
			return secp256k1.S256().Marshal(secp256k1.DecompressPubkey(publicKey))
		},
	},
	{
		name:  "secp256r1",
		order: elliptic.P256().Params().N, gx: elliptic.P256().Params().Gx, gy: elliptic.P256().Params().Gy,
		publicKey: Secp256r1PublicKey, sign: SignSecp256r1, verifier: Secp256r1SchemeVerifier{},
		uncompress: func(publicKey []byte) []byte {
			x, y := elliptic.UnmarshalCompressed(elliptic.P256(), publicKey)
			return elliptic.Marshal(elliptic.P256(), x, y)
		},
	},
}

// ecdsaTestKey returns a private key valid on both curves.
func ecdsaTestKey(firstByte byte) []byte {
	key := make([]byte, ECDSAPrivateKeySize)
	key[0] = firstByte
	key[len(key)-1] = 1
	return key
}

// TestSigSchemeVerifierECDSA checks that the ECDSA verifiers accept a lower-S
// signature of SHA-256(HashRep(message)) under a compressed public key, and
// nothing else.
func TestSigSchemeVerifierECDSA(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	msg := TestingHashable{data: []byte("signature scheme verifier round trip")}
	for _, tc := range ecdsaSchemeTests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			sk := ecdsaTestKey(1)
			pk, err := tc.publicKey(sk)
			require.NoError(t, err)
			require.Len(t, pk, ECDSAPublicKeySize)
			sig, err := tc.sign(sk, msg)
			require.NoError(t, err)
			require.Len(t, sig, ECDSASignatureSize)
			require.NoError(t, tc.verifier.Verify(msg, pk, sig))

			// Signing is deterministic.
			again, err := tc.sign(sk, msg)
			require.NoError(t, err)
			require.Equal(t, sig, again)

			invalid := func(msg Hashable, pk, sig []byte) {
				t.Helper()
				require.ErrorIs(t, tc.verifier.Verify(msg, pk, sig), ErrSigInvalid)
			}

			// Wrong sizes.
			invalid(msg, nil, sig)
			invalid(msg, pk[:len(pk)-1], sig)
			invalid(msg, append(slices.Clone(pk), 0), sig)
			invalid(msg, pk, nil)
			invalid(msg, pk, sig[:len(sig)-1])
			invalid(msg, pk, append(slices.Clone(sig), 0))

			// Wrong message or key.
			invalid(TestingHashable{data: []byte("wrong message")}, pk, sig)
			otherPK, err := tc.publicKey(ecdsaTestKey(2))
			require.NoError(t, err)
			invalid(msg, otherPK, sig)

			// Flipped bits at the start, middle and end of the key and the
			// signature. The first one swaps the key for its negation.
			for _, b := range [][]byte{pk, sig} {
				for _, i := range []int{0, len(b) / 2, len(b) - 1} {
					b[i] ^= 1
					invalid(msg, pk, sig)
					b[i] ^= 1
				}
			}

			// The key has to be in compressed form: the uncompressed and hybrid
			// forms of the same point, and other prefixes, are rejected.
			uncompressed := tc.uncompress(pk)
			require.Len(t, uncompressed, 65)
			require.Equal(t, pk[1:], uncompressed[1:33])
			invalid(msg, uncompressed, sig)
			hybrid := slices.Clone(uncompressed)
			hybrid[0] = 6 | uncompressed[64]&1
			invalid(msg, hybrid, sig)
			for _, prefix := range []byte{0, 1, 4, 5, 6, 7} {
				invalid(msg, append([]byte{prefix}, pk[1:]...), sig)
			}

			// (R, N-S) is the same signature in higher-S form.
			r, s := sig[:32], sig[32:]
			high := new(big.Int).Sub(tc.order, new(big.Int).SetBytes(s)).FillBytes(make([]byte, 32))
			require.Positive(t, bytes32Cmp(high, s))
			invalid(msg, pk, slices.Concat(r, high))

			// R and S have to be in [1, N-1].
			zero := make([]byte, 32)
			order := tc.order.FillBytes(make([]byte, 32))
			for _, v := range [][]byte{zero, order} {
				invalid(msg, pk, slices.Concat(v, s))
				invalid(msg, pk, slices.Concat(r, v))
			}

			// The signed bytes are HashRep(message): a signature of the bare
			// data does not verify.
			bare, err := tc.sign(sk, noHashID(msg.data))
			require.NoError(t, err)
			invalid(msg, pk, bare)
			require.NoError(t, tc.verifier.Verify(noHashID(msg.data), pk, bare))
		})
	}
}

func bytes32Cmp(a, b []byte) int {
	return new(big.Int).SetBytes(a).Cmp(new(big.Int).SetBytes(b))
}

// TestECDSAKnownAnswer pins one signature per curve. The expected values come
// from OpenSSL 3.6.3, independently of the libraries used here:
//
//	printf 'TE%s' 'algorand ecdsa known answer' > msg.bin
//	openssl pkeyutl -sign -inkey sk.der -keyform DER -rawin -digest sha256 \
//	    -pkeyopt nonce-type:1 -in msg.bin -out sig.der
//
// where sk.der holds the private key 000102...1f and nonce-type:1 selects
// RFC 6979. Both signatures came out in lower-S form. The public key is the
// end of `openssl ec -pubout -conv_form compressed -outform DER`.
func TestECDSAKnownAnswer(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	want := map[string]struct{ pk, r, s string }{
		"secp256k1": {
			pk: "036d6caac248af96f6afa7f904f550253a0f3ef3f5aa2fe6838a95b216691468e2",
			r:  "131042a8e15eb0973c0a063498e18cf8f3f49e1c8a96b1fef767de67d0fdb97e",
			s:  "210cc005e27e41c4a5efa9fe580ce2f5af911215e2a1cbd9a00f9f8983641df1",
		},
		"secp256r1": {
			pk: "027a593180860c4037c83c12749845c8ee1424dd297fadcb895e358255d2c7d2b2",
			r:  "eee289d1256cf6f2ab92e792d2388ebc34bd113b8c4d0d158c26de33c5a5d0be",
			s:  "60f1847eecd28669d1e235bad4b386cd8faea35c0b0a40d8962ab994016547fc",
		},
	}

	msg := TestingHashable{data: []byte("algorand ecdsa known answer")}
	sk := make([]byte, ECDSAPrivateKeySize)
	for i := range sk {
		sk[i] = byte(i)
	}
	for _, tc := range ecdsaSchemeTests {
		pk, err := tc.publicKey(sk)
		require.NoError(t, err, tc.name)
		sig, err := tc.sign(sk, msg)
		require.NoError(t, err, tc.name)

		require.Equal(t, want[tc.name].pk, hex.EncodeToString(pk), tc.name)
		require.Equal(t, want[tc.name].r+want[tc.name].s, hex.EncodeToString(sig), tc.name)
		require.NoError(t, tc.verifier.Verify(msg, pk, sig), tc.name)
	}
}

// TestECDSAPrivateKeys checks which scalars are private keys, and the public
// key of the scalar 1, which is the curve's base point.
func TestECDSAPrivateKeys(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	msg := TestingHashable{data: []byte("private key range")}
	for _, tc := range ecdsaSchemeTests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			scalar := func(v *big.Int) []byte { return v.FillBytes(make([]byte, ECDSAPrivateKeySize)) }
			one := scalar(big.NewInt(1))
			last := scalar(new(big.Int).Sub(tc.order, big.NewInt(1)))

			pk, err := tc.publicKey(one)
			require.NoError(t, err)
			require.Equal(t, append([]byte{2 | byte(tc.gy.Bit(0))}, scalar(tc.gx)...), pk)

			for _, sk := range [][]byte{one, last} {
				pk, err = tc.publicKey(sk)
				require.NoError(t, err)
				sig, err := tc.sign(sk, msg)
				require.NoError(t, err)
				require.NoError(t, tc.verifier.Verify(msg, pk, sig))
			}

			// Zero, the group order, and scalars of another size are not keys.
			for _, sk := range [][]byte{
				scalar(new(big.Int)), scalar(tc.order), nil, one[1:], append([]byte{0}, one...),
			} {
				_, err = tc.publicKey(sk)
				require.ErrorContains(t, err, tc.name)
				_, err = tc.sign(sk, msg)
				require.ErrorContains(t, err, tc.name)
			}
		})
	}
}

// TestSignECDSALowerS checks that the signers return the lower-S form of the
// RFC 6979 signature. For secp256r1 that signature comes from crypto/ecdsa,
// which returns S above half the order about half of the time.
func TestSignECDSALowerS(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	sk := ecdsaTestKey(3)
	key, err := ecdsa.ParseRawPrivateKey(elliptic.P256(), sk)
	require.NoError(t, err)
	order := elliptic.P256().Params().N
	half := new(big.Int).Rsh(order, 1)

	normalized := 0
	for i := range 32 {
		msg := TestingHashable{data: []byte{byte(i)}}
		for _, tc := range ecdsaSchemeTests {
			pk, err := tc.publicKey(sk)
			require.NoError(t, err)
			sig, err := tc.sign(sk, msg)
			require.NoError(t, err)
			require.NoError(t, tc.verifier.Verify(msg, pk, sig), "%s message %d", tc.name, i)
		}

		digest := sha256.Sum256(HashRep(msg))
		der, err := key.Sign(nil, digest[:], stdcrypto.SHA256)
		require.NoError(t, err)
		var raw struct{ R, S *big.Int }
		_, err = asn1.Unmarshal(der, &raw)
		require.NoError(t, err)
		if raw.S.Cmp(half) > 0 {
			raw.S.Sub(order, raw.S)
			normalized++
		}
		want := slices.Concat(raw.R.FillBytes(make([]byte, 32)), raw.S.FillBytes(make([]byte, 32)))
		sig, err := SignSecp256r1(sk, msg)
		require.NoError(t, err)
		require.Equal(t, want, sig, "message %d", i)
	}
	// Both branches ran.
	require.Positive(t, normalized)
	require.Less(t, normalized, 32)
}
