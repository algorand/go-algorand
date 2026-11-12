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
	"context"
	"crypto/mldsa"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"os/exec"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/algorand/go-algorand/test/partitiontest"
)

var mldsaSchemeTests = []struct {
	name     string
	params   mldsa.Parameters
	verifier SigSchemeVerifier
}{
	{"ml-dsa-44", mldsa.MLDSA44(), MLDSA44SchemeVerifier{}},
	{"ml-dsa-65", mldsa.MLDSA65(), MLDSA65SchemeVerifier{}},
	{"ml-dsa-87", mldsa.MLDSA87(), MLDSA87SchemeVerifier{}},
}

func mldsaTestKey(t *testing.T, params mldsa.Parameters, firstSeedByte byte) *mldsa.PrivateKey {
	t.Helper()
	seed := make([]byte, mldsa.PrivateKeySize)
	seed[0] = firstSeedByte
	sk, err := mldsa.NewPrivateKey(params, seed)
	require.NoError(t, err)
	return sk
}

// TestSigSchemeVerifierMLDSA checks that the ML-DSA verifiers accept a pure
// signature of HashRep(message) with an empty context, and nothing else.
func TestSigSchemeVerifierMLDSA(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	msg := TestingHashable{data: []byte("signature scheme verifier round trip")}
	for _, tc := range mldsaSchemeTests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			sk := mldsaTestKey(t, tc.params, 1)
			pk := sk.PublicKey().Bytes()
			sig, err := sk.SignDeterministic(HashRep(msg), nil)
			require.NoError(t, err)
			require.NoError(t, tc.verifier.Verify(msg, pk, sig))

			// Hedged signatures of the same message differ, and all verify.
			hedged, err := sk.Sign(nil, HashRep(msg), nil)
			require.NoError(t, err)
			require.NotEqual(t, sig, hedged)
			require.NoError(t, tc.verifier.Verify(msg, pk, hedged))

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
			invalid(msg, mldsaTestKey(t, tc.params, 2).PublicKey().Bytes(), sig)

			// Flipped bits at the start, middle and end of the key and the
			// signature.
			for _, b := range [][]byte{pk, sig} {
				for _, i := range []int{0, len(b) / 2, len(b) - 1} {
					b[i] ^= 1
					invalid(msg, pk, sig)
					b[i] ^= 1
				}
			}

			// The signed bytes are HashRep(message) with an empty context: a
			// signature of the bare data, or under a context, does not verify.
			bare, err := sk.SignDeterministic(msg.data, nil)
			require.NoError(t, err)
			invalid(msg, pk, bare)
			withContext, err := sk.SignDeterministic(HashRep(msg), &mldsa.Options{Context: "algorand"})
			require.NoError(t, err)
			invalid(msg, pk, withContext)
		})
	}
}

// TestMLDSAKnownAnswer pins one deterministic signature per parameter set. The
// expected values come from OpenSSL 4.0.3, independently of crypto/mldsa:
//
//	printf 'TE%s' 'algorand ml-dsa known answer' > msg.bin
//	openssl genpkey -algorithm ML-DSA-44 -pkeyopt hexseed:000102...1f -out sk.pem
//	openssl pkeyutl -sign -inkey sk.pem -rawin -in msg.bin -pkeyopt deterministic:1 -out sig.bin
//
// with the public key taken from the end of `openssl pkey -pubout -outform DER`.
func TestMLDSAKnownAnswer(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	sha := func(b []byte) string {
		h := sha256.Sum256(b)
		return hex.EncodeToString(h[:])
	}
	want := map[string]struct{ pk, sig string }{
		"ml-dsa-44": {
			pk:  "9f107644c1084526af3bc8098680b05499a2325a644e388fb4f970e058d19d46",
			sig: "dba3e63cdbb8b4cfa6394678b35dd8d736245ae2f26fdb6cdf7f371df94eacff",
		},
		"ml-dsa-65": {
			pk:  "d666806e11cee19a7c989f7445f90dd419cf4d2d51db8c0fdb4c0f0a542238c9",
			sig: "d8ea13edcd9ef0106b242c735c92b0e379279d5cf39d4ef3eeec4a5155a8f1b7",
		},
		"ml-dsa-87": {
			pk:  "91dc389cfaa01470b7f66eee45a4ae9026d154817c754dfe22298b3fa241ffcd",
			sig: "06fcd3ed2f8a956fdfe50715fde2fb4b0763e2cf88bcccb811700ee8bdecb08b",
		},
	}

	msg := TestingHashable{data: []byte("algorand ml-dsa known answer")}
	seed := make([]byte, mldsa.PrivateKeySize)
	for i := range seed {
		seed[i] = byte(i)
	}
	for _, tc := range mldsaSchemeTests {
		sk, err := mldsa.NewPrivateKey(tc.params, seed)
		require.NoError(t, err)
		pk := sk.PublicKey().Bytes()
		sig, err := sk.SignDeterministic(HashRep(msg), nil)
		require.NoError(t, err)

		require.Equal(t, want[tc.name].pk, sha(pk), tc.name)
		require.Equal(t, want[tc.name].sig, sha(sig), tc.name)
		require.NoError(t, tc.verifier.Verify(msg, pk, sig), tc.name)
	}
}

// TestMLDSAFIPS140v1 checks that a binary built against the FIPS 140-3 Go
// Cryptographic Module v1.0.0, which has no ML-DSA, refuses to start instead of
// rejecting every ML-DSA signature.
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
	var exitErr *exec.ExitError
	require.ErrorAs(t, err, &exitErr, out)
	require.Contains(t, out, "crypto: mldsa: unavailable")
	require.NotContains(t, out, "started")
}

// BenchmarkSigSchemeVerify measures one verification of a valid signature of
// a 300-byte message, of the same signature checked against another 300-byte
// message (which ML-DSA rejects only after all of its work), and of a valid
// signature of a 4096-byte message.
func BenchmarkSigSchemeVerify(b *testing.B) {
	type scheme struct {
		name     string
		verifier SigSchemeVerifier
		sign     func(Hashable) (pk, sig []byte)
	}
	var schemes []scheme

	ed := GenerateSignatureSecrets(Seed{1})
	schemes = append(schemes, scheme{"ed25519", Ed25519SchemeVerifier{}, func(m Hashable) ([]byte, []byte) {
		sig := ed.Sign(m)
		return ed.SignatureVerifier[:], sig[:]
	}})
	f1, err := GenerateFalcon1024Signer(FalconSeed{1})
	require.NoError(b, err)
	schemes = append(schemes, scheme{"falcon-1024", Falcon1024SchemeVerifier{}, func(m Hashable) ([]byte, []byte) {
		sig, err := f1.Sign(m)
		require.NoError(b, err)
		return f1.PublicKey[:], sig
	}})
	f5, err := GenerateFalcon512Signer(FalconSeed{1})
	require.NoError(b, err)
	schemes = append(schemes, scheme{"falcon-512", Falcon512SchemeVerifier{}, func(m Hashable) ([]byte, []byte) {
		sig, err := f5.Sign(m)
		require.NoError(b, err)
		return f5.PublicKey[:], sig
	}})
	for _, tc := range mldsaSchemeTests {
		sk, err := mldsa.NewPrivateKey(tc.params, make([]byte, mldsa.PrivateKeySize))
		require.NoError(b, err)
		schemes = append(schemes, scheme{tc.name, tc.verifier, func(m Hashable) ([]byte, []byte) {
			sig, err := sk.SignDeterministic(HashRep(m), nil)
			require.NoError(b, err)
			return sk.PublicKey().Bytes(), sig
		}})
	}

	short := TestingHashable{data: make([]byte, 300)}
	long := TestingHashable{data: make([]byte, 4096)}
	wrong := TestingHashable{data: make([]byte, 300)}
	wrong.data[0] = 1
	for _, s := range schemes {
		pk, sig := s.sign(short)
		pkLong, sigLong := s.sign(long)
		b.Run(s.name+"/valid", func(b *testing.B) {
			for b.Loop() {
				if err := s.verifier.Verify(short, pk, sig); err != nil {
					b.Fatal(err)
				}
			}
		})
		b.Run(s.name+"/invalid", func(b *testing.B) {
			for b.Loop() {
				if err := s.verifier.Verify(wrong, pk, sig); err == nil {
					b.Fatal("verified")
				}
			}
		})
		b.Run(s.name+"/4096B", func(b *testing.B) {
			for b.Loop() {
				if err := s.verifier.Verify(long, pkLong, sigLong); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}
