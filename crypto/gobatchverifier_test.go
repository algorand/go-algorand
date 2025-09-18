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

package crypto

import (
	"bufio"
	"compress/gzip"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/rand"
	"os"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/algorand/go-algorand/protocol"
	"github.com/algorand/go-algorand/test/partitiontest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ensure internal ed25519 types match the expected []byte lengths used by ed25519consensus package
func TestEd25519ConsensusBatchVerifierTypes(t *testing.T) {
	partitiontest.PartitionTest(t)

	require.Len(t, ed25519PublicKey{}, ed25519.PublicKeySize)
	require.Len(t, ed25519Signature{}, ed25519.SignatureSize)
}

// Test vectors for 12 edge cases listed in Appendix C of "Taming the many EdDSAs" https://eprint.iacr.org/2020/1244
// These are also checked in test_edge_cases in go-algorand/crypto/libsodium-fork/test/default/batch.c
func TestBatchVerifierTamingEdDSAsEdgeCases(t *testing.T) {
	partitiontest.PartitionTest(t)

	hexVecs := make([]batchTestCaseHex, len(tamingEdDSAsTestVectors))
	expectedFail := make([]bool, len(tamingEdDSAsTestVectors))
	for i, tc := range tamingEdDSAsTestVectors {
		hexVecs[i] = batchTestCaseHex{pkHex: tc.pk, sigHex: tc.sig, msgHex: tc.msg}
		expectedFail[i] = tc.expectedFail
	}
	runBatchVerifierImpls(t, func(t *testing.T, makeBV func(int) BatchVerifier) {
		testBatchVectors(t, makeBV, decodeHexTestCases(t, hexVecs), expectedFail)
	})
}

// Test vectors from "It's 255:19AM" blog post about ZIP-215 development, also used to create the
// 14x14 visualizations of different criteria across implementations in Henry de Valence's blog post
// "It's 255:19AM..." https://hdevalence.ca/blog/2020-10-04-its-25519am/
func TestBatchVerifierEd25519ConsensusTestData(t *testing.T) {
	partitiontest.PartitionTest(t)

	const msgHex = "5a63617368" // used for all signatures in this test
	hexVecs := make([]batchTestCaseHex, len(ed25519consensusCases))
	for i, tc := range ed25519consensusCases {
		hexVecs[i] = batchTestCaseHex{pkHex: tc.pk, sigHex: tc.sig, msgHex: msgHex}
	}
	// All of these test vectors should fail, matching our strict criteria
	expectedFail := make([]bool, len(hexVecs))
	for i := range expectedFail {
		expectedFail[i] = true
	}
	runBatchVerifierImpls(t, func(t *testing.T, makeBV func(int) BatchVerifier) {
		testBatchVectors(t, makeBV, decodeHexTestCases(t, hexVecs), expectedFail)
	})
}

// Test vectors from unit tests for our libsodium- and ed25519-donna-based batch verification implementation
// introduced in PR #3031.
func TestBatchVerifierLibsodiumTestData(t *testing.T) {
	partitiontest.PartitionTest(t)

	// read vectors hard-coded in test source file
	const testVectorFile = "./libsodium-fork/test/default/batch.c"
	const testVectorSize = 1025
	f, err := os.Open(testVectorFile)
	if err != nil {
		panic(err)
	}
	defer f.Close()
	scanner := bufio.NewScanner(f)

	type testCase struct {
		seed, pk, sig []byte
		m             string
	}
	var testCases []testCase
	// each line is {{sk},{pk},{sig},"m"} where sk, pk, sig are comma-delimited lists of hex-encoded bytes
	re := regexp.MustCompile(`\{\{(.*?)\},\{(.*?)\},\{(.*?)\},(.*?)\}`)
	for i := 0; scanner.Scan(); i++ {
		var tc testCase
		line := scanner.Text()
		matches := re.FindStringSubmatch(line)
		if matches == nil || len(matches) != 5 {
			continue
		}
		tc.seed = decodeCByteArray(matches[1], ed25519.SeedSize)
		tc.pk = decodeCByteArray(matches[2], ed25519.PublicKeySize)
		tc.sig = decodeCByteArray(matches[3], ed25519.SignatureSize)
		tc.m, err = strconv.Unquote(matches[4])
		require.NoError(t, err)
		testCases = append(testCases, tc)
	}
	t.Logf("loaded %d test vectors from %s", len(testCases), testVectorFile)
	require.Len(t, testCases, testVectorSize, "not enough test vectors found")

	// check test data with libsodium-based ed25519Verify
	for _, tc := range testCases {
		require.True(t, ed25519Verify(ed25519PublicKey(tc.pk), []byte(tc.m), ed25519Signature(tc.sig)))
	}

	// assert signing with test vector sk produces sig
	for _, tc := range testCases {
		pk, sk := ed25519GenerateKeySeed(ed25519Seed(tc.seed))
		require.Equal(t, tc.pk, []byte(pk[:]))
		sig := ed25519Sign(sk, []byte(tc.m))
		require.Equal(t, tc.sig, []byte(sig[:]))
	}

	// test different BatchVerifier implementations and batch sizes
	testVectors := make([]batchTestCase, len(testCases))
	for i, tc := range testCases {
		testVectors[i] = batchTestCase{pk: tc.pk, sig: tc.sig, msg: []byte(tc.m)}
	}
	expectedFail := make([]bool, len(testVectors)) // all should pass
	runBatchVerifierImpls(t, func(t *testing.T, makeBV func(int) BatchVerifier) {
		testBatchVectors(t, makeBV, testVectors, expectedFail)
	})
}

// based on TestEd25519Vectors from go/src/crypto/ed25519/ed25519vectors_test.go
// which uses test vectors from filippo.io/mostly-harmless/ed25519vectors
func TestBatchVerifierFilippoVectors(t *testing.T) {
	var vectors []struct {
		A, R, S, M string
		Flags      []string
	}
	f, err := os.Open("./testdata/ed25519vectors.json.gz")
	require.NoError(t, err)
	defer f.Close()
	rd, err := gzip.NewReader(f)
	require.NoError(t, err)
	defer rd.Close()
	err = json.NewDecoder(rd).Decode(&vectors)
	require.NoError(t, err)

	expectedFail := make([]bool, len(vectors))
	hexVecs := make([]batchTestCaseHex, len(vectors))
	for i, v := range vectors {
		for _, f := range v.Flags {
			switch f {
			case "LowOrderA": // reject small-order A
				expectedFail[i] = true
			case "NonCanonicalA", "NonCanonicalR": // reject non-canonical A or R
				expectedFail[i] = true
			case "LowOrderR": // small-order R allowed
			case "LowOrderComponentR", "LowOrderComponentA": // torsion component allowed
			case "LowOrderResidue": // cofactorless batch verification
			default:
				require.Fail(t, "unknown flag %q in test vector %d", f, i)
			}
		}
		hexVecs[i] = batchTestCaseHex{pkHex: v.A, sigHex: v.R + v.S, msgHex: hex.EncodeToString([]byte(v.M))}
	}
	runBatchVerifierImpls(t, func(t *testing.T, makeBV func(int) BatchVerifier) {
		testBatchVectors(t, makeBV, decodeHexTestCases(t, hexVecs), expectedFail)
	})

	// test isCanonicalPoint and hasSmallOrder against A and R
	t.Run("ARchecks", func(t *testing.T) {
		for _, v := range vectors {
			A, err := hex.DecodeString(v.A)
			require.NoError(t, err)
			require.Equal(t, !slices.Contains(v.Flags, "NonCanonicalA"), isCanonicalPoint([32]byte(A)))
			require.Equal(t, slices.Contains(v.Flags, "LowOrderA"), hasSmallOrder([32]byte(A)))

			R, err := hex.DecodeString(v.R)
			require.NoError(t, err)
			require.Equal(t, !slices.Contains(v.Flags, "NonCanonicalR"), isCanonicalPoint([32]byte(R)))
			require.Equal(t, slices.Contains(v.Flags, "LowOrderR"), hasSmallOrder([32]byte(R)))
		}
	})

}

// testBatchVectors tests a batch of signatures with expected pass/fail results using various batch sizes
func testBatchVectors(t *testing.T, makeBV func(int) BatchVerifier, testVectors []batchTestCase, expectedFail []bool) {
	require.Len(t, expectedFail, len(testVectors))

	// run a single batch of test vectors and compare to expected failures
	runBatch := func(t *testing.T, vecs []batchTestCase, expFail []bool) {
		bv := makeBV(len(vecs))
		for _, tv := range vecs {
			bv.EnqueueSignature(SignatureVerifier(tv.pk), noHashID(tv.msg), Signature(tv.sig))
		}
		failed, err := bv.VerifyWithFeedback()
		if slices.Contains(expFail, true) { // some failures expected
			require.Error(t, err)
			require.NotNil(t, failed)
			require.Len(t, failed, len(vecs))
			for i := range expFail {
				assert.Equal(t, expFail[i], failed[i])
			}
		} else { // no failures expected
			require.NoError(t, err)
			require.Nil(t, failed)
		}
	}

	// run all the test vectors in a single batch
	t.Run("all", func(t *testing.T) { runBatch(t, testVectors, expectedFail) })

	// split into multiple batches of different sizes, optionally shuffled
	runBatchSizes := func(shuffle bool, vecs []batchTestCase, expFail []bool) {
		if shuffle {
			vecs, expFail = slices.Clone(vecs), slices.Clone(expFail)
			rand.Shuffle(len(vecs), func(i, j int) {
				vecs[i], vecs[j], expFail[i], expFail[j] = vecs[j], vecs[i], expFail[j], expFail[i]
			})
		}

		for _, batchSize := range []int{1, 2, 4, 8, 16, 32, 64, 100, 128, 256, 512, 1024} {
			if batchSize > len(vecs) {
				continue
			}
			t.Run(fmt.Sprintf("batchSize=%d", batchSize), func(t *testing.T) {
				vectorBatches := splitBatches(vecs, batchSize)
				failBatches := splitBatches(expFail, batchSize)
				require.Equal(t, len(vectorBatches), len(failBatches))
				//t.Logf("Testing with batch size %d: %d total signatures in %d batches", batchSize, n, len(vectorBatches))
				for i, batch := range vectorBatches {
					batchExpectedFail := failBatches[i]
					//t.Logf("Batch %d/%d: signatures [%d-%d), size=%d", i+1, len(vectorBatches), i*batchSize, i*batchSize+len(batch), len(batch))
					runBatch(t, batch, batchExpectedFail)
				}
			})
		}
	}

	t.Run("unshuffled", func(t *testing.T) { runBatchSizes(false, testVectors, expectedFail) })
	t.Run("shuffled", func(t *testing.T) { runBatchSizes(true, testVectors, expectedFail) })
}

// splitBatches splits items into batches of the specified size
func splitBatches[T any](items []T, batchSize int) [][]T {
	if batchSize <= 0 {
		return nil
	}
	numBatches := len(items) / batchSize
	if len(items)%batchSize != 0 {
		numBatches++
	}
	batches := make([][]T, numBatches)

	for i, item := range items {
		batchIdx := i / batchSize
		batches[batchIdx] = append(batches[batchIdx], item)
	}

	return batches
}

// decodeCByteArray decodes a string like "0x27,0x81," into a byte array of length n
func decodeCByteArray(hexList string, n int) []byte {
	bytes := make([]byte, n)
	words := strings.Split(hexList, ",")
	// remove trailing empty string
	if words[len(words)-1] == "" {
		words = words[:len(words)-1]
	} else {
		panic("missing trailing comma")
	}
	if len(words) != n {
		panic("wrong number of words")
	}
	for i, word := range words {
		_, err := fmt.Sscanf(word, "0x%02x", &bytes[i])
		if err != nil {
			panic(err)
		}
	}
	return bytes
}

type batchTestCaseHex struct{ pkHex, sigHex, msgHex string }
type batchTestCase struct{ pk, sig, msg []byte }

// decodeHexTestCases converts hex-encoded test cases to byte arrays
func decodeHexTestCases(t *testing.T, hexCases []batchTestCaseHex) []batchTestCase {
	cases := make([]batchTestCase, len(hexCases))
	for i, hc := range hexCases {
		pk, err := hex.DecodeString(hc.pkHex)
		require.NoError(t, err)
		require.Len(t, pk, ed25519.PublicKeySize)

		sig, err := hex.DecodeString(hc.sigHex)
		require.NoError(t, err)
		require.Len(t, sig, ed25519.SignatureSize)

		msg, err := hex.DecodeString(hc.msgHex)
		require.NoError(t, err)

		cases[i] = batchTestCase{pk: pk, sig: sig, msg: msg}
	}
	return cases
}

// noHashID implements Hashable but returns an empty protocol.HashID for use
// with the test vectors, which should not be prefixed
type noHashID []byte

func (n noHashID) ToBeHashed() (protocol.HashID, []byte) { return "", n }

// Test vectors from Appendix C of "Taming the many EdDSAs" https://eprint.iacr.org/2020/1244
var tamingEdDSAsTestVectors = []struct {
	desc, msg, pk, sig string
	expectedFail       bool // Algorand-specific criteria
}{
	{"S = 0, small-order A, small-order R",
		"8c93255d71dcab10e8f379c26200f3c7bd5f09d9bc3068d3ef4edeb4853022b6",
		"c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa",
		"c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a0000000000000000000000000000000000000000000000000000000000000000",
		true},
	{"0 < S < L, small-order A, mixed-order R",
		"9bd9f44f4dcc75bd531b56b2cd280b0bb38fc1cd6d1230e14861d861de092e79",
		"c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa",
		"f7badec5b8abeaf699583992219b7b223f1df3fbbea919844e3f7c554a43dd43a5bb704786be79fc476f91d3f3f89b03984d8068dcf1bb7dfc6637b45450ac04",
		true},
	{"0 < S < L, mixed-order A, small-order R",
		"aebf3f2601a0c8c5d39cc7d8911642f740b78168218da8471772b35f9d35b9ab",
		"f7badec5b8abeaf699583992219b7b223f1df3fbbea919844e3f7c554a43dd43",
		"c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa8c4bd45aecaca5b24fb97bc10ac27ac8751a7dfe1baff8b953ec9f5833ca260e",
		false},
	{"0 < S < L, mixed-order A, mixed-order R",
		"9bd9f44f4dcc75bd531b56b2cd280b0bb38fc1cd6d1230e14861d861de092e79",
		"cdb267ce40c5cd45306fa5d2f29731459387dbf9eb933b7bd5aed9a765b88d4d",
		"9046a64750444938de19f227bb80485e92b83fdb4b6506c160484c016cc1852f87909e14428a7a1d62e9f22f3d3ad7802db02eb2e688b6c52fcd6648a98bd009",
		false},
	{"0 < S < L, mixed-order A, mixed-order R, SB != R + hA",
		"e47d62c63f830dc7a6851a0b1f33ae4bb2f507fb6cffec4011eaccd55b53f56c",
		"cdb267ce40c5cd45306fa5d2f29731459387dbf9eb933b7bd5aed9a765b88d4d",
		"160a1cb0dc9c0258cd0a7d23e94d8fa878bcb1925f2c64246b2dee1796bed5125ec6bc982a269b723e0668e540911a9a6a58921d6925e434ab10aa7940551a09",
		false},
	{`0 < S < L, mixed-order A, L-order R, SB != R + hA ("#5 fails any cofactored verification that pre-reduces scalar 8h")`,
		"e47d62c63f830dc7a6851a0b1f33ae4bb2f507fb6cffec4011eaccd55b53f56c",
		"cdb267ce40c5cd45306fa5d2f29731459387dbf9eb933b7bd5aed9a765b88d4d",
		"21122a84e0b5fca4052f5b1235c80a537878b38f3142356b2c2384ebad4668b7e40bc836dac0f71076f9abe3a53f9c03c1ceeeddb658d0030494ace586687405",
		false},
	{"S > L, L-order A, L-order R",
		"85e241a07d148b41e47d62c63f830dc7a6851a0b1f33ae4bb2f507fb6cffec40",
		"442aad9f089ad9e14647b1ef9099a1ff4798d78589e66f28eca69c11f582a623",
		"e96f66be976d82e60150baecff9906684aebb1ef181f67a7189ac78ea23b6c0e547f7690a0e2ddcd04d87dbc3490dc19b3b3052f7ff0538cb68afb369ba3a514",
		true},
	{`S >> L, L-order A, L-order R ("#7 fails bitwise tests that S > L")`,
		"85e241a07d148b41e47d62c63f830dc7a6851a0b1f33ae4bb2f507fb6cffec40",
		"442aad9f089ad9e14647b1ef9099a1ff4798d78589e66f28eca69c11f582a623",
		"8ce5b96c8f26d0ab6c47958c9e68b937104cd36e13c33566acd2fe8d38aa19427e71f98a4734e74f2f13f06f97c20d58cc3f54b8bd0d272f42b695dd7e89a8c2",
		true},
	{`0 < S < L, mixed-order A, small-order R ("#8-9 have non-canonical R; implementations that reduce R before hashing will accept #8 and reject #9, while those that do not will reject #8 and accept #9")`,
		"9bedc267423725d473888631ebf45988bad3db83851ee85c85e241a07d148b41",
		"f7badec5b8abeaf699583992219b7b223f1df3fbbea919844e3f7c554a43dd43",
		"ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff03be9678ac102edcd92b0210bb34d7428d12ffc5df5f37e359941266a4e35f0f",
		true},
	{`0 < S < L, mixed-order A, small-order R ("#8-9 have non-canonical R; implementations that reduce R before hashing will accept #8 and reject #9, while those that do not will reject #8 and accept #9")`,
		"9bedc267423725d473888631ebf45988bad3db83851ee85c85e241a07d148b41",
		"f7badec5b8abeaf699583992219b7b223f1df3fbbea919844e3f7c554a43dd43",
		"ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffca8c5b64cd208982aa38d4936621a4775aa233aa0505711d8fdcfdaa943d4908",
		true},
	{`0 < S < L, small-order A, mixed-order R ("#10-11 have a non-canonical A; implementations that reduce A before hashing will accept #10 and reject #11, while those that do not will reject #10 and accept #11")`,
		"e96b7021eb39c1a163b6da4e3093dcd3f21387da4cc4572be588fafae23c155b",
		"ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
		"a9d55260f765261eb9b84e106f665e00b867287a761990d7135963ee0a7d59dca5bb704786be79fc476f91d3f3f89b03984d8068dcf1bb7dfc6637b45450ac04",
		true},
	{`0 < S < L, small-order A, mixed-order R ("#10-11 have a non-canonical A; implementations that reduce A before hashing will accept #10 and reject #11, while those that do not will reject #10 and accept #11")`,
		"39a591f5321bbe07fd5a23dc2f39d025d74526615746727ceefd6e82ae65c06f",
		"ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
		"a9d55260f765261eb9b84e106f665e00b867287a761990d7135963ee0a7d59dca5bb704786be79fc476f91d3f3f89b03984d8068dcf1bb7dfc6637b45450ac04",
		true},
}

// "It's 255:19AM" blog post test vectors, from the ed25519consensus package
var ed25519consensusCases = [196]struct{ pk, sig string }{
	{
		"0100000000000000000000000000000000000000000000000000000000000000",
		"01000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
	},
	{
		"0100000000000000000000000000000000000000000000000000000000000000",
		"c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a0000000000000000000000000000000000000000000000000000000000000000",
	},
	{
		"0100000000000000000000000000000000000000000000000000000000000000",
		"00000000000000000000000000000000000000000000000000000000000000800000000000000000000000000000000000000000000000000000000000000000",
	},
	{
		"0100000000000000000000000000000000000000000000000000000000000000",
		"26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc050000000000000000000000000000000000000000000000000000000000000000",
	},
	{
		"0100000000000000000000000000000000000000000000000000000000000000",
		"ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f0000000000000000000000000000000000000000000000000000000000000000",
	},
	{
		"0100000000000000000000000000000000000000000000000000000000000000",
		"26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc850000000000000000000000000000000000000000000000000000000000000000",
	},
	{
		"0100000000000000000000000000000000000000000000000000000000000000",
		"00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
	},
	{
		"0100000000000000000000000000000000000000000000000000000000000000",
		"c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa0000000000000000000000000000000000000000000000000000000000000000",
	},
	{
		"0100000000000000000000000000000000000000000000000000000000000000",
		"01000000000000000000000000000000000000000000000000000000000000800000000000000000000000000000000000000000000000000000000000000000",
	},
	{
		"0100000000000000000000000000000000000000000000000000000000000000",
		"ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff0000000000000000000000000000000000000000000000000000000000000000",
	},
	{
		"0100000000000000000000000000000000000000000000000000000000000000",
		"edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f0000000000000000000000000000000000000000000000000000000000000000",
	},
	{
		"0100000000000000000000000000000000000000000000000000000000000000",
		"edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff0000000000000000000000000000000000000000000000000000000000000000",
	},
	{
		"0100000000000000000000000000000000000000000000000000000000000000",
		"eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f0000000000000000000000000000000000000000000000000000000000000000",
	},
	{
		"0100000000000000000000000000000000000000000000000000000000000000",
		"eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff0000000000000000000000000000000000000000000000000000000000000000",
	},
	{
		"c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a",
		"01000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
	},
	{
		"c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a",
		"c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a0000000000000000000000000000000000000000000000000000000000000000",
	},
	{
		"c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a",
		"00000000000000000000000000000000000000000000000000000000000000800000000000000000000000000000000000000000000000000000000000000000",
	},
	{
		"c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a",
		"26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc050000000000000000000000000000000000000000000000000000000000000000",
	},
	{
		"c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a",
		"ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f0000000000000000000000000000000000000000000000000000000000000000",
	},
	{
		"c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a",
		"26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc850000000000000000000000000000000000000000000000000000000000000000",
	},
	{
		"c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a",
		"00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
	},
	{
		"c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a",
		"c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa0000000000000000000000000000000000000000000000000000000000000000",
	},
	{
		"c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a",
		"01000000000000000000000000000000000000000000000000000000000000800000000000000000000000000000000000000000000000000000000000000000",
	},
	{
		"c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a",
		"ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff0000000000000000000000000000000000000000000000000000000000000000",
	},
	{
		"c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a",
		"edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f0000000000000000000000000000000000000000000000000000000000000000",
	},
	{
		"c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a",
		"edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff0000000000000000000000000000000000000000000000000000000000000000",
	},
	{
		"c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a",
		"eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f0000000000000000000000000000000000000000000000000000000000000000",
	},
	{
		"c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a",
		"eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff0000000000000000000000000000000000000000000000000000000000000000",
	},
	{
		"0000000000000000000000000000000000000000000000000000000000000080",
		"01000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
	},
	{
		"0000000000000000000000000000000000000000000000000000000000000080",
		"c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a0000000000000000000000000000000000000000000000000000000000000000",
	},
	{
		"0000000000000000000000000000000000000000000000000000000000000080",
		"00000000000000000000000000000000000000000000000000000000000000800000000000000000000000000000000000000000000000000000000000000000",
	},
	{
		"0000000000000000000000000000000000000000000000000000000000000080",
		"26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc050000000000000000000000000000000000000000000000000000000000000000",
	},
	{
		"0000000000000000000000000000000000000000000000000000000000000080",
		"ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f0000000000000000000000000000000000000000000000000000000000000000",
	},
	{
		"0000000000000000000000000000000000000000000000000000000000000080",
		"26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc850000000000000000000000000000000000000000000000000000000000000000",
	},
	{
		"0000000000000000000000000000000000000000000000000000000000000080",
		"00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
	},
	{
		"0000000000000000000000000000000000000000000000000000000000000080",
		"c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa0000000000000000000000000000000000000000000000000000000000000000",
	},
	{
		"0000000000000000000000000000000000000000000000000000000000000080",
		"01000000000000000000000000000000000000000000000000000000000000800000000000000000000000000000000000000000000000000000000000000000",
	},
	{
		"0000000000000000000000000000000000000000000000000000000000000080",
		"ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff0000000000000000000000000000000000000000000000000000000000000000",
	},
	{
		"0000000000000000000000000000000000000000000000000000000000000080",
		"edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f0000000000000000000000000000000000000000000000000000000000000000",
	},
	{
		"0000000000000000000000000000000000000000000000000000000000000080",
		"edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff0000000000000000000000000000000000000000000000000000000000000000",
	},
	{
		"0000000000000000000000000000000000000000000000000000000000000080",
		"eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f0000000000000000000000000000000000000000000000000000000000000000",
	},
	{
		"0000000000000000000000000000000000000000000000000000000000000080",
		"eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff0000000000000000000000000000000000000000000000000000000000000000",
	},
	{
		"26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05",
		"01000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
	},
	{
		"26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05",
		"c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a0000000000000000000000000000000000000000000000000000000000000000",
	},
	{
		"26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05",
		"00000000000000000000000000000000000000000000000000000000000000800000000000000000000000000000000000000000000000000000000000000000",
	},
	{
		"26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05",
		"26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc050000000000000000000000000000000000000000000000000000000000000000",
	},
	{
		"26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05",
		"ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f0000000000000000000000000000000000000000000000000000000000000000",
	},
	{
		"26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05",
		"26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc850000000000000000000000000000000000000000000000000000000000000000",
	},
	{
		"26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05",
		"00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
	},
	{
		"26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05",
		"c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa0000000000000000000000000000000000000000000000000000000000000000",
	},
	{
		"26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05",
		"01000000000000000000000000000000000000000000000000000000000000800000000000000000000000000000000000000000000000000000000000000000",
	},
	{
		"26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05",
		"ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff0000000000000000000000000000000000000000000000000000000000000000",
	},
	{
		"26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05",
		"edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f0000000000000000000000000000000000000000000000000000000000000000",
	},
	{
		"26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05",
		"edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff0000000000000000000000000000000000000000000000000000000000000000",
	},
	{
		"26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05",
		"eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f0000000000000000000000000000000000000000000000000000000000000000",
	},
	{
		"26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05",
		"eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff0000000000000000000000000000000000000000000000000000000000000000",
	},
	{
		"ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
		"01000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
	},
	{
		"ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
		"c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a0000000000000000000000000000000000000000000000000000000000000000",
	},
	{
		"ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
		"00000000000000000000000000000000000000000000000000000000000000800000000000000000000000000000000000000000000000000000000000000000",
	},
	{
		"ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
		"26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc050000000000000000000000000000000000000000000000000000000000000000",
	},
	{
		"ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
		"ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f0000000000000000000000000000000000000000000000000000000000000000",
	},
	{
		"ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
		"26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc850000000000000000000000000000000000000000000000000000000000000000",
	},
	{
		"ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
		"00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
	},
	{
		"ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
		"c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa0000000000000000000000000000000000000000000000000000000000000000",
	},
	{
		"ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
		"01000000000000000000000000000000000000000000000000000000000000800000000000000000000000000000000000000000000000000000000000000000",
	},
	{
		"ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
		"ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff0000000000000000000000000000000000000000000000000000000000000000",
	},
	{
		"ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
		"edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f0000000000000000000000000000000000000000000000000000000000000000",
	},
	{
		"ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
		"edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff0000000000000000000000000000000000000000000000000000000000000000",
	},
	{
		"ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
		"eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f0000000000000000000000000000000000000000000000000000000000000000",
	},
	{
		"ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
		"eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff0000000000000000000000000000000000000000000000000000000000000000",
	},
	{
		"26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc85",
		"01000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
	},
	{
		"26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc85",
		"c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a0000000000000000000000000000000000000000000000000000000000000000",
	},
	{
		"26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc85",
		"00000000000000000000000000000000000000000000000000000000000000800000000000000000000000000000000000000000000000000000000000000000",
	},
	{
		"26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc85",
		"26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc050000000000000000000000000000000000000000000000000000000000000000",
	},
	{
		"26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc85",
		"ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f0000000000000000000000000000000000000000000000000000000000000000",
	},
	{
		"26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc85",
		"26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc850000000000000000000000000000000000000000000000000000000000000000",
	},
	{
		"26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc85",
		"00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
	},
	{
		"26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc85",
		"c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa0000000000000000000000000000000000000000000000000000000000000000",
	},
	{
		"26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc85",
		"01000000000000000000000000000000000000000000000000000000000000800000000000000000000000000000000000000000000000000000000000000000",
	},
	{
		"26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc85",
		"ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff0000000000000000000000000000000000000000000000000000000000000000",
	},
	{
		"26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc85",
		"edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f0000000000000000000000000000000000000000000000000000000000000000",
	},
	{
		"26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc85",
		"edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff0000000000000000000000000000000000000000000000000000000000000000",
	},
	{
		"26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc85",
		"eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f0000000000000000000000000000000000000000000000000000000000000000",
	},
	{
		"26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc85",
		"eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff0000000000000000000000000000000000000000000000000000000000000000",
	},
	{
		"0000000000000000000000000000000000000000000000000000000000000000",
		"01000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
	},
	{
		"0000000000000000000000000000000000000000000000000000000000000000",
		"c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a0000000000000000000000000000000000000000000000000000000000000000",
	},
	{
		"0000000000000000000000000000000000000000000000000000000000000000",
		"00000000000000000000000000000000000000000000000000000000000000800000000000000000000000000000000000000000000000000000000000000000",
	},
	{
		"0000000000000000000000000000000000000000000000000000000000000000",
		"26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc050000000000000000000000000000000000000000000000000000000000000000",
	},
	{
		"0000000000000000000000000000000000000000000000000000000000000000",
		"ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f0000000000000000000000000000000000000000000000000000000000000000",
	},
	{
		"0000000000000000000000000000000000000000000000000000000000000000",
		"26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc850000000000000000000000000000000000000000000000000000000000000000",
	},
	{
		"0000000000000000000000000000000000000000000000000000000000000000",
		"00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
	},
	{
		"0000000000000000000000000000000000000000000000000000000000000000",
		"c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa0000000000000000000000000000000000000000000000000000000000000000",
	},
	{
		"0000000000000000000000000000000000000000000000000000000000000000",
		"01000000000000000000000000000000000000000000000000000000000000800000000000000000000000000000000000000000000000000000000000000000",
	},
	{
		"0000000000000000000000000000000000000000000000000000000000000000",
		"ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff0000000000000000000000000000000000000000000000000000000000000000",
	},
	{
		"0000000000000000000000000000000000000000000000000000000000000000",
		"edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f0000000000000000000000000000000000000000000000000000000000000000",
	},
	{
		"0000000000000000000000000000000000000000000000000000000000000000",
		"edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff0000000000000000000000000000000000000000000000000000000000000000",
	},
	{
		"0000000000000000000000000000000000000000000000000000000000000000",
		"eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f0000000000000000000000000000000000000000000000000000000000000000",
	},
	{
		"0000000000000000000000000000000000000000000000000000000000000000",
		"eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff0000000000000000000000000000000000000000000000000000000000000000",
	},
	{
		"c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa",
		"01000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
	},
	{
		"c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa",
		"c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a0000000000000000000000000000000000000000000000000000000000000000",
	},
	{
		"c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa",
		"00000000000000000000000000000000000000000000000000000000000000800000000000000000000000000000000000000000000000000000000000000000",
	},
	{
		"c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa",
		"26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc050000000000000000000000000000000000000000000000000000000000000000",
	},
	{
		"c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa",
		"ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f0000000000000000000000000000000000000000000000000000000000000000",
	},
	{
		"c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa",
		"26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc850000000000000000000000000000000000000000000000000000000000000000",
	},
	{
		"c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa",
		"00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
	},
	{
		"c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa",
		"c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa0000000000000000000000000000000000000000000000000000000000000000",
	},
	{
		"c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa",
		"01000000000000000000000000000000000000000000000000000000000000800000000000000000000000000000000000000000000000000000000000000000",
	},
	{
		"c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa",
		"ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff0000000000000000000000000000000000000000000000000000000000000000",
	},
	{
		"c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa",
		"edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f0000000000000000000000000000000000000000000000000000000000000000",
	},
	{
		"c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa",
		"edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff0000000000000000000000000000000000000000000000000000000000000000",
	},
	{
		"c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa",
		"eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f0000000000000000000000000000000000000000000000000000000000000000",
	},
	{
		"c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa",
		"eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff0000000000000000000000000000000000000000000000000000000000000000",
	},
	{
		"0100000000000000000000000000000000000000000000000000000000000080",
		"01000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
	},
	{
		"0100000000000000000000000000000000000000000000000000000000000080",
		"c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a0000000000000000000000000000000000000000000000000000000000000000",
	},
	{
		"0100000000000000000000000000000000000000000000000000000000000080",
		"00000000000000000000000000000000000000000000000000000000000000800000000000000000000000000000000000000000000000000000000000000000",
	},
	{
		"0100000000000000000000000000000000000000000000000000000000000080",
		"26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc050000000000000000000000000000000000000000000000000000000000000000",
	},
	{
		"0100000000000000000000000000000000000000000000000000000000000080",
		"ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f0000000000000000000000000000000000000000000000000000000000000000",
	},
	{
		"0100000000000000000000000000000000000000000000000000000000000080",
		"26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc850000000000000000000000000000000000000000000000000000000000000000",
	},
	{
		"0100000000000000000000000000000000000000000000000000000000000080",
		"00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
	},
	{
		"0100000000000000000000000000000000000000000000000000000000000080",
		"c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa0000000000000000000000000000000000000000000000000000000000000000",
	},
	{
		"0100000000000000000000000000000000000000000000000000000000000080",
		"01000000000000000000000000000000000000000000000000000000000000800000000000000000000000000000000000000000000000000000000000000000",
	},
	{
		"0100000000000000000000000000000000000000000000000000000000000080",
		"ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff0000000000000000000000000000000000000000000000000000000000000000",
	},
	{
		"0100000000000000000000000000000000000000000000000000000000000080",
		"edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f0000000000000000000000000000000000000000000000000000000000000000",
	},
	{
		"0100000000000000000000000000000000000000000000000000000000000080",
		"edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff0000000000000000000000000000000000000000000000000000000000000000",
	},
	{
		"0100000000000000000000000000000000000000000000000000000000000080",
		"eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f0000000000000000000000000000000000000000000000000000000000000000",
	},
	{
		"0100000000000000000000000000000000000000000000000000000000000080",
		"eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff0000000000000000000000000000000000000000000000000000000000000000",
	},
	{
		"ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
		"01000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
	},
	{
		"ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
		"c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a0000000000000000000000000000000000000000000000000000000000000000",
	},
	{
		"ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
		"00000000000000000000000000000000000000000000000000000000000000800000000000000000000000000000000000000000000000000000000000000000",
	},
	{
		"ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
		"26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc050000000000000000000000000000000000000000000000000000000000000000",
	},
	{
		"ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
		"ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f0000000000000000000000000000000000000000000000000000000000000000",
	},
	{
		"ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
		"26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc850000000000000000000000000000000000000000000000000000000000000000",
	},
	{
		"ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
		"00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
	},
	{
		"ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
		"c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa0000000000000000000000000000000000000000000000000000000000000000",
	},
	{
		"ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
		"01000000000000000000000000000000000000000000000000000000000000800000000000000000000000000000000000000000000000000000000000000000",
	},
	{
		"ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
		"ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff0000000000000000000000000000000000000000000000000000000000000000",
	},
	{
		"ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
		"edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f0000000000000000000000000000000000000000000000000000000000000000",
	},
	{
		"ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
		"edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff0000000000000000000000000000000000000000000000000000000000000000",
	},
	{
		"ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
		"eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f0000000000000000000000000000000000000000000000000000000000000000",
	},
	{
		"ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
		"eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff0000000000000000000000000000000000000000000000000000000000000000",
	},
	{
		"edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
		"01000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
	},
	{
		"edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
		"c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a0000000000000000000000000000000000000000000000000000000000000000",
	},
	{
		"edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
		"00000000000000000000000000000000000000000000000000000000000000800000000000000000000000000000000000000000000000000000000000000000",
	},
	{
		"edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
		"26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc050000000000000000000000000000000000000000000000000000000000000000",
	},
	{
		"edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
		"ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f0000000000000000000000000000000000000000000000000000000000000000",
	},
	{
		"edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
		"26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc850000000000000000000000000000000000000000000000000000000000000000",
	},
	{
		"edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
		"00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
	},
	{
		"edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
		"c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa0000000000000000000000000000000000000000000000000000000000000000",
	},
	{
		"edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
		"01000000000000000000000000000000000000000000000000000000000000800000000000000000000000000000000000000000000000000000000000000000",
	},
	{
		"edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
		"ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff0000000000000000000000000000000000000000000000000000000000000000",
	},
	{
		"edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
		"edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f0000000000000000000000000000000000000000000000000000000000000000",
	},
	{
		"edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
		"edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff0000000000000000000000000000000000000000000000000000000000000000",
	},
	{
		"edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
		"eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f0000000000000000000000000000000000000000000000000000000000000000",
	},
	{
		"edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
		"eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff0000000000000000000000000000000000000000000000000000000000000000",
	},
	{
		"edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
		"01000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
	},
	{
		"edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
		"c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a0000000000000000000000000000000000000000000000000000000000000000",
	},
	{
		"edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
		"00000000000000000000000000000000000000000000000000000000000000800000000000000000000000000000000000000000000000000000000000000000",
	},
	{
		"edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
		"26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc050000000000000000000000000000000000000000000000000000000000000000",
	},
	{
		"edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
		"ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f0000000000000000000000000000000000000000000000000000000000000000",
	},
	{
		"edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
		"26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc850000000000000000000000000000000000000000000000000000000000000000",
	},
	{
		"edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
		"00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
	},
	{
		"edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
		"c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa0000000000000000000000000000000000000000000000000000000000000000",
	},
	{
		"edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
		"01000000000000000000000000000000000000000000000000000000000000800000000000000000000000000000000000000000000000000000000000000000",
	},
	{
		"edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
		"ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff0000000000000000000000000000000000000000000000000000000000000000",
	},
	{
		"edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
		"edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f0000000000000000000000000000000000000000000000000000000000000000",
	},
	{
		"edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
		"edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff0000000000000000000000000000000000000000000000000000000000000000",
	},
	{
		"edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
		"eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f0000000000000000000000000000000000000000000000000000000000000000",
	},
	{
		"edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
		"eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff0000000000000000000000000000000000000000000000000000000000000000",
	},
	{
		"eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
		"01000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
	},
	{
		"eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
		"c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a0000000000000000000000000000000000000000000000000000000000000000",
	},
	{
		"eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
		"00000000000000000000000000000000000000000000000000000000000000800000000000000000000000000000000000000000000000000000000000000000",
	},
	{
		"eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
		"26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc050000000000000000000000000000000000000000000000000000000000000000",
	},
	{
		"eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
		"ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f0000000000000000000000000000000000000000000000000000000000000000",
	},
	{
		"eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
		"26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc850000000000000000000000000000000000000000000000000000000000000000",
	},
	{
		"eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
		"00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
	},
	{
		"eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
		"c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa0000000000000000000000000000000000000000000000000000000000000000",
	},
	{
		"eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
		"01000000000000000000000000000000000000000000000000000000000000800000000000000000000000000000000000000000000000000000000000000000",
	},
	{
		"eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
		"ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff0000000000000000000000000000000000000000000000000000000000000000",
	},
	{
		"eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
		"edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f0000000000000000000000000000000000000000000000000000000000000000",
	},
	{
		"eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
		"edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff0000000000000000000000000000000000000000000000000000000000000000",
	},
	{
		"eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
		"eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f0000000000000000000000000000000000000000000000000000000000000000",
	},
	{
		"eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
		"eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff0000000000000000000000000000000000000000000000000000000000000000",
	},
	{
		"eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
		"01000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
	},
	{
		"eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
		"c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a0000000000000000000000000000000000000000000000000000000000000000",
	},
	{
		"eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
		"00000000000000000000000000000000000000000000000000000000000000800000000000000000000000000000000000000000000000000000000000000000",
	},
	{
		"eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
		"26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc050000000000000000000000000000000000000000000000000000000000000000",
	},
	{
		"eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
		"ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f0000000000000000000000000000000000000000000000000000000000000000",
	},
	{
		"eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
		"26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc850000000000000000000000000000000000000000000000000000000000000000",
	},
	{
		"eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
		"00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
	},
	{
		"eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
		"c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa0000000000000000000000000000000000000000000000000000000000000000",
	},
	{
		"eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
		"01000000000000000000000000000000000000000000000000000000000000800000000000000000000000000000000000000000000000000000000000000000",
	},
	{
		"eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
		"ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff0000000000000000000000000000000000000000000000000000000000000000",
	},
	{
		"eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
		"edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f0000000000000000000000000000000000000000000000000000000000000000",
	},
	{
		"eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
		"edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff0000000000000000000000000000000000000000000000000000000000000000",
	},
	{
		"eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
		"eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f0000000000000000000000000000000000000000000000000000000000000000",
	},
	{
		"eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
		"eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff0000000000000000000000000000000000000000000000000000000000000000",
	},
}
