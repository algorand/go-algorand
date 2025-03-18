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

package vpack

import (
	"testing"

	"github.com/algorand/go-algorand/agreement"
	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/protocol"
	"github.com/algorand/go-algorand/test/partitiontest"
	"github.com/stretchr/testify/require"
)

// a string that is greater than the max 5-bit fixmap size
const gtFixMapString = "12345678901234567890123456789012"

var parseVoteTestCases = []struct {
	obj         any
	errContains string
}{
	// vote
	{map[string]string{"a": "1", "b": "2"},
		"expected fixed map size 3 for unauthenticatedVote, got 2"},
	{map[string]any{"a": 1, "b": 2, "c": 3},
		"unexpected field in unauthenticatedVote"},
	{[]int{1, 2, 3},
		"reading map for unauthenticatedVote"},
	{map[string]string{"a": "1", "b": "2", "c": "3", "d": "4", "e": "5", "f": "6", "g": "7"},
		"expected fixed map size 3 for unauthenticatedVote, got 7"},
	{map[string]string{gtFixMapString: "1", "b": "2", "c": "3"},
		"reading key for unauthenticatedVote"},

	// cred
	{map[string]string{"cred": "1", "d": "2", "e": "3"},
		"reading map for UnauthenticatedCredential"},
	{map[string]any{"cred": map[string]int{"pf": 1, "q": 2}, "d": "2", "e": "3"},
		"expected fixed map size 1 for UnauthenticatedCredential, got 2"},
	{map[string]any{"cred": map[string]int{gtFixMapString: 1}, "d": "2", "e": "3"},
		"reading key for UnauthenticatedCredential"},
	{map[string]any{"cred": map[string]string{"invalid": "1"}, "r": "2", "sig": "3"},
		"unexpected field in UnauthenticatedCredential"},
	{map[string]any{"cred": map[string]any{"pf": []byte{1, 2, 3}}, "r": "2", "sig": "3"},
		"reading pf"},

	// rawVote
	{map[string]any{"cred": map[string]any{"pf": crypto.VrfProof{1}}, "r": []int{1, 2, 3}, "sig": "3"},
		"reading map for rawVote"},
	{map[string]any{"cred": map[string]any{"pf": crypto.VrfProof{1}}, "r": map[string]string{}, "sig": "3"},
		"expected fixmap size for rawVote 1 <= cnt <= 5, got 0"},
	{map[string]any{"cred": map[string]any{"pf": crypto.VrfProof{1}}, "r": map[string]string{"a": "1", "b": "2", "c": "3", "d": "4", "e": "5", "f": "6"}, "sig": "3"},
		"expected fixmap size for rawVote 1 <= cnt <= 5, got 6"},
	{map[string]any{"cred": map[string]any{"pf": crypto.VrfProof{1}}, "r": map[string]string{gtFixMapString: "1"}, "sig": "3"},
		"reading key for rawVote"},
	{map[string]any{"cred": map[string]any{"pf": crypto.VrfProof{1}}, "r": map[string]string{"invalid": "1"}, "sig": "3"},
		"unexpected field in rawVote"},
	{map[string]any{"cred": map[string]any{"pf": crypto.VrfProof{1}}, "r": map[string]any{"per": "not-a-number"}, "sig": "3"},
		"reading per"},
	{map[string]any{"cred": map[string]any{"pf": crypto.VrfProof{1}}, "r": map[string]any{"rnd": "not-a-number"}, "sig": "3"},
		"reading rnd"},
	{map[string]any{"cred": map[string]any{"pf": crypto.VrfProof{1}}, "r": map[string]any{"step": "not-a-number"}, "sig": "3"},
		"reading step"},
	{map[string]any{"cred": map[string]any{"pf": crypto.VrfProof{1}}, "r": map[string]any{"prop": "not-a-map"}, "sig": "3"},
		"reading map for proposalValue"},
	{map[string]any{"cred": map[string]any{"pf": crypto.VrfProof{1}}, "r": map[string]any{"snd": []int{1, 2, 3}}, "sig": "3"},
		"reading snd"},
	{map[string]any{"cred": map[string]any{"pf": crypto.VrfProof{1}}, "r": map[string]string{"snd": "1"}, "sig": []int{1, 2, 3}},
		"reading snd: expected bin8 length 32"},

	// proposalValue
	{map[string]any{"cred": map[string]any{"pf": crypto.VrfProof{1}}, "r": map[string]any{"prop": map[string]string{"invalid": "1"}}, "sig": "3"},
		"unexpected field in proposalValue"},
	{map[string]any{"cred": map[string]any{"pf": crypto.VrfProof{1}}, "r": map[string]any{"prop": map[string]string{gtFixMapString: "1"}}, "sig": "3"},
		"reading key for proposalValue"},
	{map[string]any{"cred": map[string]any{"pf": crypto.VrfProof{1}}, "r": map[string]any{"prop": map[string]any{"dig": []int{1, 2, 3}}}, "sig": "3"},
		"reading dig"},
	{map[string]any{"cred": map[string]any{"pf": crypto.VrfProof{1}}, "r": map[string]any{"prop": map[string]any{"encdig": []int{1, 2, 3}}}, "sig": "3"},
		"reading encdig"},
	{map[string]any{"cred": map[string]any{"pf": crypto.VrfProof{1}}, "r": map[string]any{"prop": map[string]any{"oper": "not-a-number"}}, "sig": "3"},
		"reading oper"},
	{map[string]any{"cred": map[string]any{"pf": crypto.VrfProof{1}}, "r": map[string]any{"prop": map[string]any{"oprop": []int{1, 2, 3}}}, "sig": "3"},
		"reading oprop"},
	{map[string]any{"cred": map[string]any{"pf": crypto.VrfProof{1}}, "r": map[string]any{"prop": map[string]any{"a": 1, "b": 2, "c": 3, "d": 4, "e": 5}}, "sig": "3"},
		"expected fixmap size for proposalValue 1 <= cnt <= 4, got 5"},

	// sig
	{map[string]any{"cred": map[string]any{"pf": crypto.VrfProof{1}}, "r": map[string]any{"rnd": 1}, "sig": []int{1, 2, 3}},
		"reading map for OneTimeSignature"},
	{map[string]any{"cred": map[string]any{"pf": crypto.VrfProof{1}}, "r": map[string]any{"rnd": 1}, "sig": map[string]any{}},
		"expected fixed map size 6 for OneTimeSignature, got 0"},
	{map[string]any{"cred": map[string]any{"pf": crypto.VrfProof{1}}, "r": map[string]any{"rnd": 1}, "sig": map[string]any{"p": []int{1}}},
		"expected fixed map size 6 for OneTimeSignature, got 1"},
	{map[string]any{"cred": map[string]any{"pf": crypto.VrfProof{1}}, "r": map[string]any{"rnd": 1}, "sig": map[string]any{
		gtFixMapString: "1", "a": 1, "b": 2, "c": 3, "d": 4, "e": 5}},
		"reading key for OneTimeSignature"},
	{map[string]any{"cred": map[string]any{"pf": crypto.VrfProof{1}}, "r": map[string]any{"rnd": 1}, "sig": map[string]any{
		"a": 1, "b": 2, "c": 3, "d": 4, "e": 5, "f": 6}},
		"unexpected field in OneTimeSignature"},
	{map[string]any{"cred": map[string]any{"pf": crypto.VrfProof{1}}, "r": map[string]any{"rnd": 1}, "sig": map[string]any{
		"p": []int{1}, "p1s": [64]byte{}, "p2": [32]byte{}, "p2s": [64]byte{}, "ps": [64]byte{}, "s": [64]byte{}}},
		"reading p: expected bin8 length 32"},
	{map[string]any{"cred": map[string]any{"pf": crypto.VrfProof{1}}, "r": map[string]any{"rnd": 1}, "sig": map[string]any{
		"p": [32]byte{}, "p1s": []int{1}, "p2": [32]byte{}, "p2s": [64]byte{}, "ps": [64]byte{}, "s": [64]byte{}}},
		"reading p1s: expected bin8 length 64"},
	{map[string]any{"cred": map[string]any{"pf": crypto.VrfProof{1}}, "r": map[string]any{"rnd": 1}, "sig": map[string]any{
		"p": [32]byte{}, "p1s": [64]byte{}, "p2": []int{1}, "p2s": [64]byte{}, "ps": [64]byte{}, "s": [64]byte{}}},
		"reading p2: expected bin8 length 32"},
	{map[string]any{"cred": map[string]any{"pf": crypto.VrfProof{1}}, "r": map[string]any{"rnd": 1}, "sig": map[string]any{
		"p": [32]byte{}, "p1s": [64]byte{}, "p2": [32]byte{}, "p2s": []int{1}, "ps": [64]byte{}, "s": [64]byte{}}},
		"reading p2s: expected bin8 length 64"},
	{map[string]any{"cred": map[string]any{"pf": crypto.VrfProof{1}}, "r": map[string]any{"rnd": 1}, "sig": map[string]any{
		"p": [32]byte{}, "p1s": [64]byte{}, "p2": [32]byte{}, "p2s": [64]byte{}, "ps": []int{1}, "s": [64]byte{}}},
		"reading ps: expected bin8 length 64"},
	{map[string]any{"cred": map[string]any{"pf": crypto.VrfProof{1}}, "r": map[string]any{"rnd": 1}, "sig": map[string]any{
		"p": [32]byte{}, "p1s": [64]byte{}, "p2": [32]byte{}, "p2s": [64]byte{}, "ps": [64]byte{}, "s": []int{1}}},
		"reading s: expected bin8 length 64"},
}

// TestParseVoteErrors tests error cases of the parseVote function
func TestParseVoteErrors(t *testing.T) {
	partitiontest.PartitionTest(t)

	for _, tc := range parseVoteTestCases {
		mock := &mockCompressWriter{}
		var buf []byte
		// protocol.Encode and protocol.EncodeReflect encode keys in alphabetical order
		if v, ok := tc.obj.(*agreement.UnauthenticatedVote); ok {
			buf = protocol.Encode(v)
		} else {
			buf = protocol.EncodeReflect(tc.obj)
		}
		err := parseVote(buf, mock)
		require.Error(t, err)
		require.Contains(t, err.Error(), tc.errContains)
	}
}

// TestParseEncodeStaticSteps asserts that table entries for step:1, step:2, step:3 are encoded
func TestParseEncodeStaticSteps(t *testing.T) {
	partitiontest.PartitionTest(t)
	v := agreement.UnauthenticatedVote{}
	v.Cred.Proof[0] = 1 // not empty
	v.R.Round = 1
	v.Sig.PK[0] = 1 // not empty

	for i := 1; i <= 3; i++ {
		var expectedStaticIdx uint8
		switch i {
		case 1:
			v.R.Step = 1
			expectedStaticIdx = staticIdxStepVal1Field
		case 2:
			v.R.Step = 2
			expectedStaticIdx = staticIdxStepVal2Field
		case 3:
			v.R.Step = 3
			expectedStaticIdx = staticIdxStepVal3Field
		}

		msgpbuf := protocol.Encode(&v)
		w := &mockCompressWriter{}
		err := parseVote(msgpbuf, w)
		require.NoError(t, err)
		require.Contains(t, w.writes, expectedStaticIdx)
	}
}

// mockCompressWriter implements compressWriter for testing
type mockCompressWriter struct{ writes []any }

func (m *mockCompressWriter) writeStatic(idx uint8)          { m.writes = append(m.writes, idx) }
func (m *mockCompressWriter) writeLiteralBin64(val [64]byte) { m.writes = append(m.writes, val) }
func (m *mockCompressWriter) writeLiteralBin80(val [80]byte) { m.writes = append(m.writes, val) }
func (m *mockCompressWriter) writeDynamicBin32(val [32]byte) { m.writes = append(m.writes, val) }
func (m *mockCompressWriter) writeDynamicVaruint(valBytes []byte) error {
	m.writes = append(m.writes, valBytes)
	return nil
}
