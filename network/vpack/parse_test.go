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
	"fmt"
	"testing"

	"github.com/algorand/go-algorand/agreement"
	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/protocol"
	"github.com/algorand/go-algorand/test/partitiontest"
	"github.com/stretchr/testify/assert"
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
		"expected string \"cred\", got \"a\""},
	{[]int{1, 2, 3},
		"reading map for unauthenticatedVote"},
	{map[string]string{"a": "1", "b": "2", "c": "3", "d": "4", "e": "5", "f": "6", "g": "7"},
		"expected fixed map size 3 for unauthenticatedVote, got 7"},
	{map[string]string{gtFixMapString: "1", "b": "2", "c": "3"},
		"readString: expected fixstr, got 0xd9"},

	// cred
	{map[string]string{"cred": "1", "d": "2", "e": "3"},
		"reading map for UnauthenticatedCredential"},
	{map[string]any{"cred": map[string]int{"pf": 1, "q": 2}, "d": "2", "e": "3"},
		"expected fixed map size 1 for UnauthenticatedCredential, got 2"},
	{map[string]any{"cred": map[string]int{gtFixMapString: 1}, "d": "2", "e": "3"},
		"readString: expected fixstr, got 0xd9"},
	{map[string]any{"cred": map[string]string{"invalid": "1"}, "r": "2", "sig": "3"},
		"expected string \"pf\", got \"invalid\""},
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
		"readString: expected fixstr, got 0xd9"},
	{map[string]any{"cred": map[string]any{"pf": crypto.VrfProof{1}}, "r": map[string]any{"rnd": 1}, "sig": map[string]any{
		"a": 1, "b": 2, "c": 3, "d": 4, "e": 5, "f": 6}},
		"expected string \"p\", got \"a\""},
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
		assert.ErrorContains(t, err, tc.errContains)
	}
}

// TestParseVaruintError asserts that an error is returned when writeVaruint fails,
// to improve test coverage.
func TestParseVaruintError(t *testing.T) {
	partitiontest.PartitionTest(t)
	v := agreement.UnauthenticatedVote{}
	v.Cred.Proof[0] = 1
	v.Sig.PK[0] = 1
	// make 4 votes, each with a different varuint set
	v1 := v
	v1.R.Round = 1
	v2 := v
	v2.R.Step = 100
	v3 := v
	v3.R.Period = 200
	v4 := v
	v4.R.Proposal.OriginalPeriod = 300

	for i, v := range []agreement.UnauthenticatedVote{v1, v2, v3, v4} {
		t.Logf("test %d", i)
		msgpbuf := protocol.Encode(&v)
		w := &mockCompressWriter{failVaruint: true}
		err := parseVote(msgpbuf, w)
		require.ErrorContains(t, err, "mockCompressWriter.writeVaruint")
	}
}

// mockCompressWriter implements compressWriter for testing
type mockCompressWriter struct {
	failVaruint bool
	writes      []any
}

func (m *mockCompressWriter) writeBin64(v voteValueType, val [64]byte) {
	m.writes = append(m.writes, val)
}
func (m *mockCompressWriter) writeBin80(v voteValueType, val [80]byte) {
	m.writes = append(m.writes, val)
}
func (m *mockCompressWriter) writeBin32(v voteValueType, val [32]byte) {
	m.writes = append(m.writes, val)
}
func (m *mockCompressWriter) writeVaruint(v voteValueType, valBytes []byte) error {
	if m.failVaruint {
		return fmt.Errorf("mockCompressWriter.writeVaruint")
	}
	m.writes = append(m.writes, valBytes)
	return nil
}
