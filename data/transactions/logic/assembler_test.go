// Copyright (C) 2019 Algorand, Inc.
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
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/require"
)

// used by TestAssemble and others, see UPDATE PROCEDURE in TestAssemble()
const bigTestAssembleNonsenseProgram = `err
global Round
global MinTxnFee
global MinBalance
global MaxTxnLife
global TimeStamp
byte 0x1234
byte base64 aGVsbG8gd29ybGQh
byte base64(aGVsbG8gd29ybGQh)
byte b64 aGVsbG8gd29ybGQh
byte b64(aGVsbG8gd29ybGQh)
addr RWXCBB73XJITATVQFOI7MVUUQOL2PFDDSDUMW4H4T2SNSX4SEUOQ2MM7F4
txn Sender
txn Fee
txn FirstValid
txn LastValid
txn Note
txn Receiver
txn Amount
txn CloseRemainderTo
txn VotePK
txn SelectionPK
txn VoteFirst
txn VoteLast
arg 0 // comment
arg 1 //comment
//account Balance
sha256
keccak256
int 0x031337
int 0x1234567812345678
int 0x0034567812345678
int 0x0000567812345678
int 0x0000007812345678
+ // comment
// extra int pushes to satisfy typechecking on the ops that pop two ints
intc 0
- //comment
intc 2
/
intc 1
*
intc 1
<
intc 1
>
intc 1
<=
intc 1
>=
intc 1
&&
intc 1
||
intc 1
==
intc 1
!=
intc 1
!
byte 0x4242
btoi
bytec 1
len
bnz there
bytec 1
sha512_256
there:
pop
`

// Check that assembly output is stable across time.
func TestAssemble(t *testing.T) {
	// UPDATE PROCEDURE:
	// Run test. It should pass. If test is not passing, do not change this test, fix the assembler first.
	// Extend this test program text. It is preferrable to append instructions to the end so that the program byte hex is visually similar and also simply extended by some new bytes.
	// Copy hex string from failing test output into source.
	// Run test. It should pass.
	//
	// This doesn't have to be a sensible program to run, it just has to compile.
	program, err := AssembleString(bigTestAssembleNonsenseProgram)
	require.NoError(t, err)
	// check that compilation is stable over time and we assemble to the same bytes this month that we did last month.
	expectedBytes, _ := hex.DecodeString("012005b7a60cf8acd19181cf959a12f8acd19181cf951af8acd19181cf15f8acd191810f26040212340c68656c6c6f20776f726c6421208dae2087fbba51304eb02b91f656948397a7946390e8cb70fc9ea4d95f92251d024242003200320132023203320428292929292a3100310131023103310431053106310731083109310a310b2d2e0102222324252104082209240a230b230c230d230e230f231023112312231323142b172915400002290348")
	if bytes.Compare(expectedBytes, program) != 0 {
		// this print is for convenience if the program has been changed. the hex string can be copy pasted back in as a new expected result.
		t.Log(hex.EncodeToString(program))
	}
	require.Equal(t, expectedBytes, program)
}

func TestOpUint(t *testing.T) {
	ops := OpStream{}
	err := ops.Uint(0xcafebabe)
	require.NoError(t, err)
	program, err := ops.Bytes()
	require.NoError(t, err)
	s := hex.EncodeToString(program)
	require.Equal(t, "012001bef5fad70c22", s)
}

func TestOpUint64(t *testing.T) {
	ops := OpStream{}
	err := ops.Uint(0xcafebabecafebabe)
	require.NoError(t, err)
	program, err := ops.Bytes()
	require.NoError(t, err)
	s := hex.EncodeToString(program)
	require.Equal(t, "012001bef5fad7ecd7aeffca0122", s)
}

func TestOpBytes(t *testing.T) {
	ops := OpStream{}
	err := ops.ByteLiteral([]byte("abcdef"))
	program, err := ops.Bytes()
	require.NoError(t, err)
	s := hex.EncodeToString(program)
	require.Equal(t, "0126010661626364656628", s)
}

func TestAssembleInt(t *testing.T) {
	text := "int 0xcafebabe"
	program, err := AssembleString(text)
	require.NoError(t, err)
	s := hex.EncodeToString(program)
	require.Equal(t, "012001bef5fad70c22", s)
}

/*
test values generated in Python
python3
import base64
raw='abcdef'
base64.b64encode(raw.encode())
base64.b32encode(raw.encode())
base64.b16encode(raw.encode())
*/

func TestAssembleBytes(t *testing.T) {
	variations := []string{
		"byte b32 MFRGGZDFMY",
		"byte base32 MFRGGZDFMY",
		"byte base32(MFRGGZDFMY)",
		"byte b32(MFRGGZDFMY)",
		"byte b64 YWJjZGVm",
		"byte base64 YWJjZGVm",
		"byte b64(YWJjZGVm)",
		"byte base64(YWJjZGVm)",
		"byte 0x616263646566",
	}
	for _, vi := range variations {
		program, err := AssembleString(vi)
		require.NoError(t, err)
		s := hex.EncodeToString(program)
		require.Equal(t, "0126010661626364656628", s)
	}
}

func TestAssembleRejectNegJump(t *testing.T) {
	text := `wat:
int 1
bnz wat`
	program, err := AssembleString(text)
	require.Error(t, err)
	require.Nil(t, program)
}

func TestAssembleRejectUnkLabel(t *testing.T) {
	text := `int 1
bnz nowhere`
	program, err := AssembleString(text)
	require.Error(t, err)
	require.Nil(t, program)
}

func TestAssembleDisassemble(t *testing.T) {
	// Specifically constructed program text that should be recreated by Disassemble()
	// TODO: disassemble to int/byte psuedo-ops instead of raw intcblock/bytecblock/intc/bytec
	text := `// version 1
intcblock 0 1 2 3 4 5
bytecblock 0xcafed00d 0x1337 0x2001 0xdeadbeef 0x70077007
intc_1
intc_0
+
intc 4
*
bytec_1
bytec_0
==
bytec 4
len
+
arg_0
len
arg 5
len
+
global Round
global MinTxnFee
global MinBalance
global MaxTxnLife
global TimeStamp
txn Sender
txn Fee
txn FirstValid
txn LastValid
txn Note
txn Receiver
txn Amount
txn CloseRemainderTo
txn VotePK
txn SelectionPK
txn VoteFirst
txn VoteLast
`
	program, err := AssembleString(text)
	require.NoError(t, err)
	t2, err := Disassemble(program)
	require.Equal(t, text, t2)
	require.NoError(t, err)
}

func TestAssembleDisassembleCycle(t *testing.T) {
	// Test that disassembly re-assembles to the same program bytes.
	// It disassembly won't necessarily perfectly recreate the source text, but assembling the result of Disassemble() should be the same program bytes.
	program, err := AssembleString(bigTestAssembleNonsenseProgram)
	require.NoError(t, err)
	t2, err := Disassemble(program)
	require.NoError(t, err)
	p2, err := AssembleString(t2)
	if err != nil {
		t.Log(t2)
	}
	require.NoError(t, err)
	require.Equal(t, program, p2)
}
