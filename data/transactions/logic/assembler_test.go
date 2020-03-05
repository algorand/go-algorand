// Copyright (C) 2019-2020 Algorand, Inc.
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
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// used by TestAssemble and others, see UPDATE PROCEDURE in TestAssemble()
const bigTestAssembleNonsenseProgram = `err
global MinTxnFee
global MinBalance
global MaxTxnLife
global ZeroAddress
byte 0x1234
byte base64 aGVsbG8gd29ybGQh
byte base64(aGVsbG8gd29ybGQh)
byte b64 aGVsbG8gd29ybGQh
byte b64(aGVsbG8gd29ybGQh)
addr RWXCBB73XJITATVQFOI7MVUUQOL2PFDDSDUMW4H4T2SNSX4SEUOQ2MM7F4
ed25519verify
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
txn VoteKeyDilution
txn Type
txn XferAsset
txn AssetAmount
txn AssetSender
txn AssetReceiver
txn AssetCloseTo
txn Action
gtxn 0 Sender
gtxn 0 Fee
gtxn 0 FirstValid
gtxn 0 LastValid
gtxn 0 Note
gtxn 0 Receiver
gtxn 0 Amount
gtxn 0 CloseRemainderTo
gtxn 0 VotePK
gtxn 0 SelectionPK
gtxn 0 VoteFirst
gtxn 0 VoteLast
gtxn 0 VoteKeyDilution
gtxn 0 Type
gtxn 0 XferAsset
gtxn 0 AssetAmount
gtxn 0 AssetSender
gtxn 0 AssetReceiver
gtxn 0 AssetCloseTo
arg 0 // comment
arg 1 //comment
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
intc_0
*
intc_1
<
intc_2
>
intc_3
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
%
^
~
byte 0x4242
btoi
itob
len
bnz there
bytec 1
sha512_256
dup
there:
pop
load 3
store 2
intc 0
intc 1
mulw
pop  // pop extra returned element to balance the stack
int 1
balance
int 1
app_opted_in
int 1
byte 0x4242
app_read_local
pop
pop
byte 0x4242
app_read_global
pop
pop
int 1
byte 0x4242
int 2
app_write_local
byte 0x4242
int 1
app_write_global
int 0
int 1
byte 0x4242
app_read_other_global
pop
pop
int 0
int 1
int 2
asset_read_holding
pop
pop
int 0
int 1
int 2
asset_read_params
pop
pop
app_arg_0
pop
app_arg 2
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
	for _, spec := range OpSpecs {
		// Ensure that we have some basic check of all the ops, except
		// we don't test every combination of
		// intcblock,bytecblock,intc*,bytec*,arg* here.
		if !strings.Contains(bigTestAssembleNonsenseProgram, spec.Name) &&
			!strings.HasPrefix(spec.Name, "int") &&
			!strings.HasPrefix(spec.Name, "byte") &&
			!strings.HasPrefix(spec.Name, "arg") &&
			!strings.HasPrefix(spec.Name, "app_arg") {
			t.Errorf("test should contain op %v", spec.Name)
		}
	}
	program, err := AssembleString(bigTestAssembleNonsenseProgram)
	require.NoError(t, err)
	// check that compilation is stable over time and we assemble to the same bytes this month that we did last month.
	expectedBytes, _ := hex.DecodeString("012008b7a60cf8acd19181cf959a12f8acd19181cf951af8acd19181cf15f8acd191810f01020026040212340c68656c6c6f20776f726c6421208dae2087fbba51304eb02b91f656948397a7946390e8cb70fc9ea4d95f92251d02424200320032013202320328292929292a0431003101310231043105310731083109310a310b310c310d310e310f31113112311331143115311833000033000133000233000433000533000733000833000933000a33000b33000c33000d33000e33000f3300113300123300133300143300152d2e0102222324252104082209240a220b230c240d250e230f23102311231223132314181b1c2b171615400003290349483403350222231d4821056021056121052b6248482b63484821052b2106642b210565210721052b66484821072105210670484821072105210671484868486a")
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
		"byte b32 MFRGGZDFMY======",
		"byte base32 MFRGGZDFMY======",
		"byte base32(MFRGGZDFMY======)",
		"byte b32(MFRGGZDFMY======)",
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

func TestAssembleBase64(t *testing.T) {
	text := `byte base64 //GWRM+yy3BCavBDXO/FYTNZ6o2Jai5edsMCBdDEz+0=
byte base64 avGWRM+yy3BCavBDXO/FYTNZ6o2Jai5edsMCBdDEz//=
//
//text
==
int 1 //sometext
&& //somemoretext
==
byte b64 //GWRM+yy3BCavBDXO/FYTNZ6o2Jai5edsMCBdDEz+8=
byte b64 avGWRM+yy3BCavBDXO/FYTNZ6o2Jai5edsMCBdDEz//=
==
||`
	program, err := AssembleString(text)
	require.NoError(t, err)
	s := hex.EncodeToString(program)
	require.Equal(t, "01200101260320fff19644cfb2cb70426af0435cefc5613359ea8d896a2e5e76c30205d0c4cfed206af19644cfb2cb70426af0435cefc5613359ea8d896a2e5e76c30205d0c4cfff20fff19644cfb2cb70426af0435cefc5613359ea8d896a2e5e76c30205d0c4cfef2829122210122a291211", s)
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
bnz label1
global MinTxnFee
global MinBalance
global MaxTxnLife
txn Sender
txn Fee
bnz label1
txn FirstValid
txn LastValid
txn Note
txn Receiver
txn Amount
label1:
txn CloseRemainderTo
txn VotePK
txn SelectionPK
txn VoteFirst
txn VoteLast
gtxn 12 Fee
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
