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
	"fmt"
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
concat
substring 42 99
intc 0
intc 1
substring3
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
txn ApplicationID
txn OnCompletion
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
bz there
b there
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
app_local_get
pop
pop
int 1
byte 0x4242
app_local_gets
pop
byte 0x4242
app_global_gets
byte 0x4242
app_global_get
pop
pop
int 1
byte 0x4242
int 2
app_local_put
byte 0x4242
int 1
app_global_put
int 0
byte 0x4242
app_local_del
byte 0x4242
app_global_del
int 0
int 1
asset_holding_get AssetBalance
pop
pop
int 0
int 1
asset_params_get AssetTotal
pop
pop
txna Accounts 0
pop
gtxna 0 ApplicationArgs 0
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
	for _, spec := range OpSpecs {
		// Ensure that we have some basic check of all the ops, except
		// we don't test every combination of
		// intcblock,bytecblock,intc*,bytec*,arg* here.
		if !strings.Contains(bigTestAssembleNonsenseProgram, spec.Name) &&
			!strings.HasPrefix(spec.Name, "int") &&
			!strings.HasPrefix(spec.Name, "byte") &&
			!strings.HasPrefix(spec.Name, "arg") {
			t.Errorf("test should contain op %v", spec.Name)
		}
	}
	program, err := AssembleString(bigTestAssembleNonsenseProgram)
	require.NoError(t, err)
	// check that compilation is stable over time and we assemble to the same bytes this month that we did last month.
	expectedBytes, _ := hex.DecodeString("022008b7a60cf8acd19181cf959a12f8acd19181cf951af8acd19181cf15f8acd191810f01020026040212340c68656c6c6f20776f726c6421208dae2087fbba51304eb02b91f656948397a7946390e8cb70fc9ea4d95f92251d02424200320032013202320328292929292a50512a632223520431003101310231043105310731083109310a310b310c310d310e310f311131123113311431153118311933000033000133000233000433000533000733000833000933000a33000b33000c33000d33000e33000f3300113300123300133300143300152d2e0102222324252104082209240a220b230c240d250e230f23102311231223132314181b1c41000d42000a2b171615400003290349483403350222231d4821056021056121052b63484821052b62482b642b65484821052b2106662b21056721072b682b6921072105700048482107210571004848361c004837001a0048")
	if bytes.Compare(expectedBytes, program) != 0 {
		// this print is for convenience if the program has been changed. the hex string can be copy pasted back in as a new expected result.
		t.Log(hex.EncodeToString(program))
	}
	require.Equal(t, expectedBytes, program)
}

func TestAssembleAlias(t *testing.T) {
	t.Parallel()
	source1 := `txn Accounts 0  // alias to txna
pop
gtxn 0 ApplicationArgs 0 // alias to gtxn
pop
`
	prog1, err := AssembleString(source1)
	require.NoError(t, err)

	source2 := `txna Accounts 0
pop
gtxna 0 ApplicationArgs 0
pop
`
	prog2, err := AssembleString(source2)
	require.NoError(t, err)

	require.Equal(t, prog1, prog2)
}

func TestAssembleTxna(t *testing.T) {
	source := `txna Accounts 256`
	_, err := AssembleString(source)
	require.Error(t, err)
	require.Contains(t, err.Error(), "txna cannot look up beyond index 255")

	source = `txna ApplicationArgs 256`
	_, err = AssembleString(source)
	require.Error(t, err)
	require.Contains(t, err.Error(), "txna cannot look up beyond index 255")

	source = `txna Sender 256`
	_, err = AssembleString(source)
	require.Error(t, err)
	require.Contains(t, err.Error(), "txna unknown arg")

	source = `gtxna 0 Accounts 256`
	_, err = AssembleString(source)
	require.Error(t, err)
	require.Contains(t, err.Error(), "gtxna cannot look up beyond index 255")

	source = `gtxna 0 ApplicationArgs 256`
	_, err = AssembleString(source)
	require.Error(t, err)
	require.Contains(t, err.Error(), "gtxna cannot look up beyond index 255")

	source = `gtxna 256 Accounts 0`
	_, err = AssembleString(source)
	require.Error(t, err)
	require.Contains(t, err.Error(), "gtxna cannot look up beyond index 255")

	source = `gtxna 0 Sender 256`
	_, err = AssembleString(source)
	require.Error(t, err)
	require.Contains(t, err.Error(), "gtxna unknown arg")

	source = `txn Accounts 0`
	_, err = AssembleStringV1(source)
	require.Error(t, err)
	require.Contains(t, err.Error(), "txn expects one argument")

	source = `txn Accounts 0 1`
	_, err = AssembleStringV2(source)
	require.Error(t, err)
	require.Contains(t, err.Error(), "txn expects one or two arguments")

	source = `txna Accounts 0 1`
	_, err = AssembleString(source)
	require.Error(t, err)
	require.Contains(t, err.Error(), "txna expects two arguments")

	source = `txna Accounts a`
	_, err = AssembleString(source)
	require.Error(t, err)
	require.Contains(t, err.Error(), "strconv.ParseUint")

	source = `gtxn 0 Sender 0`
	_, err = AssembleStringV1(source)
	require.Error(t, err)
	require.Contains(t, err.Error(), "gtxn expects two arguments")

	source = `gtxn 0 Sender 1 2`
	_, err = AssembleStringV2(source)
	require.Error(t, err)
	require.Contains(t, err.Error(), "gtxn expects two or three arguments")

	source = `gtxna 0 Accounts 1 2`
	_, err = AssembleString(source)
	require.Error(t, err)
	require.Contains(t, err.Error(), "gtxna expects three arguments")

	source = `gtxna a Accounts 0`
	_, err = AssembleString(source)
	require.Error(t, err)
	require.Contains(t, err.Error(), "strconv.ParseUint")

	source = `gtxna 0 Accounts a`
	_, err = AssembleString(source)
	require.Error(t, err)
	require.Contains(t, err.Error(), "strconv.ParseUint")

	source = `txn ABC`
	_, err = AssembleStringV2(source)
	require.Error(t, err)
	require.Contains(t, err.Error(), "txn unknown arg")

	source = `gtxn 0 ABC`
	_, err = AssembleStringV2(source)
	require.Error(t, err)
	require.Contains(t, err.Error(), "gtxn unknown arg")

	source = `gtxn a ABC`
	_, err = AssembleStringV2(source)
	require.Error(t, err)
	require.Contains(t, err.Error(), "strconv.ParseUint")
}

func TestAssembleGlobal(t *testing.T) {
	source := `global`
	_, err := AssembleString(source)
	require.Error(t, err)
	require.Contains(t, err.Error(), "global expects one argument")

	source = `global a`
	_, err = AssembleString(source)
	require.Error(t, err)
	require.Contains(t, err.Error(), "global unknown arg")
}

func TestAssembleDefault(t *testing.T) {
	source := `byte 0x1122334455
int 1
+
// comment
`
	_, err := AssembleString(source)
	require.Error(t, err)
	require.Contains(t, err.Error(), "wanted type uint64 got []byte")
}

// mutateProgVersion replaces version (first two symbols) in hex-encoded program
func mutateProgVersion(version uint64, prog string) string {
	return fmt.Sprintf("%02x%s", version, prog[2:])
}

func TestOpUint(t *testing.T) {
	for v := uint64(1); v <= AssemblerDefaultVersion; v++ {
		t.Run(fmt.Sprintf("v=%d", v), func(t *testing.T) {
			ops := OpStream{Version: v}
			err := ops.Uint(0xcafebabe)
			require.NoError(t, err)
			program, err := ops.Bytes()
			require.NoError(t, err)
			s := hex.EncodeToString(program)
			expected := mutateProgVersion(v, "012001bef5fad70c22")
			require.Equal(t, expected, s)
		})
	}
}

func TestOpUint64(t *testing.T) {
	t.Parallel()
	for v := uint64(1); v <= AssemblerDefaultVersion; v++ {
		t.Run(fmt.Sprintf("v=%d", v), func(t *testing.T) {
			t.Parallel()
			ops := OpStream{Version: v}
			err := ops.Uint(0xcafebabecafebabe)
			require.NoError(t, err)
			program, err := ops.Bytes()
			require.NoError(t, err)
			s := hex.EncodeToString(program)
			require.Equal(t, mutateProgVersion(v, "012001bef5fad7ecd7aeffca0122"), s)
		})
	}
}

func TestOpBytes(t *testing.T) {
	t.Parallel()
	for v := uint64(1); v <= AssemblerDefaultVersion; v++ {
		t.Run(fmt.Sprintf("v=%d", v), func(t *testing.T) {
			ops := OpStream{Version: v}
			err := ops.ByteLiteral([]byte("abcdef"))
			program, err := ops.Bytes()
			require.NoError(t, err)
			s := hex.EncodeToString(program)
			require.Equal(t, mutateProgVersion(v, "0126010661626364656628"), s)
		})
	}
}

func TestAssembleInt(t *testing.T) {
	t.Parallel()
	for v := uint64(1); v <= AssemblerDefaultVersion; v++ {
		t.Run(fmt.Sprintf("v=%d", v), func(t *testing.T) {
			text := "int 0xcafebabe"
			program, err := AssembleStringWithVersion(text, v)
			require.NoError(t, err)
			s := hex.EncodeToString(program)
			require.Equal(t, mutateProgVersion(v, "012001bef5fad70c22"), s)
		})
	}
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
	t.Parallel()
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
	for v := uint64(1); v <= AssemblerDefaultVersion; v++ {
		t.Run(fmt.Sprintf("v=%d", v), func(t *testing.T) {
			for _, vi := range variations {
				program, err := AssembleStringWithVersion(vi, v)
				require.NoError(t, err)
				s := hex.EncodeToString(program)
				require.Equal(t, mutateProgVersion(v, "0126010661626364656628"), s)
			}
		})
	}
}

func TestAssembleRejectNegJump(t *testing.T) {
	t.Parallel()
	text := `wat:
int 1
bnz wat`
	for v := uint64(1); v <= AssemblerDefaultVersion; v++ {
		t.Run(fmt.Sprintf("v=%d", v), func(t *testing.T) {
			program, err := AssembleStringWithVersion(text, v)
			require.Error(t, err)
			require.Nil(t, program)
		})
	}
}

func TestAssembleBase64(t *testing.T) {
	t.Parallel()
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
	for v := uint64(1); v <= AssemblerDefaultVersion; v++ {
		t.Run(fmt.Sprintf("v=%d", v), func(t *testing.T) {
			program, err := AssembleStringWithVersion(text, v)
			require.NoError(t, err)
			s := hex.EncodeToString(program)
			require.Equal(t, mutateProgVersion(v, "01200101260320fff19644cfb2cb70426af0435cefc5613359ea8d896a2e5e76c30205d0c4cfed206af19644cfb2cb70426af0435cefc5613359ea8d896a2e5e76c30205d0c4cfff20fff19644cfb2cb70426af0435cefc5613359ea8d896a2e5e76c30205d0c4cfef2829122210122a291211"), s)
		})
	}
}

func TestAssembleRejectUnkLabel(t *testing.T) {
	t.Parallel()
	text := `int 1
bnz nowhere`
	for v := uint64(1); v <= AssemblerDefaultVersion; v++ {
		t.Run(fmt.Sprintf("v=%d", v), func(t *testing.T) {
			program, err := AssembleStringWithVersion(text, v)
			require.Error(t, err)
			require.Nil(t, program)
		})
	}
}

func TestAssembleJumpToTheEnd(t *testing.T) {
	text := `intcblock 1
intc 0
intc 0
bnz done
done:`
	program, err := AssembleString(text)
	require.NoError(t, err)
	require.Equal(t, 9, len(program))
	expectedProgBytes := []byte("\x01\x20\x01\x01\x22\x22\x40\x00\x00")
	expectedProgBytes[0] = byte(AssemblerDefaultVersion)
	require.Equal(t, expectedProgBytes, program)
}

func TestAssembleDisassemble(t *testing.T) {
	// Specifically constructed program text that should be recreated by Disassemble()
	// TODO: disassemble to int/byte psuedo-ops instead of raw intcblock/bytecblock/intc/bytec
	t.Parallel()
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
global ZeroAddress
global GroupSize
global LogicSigVersion
global Round
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
txn FirstValidTime
txn Lease
txn VoteKeyDilution
txn Type
txn TypeEnum
txn XferAsset
txn AssetAmount
txn AssetSender
txn AssetReceiver
txn AssetCloseTo
txn GroupIndex
txn TxID
txn ApplicationID
txn OnCompletion
txn ApplicationArgs
txn NumAppArgs
txn Accounts
txn NumAccounts
txn ApprovalProgram
txn ClearStateProgram
gtxn 12 Fee
`
	for _, globalField := range GlobalFieldNames {
		if !strings.Contains(text, globalField) {
			t.Errorf("TestAssembleDisassemble missing field global %v", globalField)
		}
	}
	for _, txnField := range TxnFieldNames {
		if !strings.Contains(text, txnField) {
			t.Errorf("TestAssembleDisassemble missing field txn %v", txnField)
		}
	}
	program, err := AssembleStringV1(text)
	require.NoError(t, err)
	t2, err := Disassemble(program)
	require.Equal(t, text, t2)
	require.NoError(t, err)
}

func TestAssembleDisassembleCycle(t *testing.T) {
	// Test that disassembly re-assembles to the same program bytes.
	// It disassembly won't necessarily perfectly recreate the source text, but assembling the result of Disassemble() should be the same program bytes.
	t.Parallel()

	tests := map[uint64]string{
		2: bigTestAssembleNonsenseProgram,
		1: bigTestAssembleNonsenseProgram[:strings.Index(bigTestAssembleNonsenseProgram, "balance")],
	}

	for v, source := range tests {
		t.Run(fmt.Sprintf("v=%d", v), func(t *testing.T) {
			program, err := AssembleString(source)
			require.NoError(t, err)
			t2, err := Disassemble(program)
			require.NoError(t, err)
			p2, err := AssembleStringV2(t2)
			if err != nil {
				t.Log(t2)
			}
			require.NoError(t, err)
			require.Equal(t, program, p2)
		})
	}
}

func TestAssembleDisassembleErrors(t *testing.T) {
	source := `txn Sender`
	program, err := AssembleString(source)
	require.NoError(t, err)
	program[2] = 0x50 // txn field
	_, err = Disassemble(program)
	require.Error(t, err)
	require.Contains(t, err.Error(), "invalid txn arg index")

	source = `txna Accounts 0`
	program, err = AssembleString(source)
	require.NoError(t, err)
	program[2] = 0x50 // txn field
	_, err = Disassemble(program)
	require.Error(t, err)
	require.Contains(t, err.Error(), "invalid txn arg index")

	source = `gtxn 0 Sender`
	program, err = AssembleString(source)
	require.NoError(t, err)
	program[3] = 0x50 // txn field
	_, err = Disassemble(program)
	require.Error(t, err)
	require.Contains(t, err.Error(), "invalid txn arg index")

	source = `gtxna 0 Accounts 0`
	program, err = AssembleString(source)
	require.NoError(t, err)
	program[3] = 0x50 // txn field
	_, err = Disassemble(program)
	require.Error(t, err)
	require.Contains(t, err.Error(), "invalid txn arg index")

	source = `global MinTxnFee`
	program, err = AssembleString(source)
	require.NoError(t, err)
	program[2] = 0x50 // txn field
	_, err = Disassemble(program)
	require.Error(t, err)
	require.Contains(t, err.Error(), "invalid global arg index")

	program[0] = 0x11 // version
	out, err := Disassemble(program)
	require.NoError(t, err)
	require.Contains(t, out, "unsupported version")

	program[0] = 0x01 // version
	program[1] = 0xFF // first opcode
	out, err = Disassemble(program)
	require.Error(t, err)
	require.Contains(t, err.Error(), "invalid opcode")

	source = "int 0\nint 0\nasset_holding_get AssetFrozen"
	program, err = AssembleString(source)
	require.NoError(t, err)
	program[7] = 0x50 // holding field
	_, err = Disassemble(program)
	require.Error(t, err)
	require.Contains(t, err.Error(), "invalid asset holding arg index")

	source = "int 0\nint 0\nasset_params_get AssetTotal"
	program, err = AssembleString(source)
	require.NoError(t, err)
	program[7] = 0x50 // params field
	_, err = Disassemble(program)
	require.Error(t, err)
	require.Contains(t, err.Error(), "invalid asset params arg index")
}

func TestAssembleVersions(t *testing.T) {
	text := `int 1
txna Accounts 0
`
	_, err := AssembleString(text)
	require.NoError(t, err)

	_, err = AssembleStringV2(text)
	require.NoError(t, err)

	_, err = AssembleStringV1(text)
	require.Error(t, err)
	require.Contains(t, err.Error(), "unknown opcode txna")
}

func TestAssembleBalance(t *testing.T) {
	t.Parallel()

	text := `byte 0x00
balance
int 1
==`
	_, err := AssembleString(text)
	require.Error(t, err)
	require.Contains(t, err.Error(), "balance arg 0 wanted type uint64 got []byte")
}

func TestAssembleAsset(t *testing.T) {
	source := "int 0\nint 0\nasset_holding_get ABC 1"
	_, err := AssembleString(source)
	require.Error(t, err)
	require.Contains(t, err.Error(), "asset_holding_get expects one argument")

	source = "int 0\nint 0\nasset_holding_get ABC"
	_, err = AssembleString(source)
	require.Error(t, err)
	require.Contains(t, err.Error(), "asset_holding_get unknown arg")

	source = "int 0\nint 0\nasset_params_get ABC 1"
	_, err = AssembleString(source)
	require.Error(t, err)
	require.Contains(t, err.Error(), "asset_params_get expects one argument")

	source = "int 0\nint 0\nasset_params_get ABC"
	_, err = AssembleString(source)
	require.Error(t, err)
	require.Contains(t, err.Error(), "asset_params_get unknown arg")
}

func TestDisassembleSingleOp(t *testing.T) {
	// test ensures no double arg_0 entries in disassebly listing
	sample := "// version 2\narg_0\n"
	program, err := AssembleString(sample)
	require.NoError(t, err)
	require.Equal(t, 2, len(program))
	disassembled, err := Disassemble(program)
	require.NoError(t, err)
	require.Equal(t, sample, disassembled)
}

func TestAssembleOffsets(t *testing.T) {
	source := "err"
	program, offsets, err := AssembleStringWithVersionEx(source, AssemblerDefaultVersion)
	require.NoError(t, err)
	require.Equal(t, 2, len(program))
	require.Equal(t, 1, len(offsets))
	// vlen
	line, ok := offsets[0]
	require.False(t, ok)
	// err
	line, ok = offsets[1]
	require.True(t, ok)
	require.Equal(t, 0, line)

	source = `err
// comment
err
`
	program, offsets, err = AssembleStringWithVersionEx(source, AssemblerDefaultVersion)
	require.NoError(t, err)
	require.Equal(t, 3, len(program))
	require.Equal(t, 2, len(offsets))
	// vlen
	line, ok = offsets[0]
	require.False(t, ok)
	// err 1
	line, ok = offsets[1]
	require.True(t, ok)
	require.Equal(t, 0, line)
	// err 2
	line, ok = offsets[2]
	require.True(t, ok)
	require.Equal(t, 2, line)

	source = `err
bnz label1
err
label1:
err
`
	program, offsets, err = AssembleStringWithVersionEx(source, AssemblerDefaultVersion)
	require.NoError(t, err)
	require.Equal(t, 7, len(program))
	require.Equal(t, 4, len(offsets))
	// vlen
	line, ok = offsets[0]
	require.False(t, ok)
	// err 1
	line, ok = offsets[1]
	require.True(t, ok)
	require.Equal(t, 0, line)
	// bnz
	line, ok = offsets[2]
	require.True(t, ok)
	require.Equal(t, 1, line)
	// bnz byte 1
	line, ok = offsets[3]
	require.False(t, ok)
	// bnz byte 2
	line, ok = offsets[4]
	require.False(t, ok)
	// err 2
	line, ok = offsets[5]
	require.True(t, ok)
	require.Equal(t, 2, line)
	// err 3
	line, ok = offsets[6]
	require.True(t, ok)
	require.Equal(t, 4, line)

	source = `int 0
// comment
!
`
	program, offsets, err = AssembleStringWithVersionEx(source, AssemblerDefaultVersion)
	require.NoError(t, err)
	require.Equal(t, 6, len(program))
	require.Equal(t, 2, len(offsets))
	// vlen
	line, ok = offsets[0]
	require.False(t, ok)
	// int 0
	line, ok = offsets[4]
	require.True(t, ok)
	require.Equal(t, 0, line)
	// !
	line, ok = offsets[5]
	require.True(t, ok)
	require.Equal(t, 2, line)
}
