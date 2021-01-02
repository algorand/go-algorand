// Copyright (C) 2019-2021 Algorand, Inc.
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
dup2
pop
pop
pop
pop
addr RWXCBB73XJITATVQFOI7MVUUQOL2PFDDSDUMW4H4T2SNSX4SEUOQ2MM7F4
concat
substring 42 99
intc 0
intc 1
substring3
bz there2
b there2
there2:
return
int 1
balance
int 1
app_opted_in
int 1
byte "test"
app_local_get_ex
pop
pop
int 1
byte "\x42\x42"
app_local_get
pop
byte 0x4242
app_global_get
byte 0x4242
app_global_get_ex
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
asset_params_get AssetTotal
pop
pop
txna Accounts 0
gtxna 0 ApplicationArgs 0
txn ApplicationID
txn OnCompletion
txn NumAppArgs
txn NumAccounts
txn ApprovalProgram
txn ClearStateProgram
txn RekeyTo
int 0
int 1
addw
txn ConfigAsset
txn ConfigAssetTotal
txn ConfigAssetDecimals
txn ConfigAssetDefaultFrozen
txn ConfigAssetUnitName
txn ConfigAssetName
txn ConfigAssetURL
txn ConfigAssetMetadataHash
txn ConfigAssetManager
txn ConfigAssetReserve
txn ConfigAssetFreeze
txn ConfigAssetClawback
txn FreezeAsset
txn FreezeAssetAccount
txn FreezeAssetFrozen
`

// Check that assembly output is stable across time.
func TestAssemble(t *testing.T) {
	// UPDATE PROCEDURE:
	// Run test. It should pass. If test is not passing, do not change this test, fix the assembler first.
	// Extend this test program text. Append instructions to the end so that the program byte hex is visually similar and also simply extended by some new bytes,
	// and so that version-dependent tests pass.
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
	ops, err := AssembleStringWithVersion(bigTestAssembleNonsenseProgram, AssemblerMaxVersion)
	require.NoError(t, err)
	// check that compilation is stable over time and we assemble to the same bytes this month that we did last month.
	expectedBytes, _ := hex.DecodeString("022008b7a60cf8acd19181cf959a12f8acd19181cf951af8acd19181cf15f8acd191810f01020026050212340c68656c6c6f20776f726c6421208dae2087fbba51304eb02b91f656948397a7946390e8cb70fc9ea4d95f92251d024242047465737400320032013202320328292929292a0431003101310231043105310731083109310a310b310c310d310e310f3111311231133114311533000033000133000233000433000533000733000833000933000a33000b33000c33000d33000e33000f3300113300123300133300143300152d2e0102222324252104082209240a220b230c240d250e230f23102311231223132314181b1c2b171615400003290349483403350222231d4a484848482a50512a63222352410003420000432105602105612105270463484821052b62482b642b65484821052b2106662b21056721072b682b692107210570004848210771004848361c0037001a0031183119311b311d311e311f3120210721051e312131223123312431253126312731283129312a312b312c312d312e312f")
	if bytes.Compare(expectedBytes, ops.Program) != 0 {
		// this print is for convenience if the program has been changed. the hex string can be copy pasted back in as a new expected result.
		t.Log(hex.EncodeToString(ops.Program))
	}
	require.Equal(t, expectedBytes, ops.Program)
}

func TestAssembleAlias(t *testing.T) {
	t.Parallel()
	source1 := `txn Accounts 0  // alias to txna
pop
gtxn 0 ApplicationArgs 0 // alias to gtxn
pop
`
	ops1, err := AssembleStringWithVersion(source1, AssemblerMaxVersion)
	require.NoError(t, err)

	source2 := `txna Accounts 0
pop
gtxna 0 ApplicationArgs 0
pop
`
	ops2, err := AssembleStringWithVersion(source2, AssemblerMaxVersion)
	require.NoError(t, err)

	require.Equal(t, ops1.Program, ops2.Program)
}

type expect struct {
	l int
	s string
}

func testMatch(t *testing.T, actual, expected string) {
	if strings.HasPrefix(expected, "...") && strings.HasSuffix(expected, "...") {
		require.Contains(t, actual, expected[3:len(expected)-3])
	} else if strings.HasPrefix(expected, "...") {
		require.Contains(t, actual+"^", expected[3:]+"^")
	} else if strings.HasSuffix(expected, "...") {
		require.Contains(t, "^"+actual, "^"+expected[:len(expected)-3])
	} else {
		require.Equal(t, actual, expected)
	}
}

func testProg(t *testing.T, source string, ver uint64, expected ...expect) {
	ops, err := AssembleStringWithVersion(source, ver)
	if len(expected) == 0 {
		require.NoError(t, err)
		require.NotNil(t, ops)
		require.Empty(t, ops.Errors)
		require.NotNil(t, ops.Program)
	} else {
		require.Error(t, err)
		errors := ops.Errors
		require.Len(t, errors, len(expected))
		for _, exp := range expected {
			var found *lineError
			for _, err := range errors {
				if err.Line == exp.l {
					found = err
				}
			}
			require.NotNil(t, found)
			msg := found.Unwrap().Error()
			testMatch(t, msg, exp.s)
		}
		require.Nil(t, ops.Program)
	}
}

func testLine(t *testing.T, line string, ver uint64, expected string) {
	// By embedding the source line between two other lines, the
	// test for the correct line number in the error is more
	// meaningful.
	source := "int 1\n" + line + "\nint 1\n"
	if expected == "" {
		testProg(t, source, ver)
		return
	}
	testProg(t, source, ver, expect{2, expected})
}
func TestAssembleTxna(t *testing.T) {
	testLine(t, "txna Accounts 256", AssemblerMaxVersion, "txna array index beyond 255: 256")
	testLine(t, "txna ApplicationArgs 256", AssemblerMaxVersion, "txna array index beyond 255: 256")
	testLine(t, "txna Sender 256", AssemblerMaxVersion, "txna unknown arg: Sender")
	testLine(t, "gtxna 0 Accounts 256", AssemblerMaxVersion, "gtxna array index beyond 255: 256")
	testLine(t, "gtxna 0 ApplicationArgs 256", AssemblerMaxVersion, "gtxna array index beyond 255: 256")
	testLine(t, "gtxna 256 Accounts 0", AssemblerMaxVersion, "gtxna group index beyond 255: 256")
	testLine(t, "gtxna 0 Sender 256", AssemblerMaxVersion, "gtxna unknown arg: Sender")
	testLine(t, "txn Accounts 0", 1, "txn expects one argument")
	testLine(t, "txn Accounts 0 1", 2, "txn expects one or two arguments")
	testLine(t, "txna Accounts 0 1", AssemblerMaxVersion, "txna expects two arguments")
	testLine(t, "txna Accounts a", AssemblerMaxVersion, "strconv.ParseUint...")
	testLine(t, "gtxn 0 Sender 0", 1, "gtxn expects two arguments")
	testLine(t, "gtxn 0 Sender 1 2", 2, "gtxn expects two or three arguments")
	testLine(t, "gtxna 0 Accounts 1 2", AssemblerMaxVersion, "gtxna expects three arguments")
	testLine(t, "gtxna a Accounts 0", AssemblerMaxVersion, "strconv.ParseUint...")
	testLine(t, "gtxna 0 Accounts a", AssemblerMaxVersion, "strconv.ParseUint...")
	testLine(t, "txn ABC", 2, "txn unknown arg: ABC")
	testLine(t, "gtxn 0 ABC", 2, "gtxn unknown arg: ABC")
	testLine(t, "gtxn a ABC", 2, "strconv.ParseUint...")
	testLine(t, "txn Accounts", AssemblerMaxVersion, "found txna field Accounts in txn op")
	testLine(t, "txn Accounts", 1, "found txna field Accounts in txn op")
	testLine(t, "txn Accounts 0", AssemblerMaxVersion, "")
	testLine(t, "gtxn 0 Accounts", AssemblerMaxVersion, "found gtxna field Accounts in gtxn op")
	testLine(t, "gtxn 0 Accounts", 1, "found gtxna field Accounts in gtxn op")
	testLine(t, "gtxn 0 Accounts 1", AssemblerMaxVersion, "")
}

func TestAssembleGlobal(t *testing.T) {
	testLine(t, "global", AssemblerMaxVersion, "global expects one argument")
	testLine(t, "global a", AssemblerMaxVersion, "global unknown arg: a")
}

func TestAssembleDefault(t *testing.T) {
	source := `byte 0x1122334455
int 1
+
// comment
`
	testProg(t, source, AssemblerMaxVersion, expect{3, "+ arg 0 wanted type uint64 got []byte"})
}

// mutateProgVersion replaces version (first two symbols) in hex-encoded program
func mutateProgVersion(version uint64, prog string) string {
	return fmt.Sprintf("%02x%s", version, prog[2:])
}

func TestOpUint(t *testing.T) {
	for v := uint64(1); v <= AssemblerMaxVersion; v++ {
		t.Run(fmt.Sprintf("v=%d", v), func(t *testing.T) {
			ops := OpStream{Version: v}
			ops.Uint(0xcafebabe)
			prog := ops.prependCBlocks()
			require.NotNil(t, prog)
			s := hex.EncodeToString(prog)
			expected := mutateProgVersion(v, "012001bef5fad70c22")
			require.Equal(t, expected, s)
		})
	}
}

func TestOpUint64(t *testing.T) {
	t.Parallel()
	for v := uint64(1); v <= AssemblerMaxVersion; v++ {
		t.Run(fmt.Sprintf("v=%d", v), func(t *testing.T) {
			t.Parallel()
			ops := OpStream{Version: v}
			ops.Uint(0xcafebabecafebabe)
			prog := ops.prependCBlocks()
			require.NotNil(t, prog)
			s := hex.EncodeToString(prog)
			require.Equal(t, mutateProgVersion(v, "012001bef5fad7ecd7aeffca0122"), s)
		})
	}
}

func TestOpBytes(t *testing.T) {
	t.Parallel()
	for v := uint64(1); v <= AssemblerMaxVersion; v++ {
		t.Run(fmt.Sprintf("v=%d", v), func(t *testing.T) {
			ops := OpStream{Version: v}
			ops.ByteLiteral([]byte("abcdef"))
			prog := ops.prependCBlocks()
			require.NotNil(t, prog)
			s := hex.EncodeToString(prog)
			require.Equal(t, mutateProgVersion(v, "0126010661626364656628"), s)
		})
	}
}

func TestAssembleInt(t *testing.T) {
	t.Parallel()
	for v := uint64(1); v <= AssemblerMaxVersion; v++ {
		t.Run(fmt.Sprintf("v=%d", v), func(t *testing.T) {
			text := "int 0xcafebabe"
			ops, err := AssembleStringWithVersion(text, v)
			require.NoError(t, err)
			s := hex.EncodeToString(ops.Program)
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
		`byte "\x61\x62\x63\x64\x65\x66"`,
		`byte "abcdef"`,
	}
	for v := uint64(1); v <= AssemblerMaxVersion; v++ {
		t.Run(fmt.Sprintf("v=%d", v), func(t *testing.T) {
			for _, vi := range variations {
				ops, err := AssembleStringWithVersion(vi, v)
				require.NoError(t, err)
				s := hex.EncodeToString(ops.Program)
				require.Equal(t, mutateProgVersion(v, "0126010661626364656628"), s)
			}

		})
	}
}

func TestAssembleBytesString(t *testing.T) {
	for v := uint64(1); v <= AssemblerMaxVersion; v++ {
		t.Run(fmt.Sprintf("v=%d", v), func(t *testing.T) {
			testLine(t, `byte "foo bar"`, v, "")
			testLine(t, `byte "foo bar // not a comment"`, v, "")
		})
	}
}

func TestFieldsFromLine(t *testing.T) {
	line := "op arg"
	fields := fieldsFromLine(line)
	require.Equal(t, 2, len(fields))
	require.Equal(t, "op", fields[0])
	require.Equal(t, "arg", fields[1])

	line = "op arg // test"
	fields = fieldsFromLine(line)
	require.Equal(t, 2, len(fields))
	require.Equal(t, "op", fields[0])
	require.Equal(t, "arg", fields[1])

	line = "op base64 ABC//=="
	fields = fieldsFromLine(line)
	require.Equal(t, 3, len(fields))
	require.Equal(t, "op", fields[0])
	require.Equal(t, "base64", fields[1])
	require.Equal(t, "ABC//==", fields[2])

	line = "op base64 ABC/=="
	fields = fieldsFromLine(line)
	require.Equal(t, 3, len(fields))
	require.Equal(t, "op", fields[0])
	require.Equal(t, "base64", fields[1])
	require.Equal(t, "ABC/==", fields[2])

	line = "op base64 ABC/== /"
	fields = fieldsFromLine(line)
	require.Equal(t, 4, len(fields))
	require.Equal(t, "op", fields[0])
	require.Equal(t, "base64", fields[1])
	require.Equal(t, "ABC/==", fields[2])
	require.Equal(t, "/", fields[3])

	line = "op base64 ABC/== //"
	fields = fieldsFromLine(line)
	require.Equal(t, 3, len(fields))
	require.Equal(t, "op", fields[0])
	require.Equal(t, "base64", fields[1])
	require.Equal(t, "ABC/==", fields[2])

	line = "op base64 ABC//== //"
	fields = fieldsFromLine(line)
	require.Equal(t, 3, len(fields))
	require.Equal(t, "op", fields[0])
	require.Equal(t, "base64", fields[1])
	require.Equal(t, "ABC//==", fields[2])

	line = "op b64 ABC//== //"
	fields = fieldsFromLine(line)
	require.Equal(t, 3, len(fields))
	require.Equal(t, "op", fields[0])
	require.Equal(t, "b64", fields[1])
	require.Equal(t, "ABC//==", fields[2])

	line = "op b64(ABC//==) // comment"
	fields = fieldsFromLine(line)
	require.Equal(t, 2, len(fields))
	require.Equal(t, "op", fields[0])
	require.Equal(t, "b64(ABC//==)", fields[1])

	line = "op base64(ABC//==) // comment"
	fields = fieldsFromLine(line)
	require.Equal(t, 2, len(fields))
	require.Equal(t, "op", fields[0])
	require.Equal(t, "base64(ABC//==)", fields[1])

	line = "op b64(ABC/==) // comment"
	fields = fieldsFromLine(line)
	require.Equal(t, 2, len(fields))
	require.Equal(t, "op", fields[0])
	require.Equal(t, "b64(ABC/==)", fields[1])

	line = "op base64(ABC/==) // comment"
	fields = fieldsFromLine(line)
	require.Equal(t, 2, len(fields))
	require.Equal(t, "op", fields[0])
	require.Equal(t, "base64(ABC/==)", fields[1])

	line = "base64(ABC//==)"
	fields = fieldsFromLine(line)
	require.Equal(t, 1, len(fields))
	require.Equal(t, "base64(ABC//==)", fields[0])

	line = "b(ABC//==)"
	fields = fieldsFromLine(line)
	require.Equal(t, 1, len(fields))
	require.Equal(t, "b(ABC", fields[0])

	line = "b(ABC//==) //"
	fields = fieldsFromLine(line)
	require.Equal(t, 1, len(fields))
	require.Equal(t, "b(ABC", fields[0])

	line = "b(ABC ==) //"
	fields = fieldsFromLine(line)
	require.Equal(t, 2, len(fields))
	require.Equal(t, "b(ABC", fields[0])
	require.Equal(t, "==)", fields[1])

	line = "op base64 ABC)"
	fields = fieldsFromLine(line)
	require.Equal(t, 3, len(fields))
	require.Equal(t, "op", fields[0])
	require.Equal(t, "base64", fields[1])
	require.Equal(t, "ABC)", fields[2])

	line = "op base64 ABC) // comment"
	fields = fieldsFromLine(line)
	require.Equal(t, 3, len(fields))
	require.Equal(t, "op", fields[0])
	require.Equal(t, "base64", fields[1])
	require.Equal(t, "ABC)", fields[2])

	line = "op base64 ABC//) // comment"
	fields = fieldsFromLine(line)
	require.Equal(t, 3, len(fields))
	require.Equal(t, "op", fields[0])
	require.Equal(t, "base64", fields[1])
	require.Equal(t, "ABC//)", fields[2])

	line = `op "test"`
	fields = fieldsFromLine(line)
	require.Equal(t, 2, len(fields))
	require.Equal(t, "op", fields[0])
	require.Equal(t, `"test"`, fields[1])

	line = `op "test1 test2"`
	fields = fieldsFromLine(line)
	require.Equal(t, 2, len(fields))
	require.Equal(t, "op", fields[0])
	require.Equal(t, `"test1 test2"`, fields[1])

	line = `op "test1 test2" // comment`
	fields = fieldsFromLine(line)
	require.Equal(t, 2, len(fields))
	require.Equal(t, "op", fields[0])
	require.Equal(t, `"test1 test2"`, fields[1])

	line = `op "test1 test2 // not a comment"`
	fields = fieldsFromLine(line)
	require.Equal(t, 2, len(fields))
	require.Equal(t, "op", fields[0])
	require.Equal(t, `"test1 test2 // not a comment"`, fields[1])

	line = `op "test1 test2 // not a comment" // comment`
	fields = fieldsFromLine(line)
	require.Equal(t, 2, len(fields))
	require.Equal(t, "op", fields[0])
	require.Equal(t, `"test1 test2 // not a comment"`, fields[1])

	line = `op "test1 test2 // not a comment" // comment`
	fields = fieldsFromLine(line)
	require.Equal(t, 2, len(fields))
	require.Equal(t, "op", fields[0])
	require.Equal(t, `"test1 test2 // not a comment"`, fields[1])

	line = `op "test1 test2" //`
	fields = fieldsFromLine(line)
	require.Equal(t, 2, len(fields))
	require.Equal(t, "op", fields[0])
	require.Equal(t, `"test1 test2"`, fields[1])

	line = `op "test1 test2"//`
	fields = fieldsFromLine(line)
	require.Equal(t, 2, len(fields))
	require.Equal(t, "op", fields[0])
	require.Equal(t, `"test1 test2"`, fields[1])

	line = `op "test1 test2` // non-terminated string literal
	fields = fieldsFromLine(line)
	require.Equal(t, 2, len(fields))
	require.Equal(t, "op", fields[0])
	require.Equal(t, `"test1 test2`, fields[1])

	line = `op "test1 test2\"` // non-terminated string literal
	fields = fieldsFromLine(line)
	require.Equal(t, 2, len(fields))
	require.Equal(t, "op", fields[0])
	require.Equal(t, `"test1 test2\"`, fields[1])

	line = `op \"test1 test2\"` // not a string literal
	fields = fieldsFromLine(line)
	require.Equal(t, 3, len(fields))
	require.Equal(t, "op", fields[0])
	require.Equal(t, `\"test1`, fields[1])
	require.Equal(t, `test2\"`, fields[2])

	line = `"test1 test2"`
	fields = fieldsFromLine(line)
	require.Equal(t, 1, len(fields))
	require.Equal(t, `"test1 test2"`, fields[0])

	line = `\"test1 test2"`
	fields = fieldsFromLine(line)
	require.Equal(t, 2, len(fields))
	require.Equal(t, `\"test1`, fields[0])
	require.Equal(t, `test2"`, fields[1])

	line = `"" // test`
	fields = fieldsFromLine(line)
	require.Equal(t, 1, len(fields))
	require.Equal(t, `""`, fields[0])
}

func TestAssembleRejectNegJump(t *testing.T) {
	t.Parallel()
	source := `wat:
int 1
bnz wat
int 2`
	for v := uint64(1); v <= AssemblerMaxVersion; v++ {
		t.Run(fmt.Sprintf("v=%d", v), func(t *testing.T) {
			testProg(t, source, v, expect{3, "label wat is before reference but only forward jumps are allowed"})
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
	for v := uint64(1); v <= AssemblerMaxVersion; v++ {
		t.Run(fmt.Sprintf("v=%d", v), func(t *testing.T) {
			ops, err := AssembleStringWithVersion(text, v)
			require.NoError(t, err)
			s := hex.EncodeToString(ops.Program)
			require.Equal(t, mutateProgVersion(v, "01200101260320fff19644cfb2cb70426af0435cefc5613359ea8d896a2e5e76c30205d0c4cfed206af19644cfb2cb70426af0435cefc5613359ea8d896a2e5e76c30205d0c4cfff20fff19644cfb2cb70426af0435cefc5613359ea8d896a2e5e76c30205d0c4cfef2829122210122a291211"), s)
		})
	}
}

func TestAssembleRejectUnkLabel(t *testing.T) {
	t.Parallel()
	source := `int 1
bnz nowhere
int 2`
	for v := uint64(1); v <= AssemblerMaxVersion; v++ {
		t.Run(fmt.Sprintf("v=%d", v), func(t *testing.T) {
			testProg(t, source, v, expect{2, "reference to undefined label nowhere"})
		})
	}
}

func TestAssembleJumpToTheEnd(t *testing.T) {
	t.Parallel()
	source := `intcblock 1
intc 0
intc 0
bnz done
done:`
	ops, err := AssembleStringWithVersion(source, AssemblerMaxVersion)
	require.NoError(t, err)
	require.Equal(t, 9, len(ops.Program))
	expectedProgBytes := []byte("\x01\x20\x01\x01\x22\x22\x40\x00\x00")
	expectedProgBytes[0] = byte(AssemblerMaxVersion)
	require.Equal(t, expectedProgBytes, ops.Program)
}

func TestMultipleErrors(t *testing.T) {
	t.Parallel()
	source := `int 1
bnz nowhere
// comment
txn XYZ
int 2`
	for v := uint64(1); v <= AssemblerMaxVersion; v++ {
		t.Run(fmt.Sprintf("v=%d", v), func(t *testing.T) {
			testProg(t, source, v,
				expect{2, "reference to undefined label nowhere"},
				expect{4, "txn unknown arg: XYZ"})
		})
	}
}

func TestAssembleDisassemble(t *testing.T) {
	// Specifically constructed program text that should be recreated by Disassemble()
	// TODO: disassemble to int/byte psuedo-ops instead of raw intcblock/bytecblock/intc/bytec
	t.Parallel()
	text := `// version 2
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
global LatestTimestamp
global CurrentApplicationID
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
txna ApplicationArgs 0
txn NumAppArgs
txna Accounts 0
txn NumAccounts
txn ApprovalProgram
txn ClearStateProgram
txn RekeyTo
txn ConfigAsset
txn ConfigAssetTotal
txn ConfigAssetDecimals
txn ConfigAssetDefaultFrozen
txn ConfigAssetUnitName
txn ConfigAssetName
txn ConfigAssetURL
txn ConfigAssetMetadataHash
txn ConfigAssetManager
txn ConfigAssetReserve
txn ConfigAssetFreeze
txn ConfigAssetClawback
txn FreezeAsset
txn FreezeAssetAccount
txn FreezeAssetFrozen
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
	ops, err := AssembleStringWithVersion(text, AssemblerMaxVersion)
	require.NoError(t, err)
	t2, err := Disassemble(ops.Program)
	require.Equal(t, text, t2)
	require.NoError(t, err)
}

func TestAssembleDisassembleCycle(t *testing.T) {
	// Test that disassembly re-assembles to the same program bytes.
	// It disassembly won't necessarily perfectly recreate the source text, but assembling the result of Disassemble() should be the same program bytes.
	t.Parallel()

	tests := map[uint64]string{
		2: bigTestAssembleNonsenseProgram,
		1: bigTestAssembleNonsenseProgram[:strings.Index(bigTestAssembleNonsenseProgram, "dup2")],
	}

	for v, source := range tests {
		t.Run(fmt.Sprintf("v=%d", v), func(t *testing.T) {
			ops, err := AssembleStringWithVersion(source, v)
			require.NoError(t, err)
			t2, err := Disassemble(ops.Program)
			require.NoError(t, err)
			ops2, err := AssembleStringWithVersion(t2, 2)
			if err != nil {
				t.Log(t2)
			}
			require.NoError(t, err)
			require.Equal(t, ops.Program[1:], ops2.Program[1:])
		})
	}
}

func TestAssembleDisassembleErrors(t *testing.T) {
	t.Parallel()

	source := `txn Sender`
	ops, err := AssembleStringWithVersion(source, AssemblerMaxVersion)
	require.NoError(t, err)
	ops.Program[2] = 0x50 // txn field
	_, err = Disassemble(ops.Program)
	require.Error(t, err)
	require.Contains(t, err.Error(), "invalid txn arg index")

	source = `txna Accounts 0`
	ops, err = AssembleStringWithVersion(source, AssemblerMaxVersion)
	require.NoError(t, err)
	ops.Program[2] = 0x50 // txn field
	_, err = Disassemble(ops.Program)
	require.Error(t, err)
	require.Contains(t, err.Error(), "invalid txn arg index")

	source = `gtxn 0 Sender`
	ops, err = AssembleStringWithVersion(source, AssemblerMaxVersion)
	require.NoError(t, err)
	ops.Program[3] = 0x50 // txn field
	_, err = Disassemble(ops.Program)
	require.Error(t, err)
	require.Contains(t, err.Error(), "invalid txn arg index")

	source = `gtxna 0 Accounts 0`
	ops, err = AssembleStringWithVersion(source, AssemblerMaxVersion)
	require.NoError(t, err)
	ops.Program[3] = 0x50 // txn field
	_, err = Disassemble(ops.Program)
	require.Error(t, err)
	require.Contains(t, err.Error(), "invalid txn arg index")

	source = `global MinTxnFee`
	ops, err = AssembleStringWithVersion(source, AssemblerMaxVersion)
	require.NoError(t, err)
	ops.Program[2] = 0x50 // txn field
	_, err = Disassemble(ops.Program)
	require.Error(t, err)
	require.Contains(t, err.Error(), "invalid global arg index")

	ops.Program[0] = 0x11 // version
	out, err := Disassemble(ops.Program)
	require.NoError(t, err)
	require.Contains(t, out, "unsupported version")

	ops.Program[0] = 0x01 // version
	ops.Program[1] = 0xFF // first opcode
	_, err = Disassemble(ops.Program)
	require.Error(t, err)
	require.Contains(t, err.Error(), "invalid opcode")

	source = "int 0\nint 0\nasset_holding_get AssetFrozen"
	ops, err = AssembleStringWithVersion(source, AssemblerMaxVersion)
	require.NoError(t, err)
	ops.Program[7] = 0x50 // holding field
	_, err = Disassemble(ops.Program)
	require.Error(t, err)
	require.Contains(t, err.Error(), "invalid asset holding arg index")

	source = "int 0\nasset_params_get AssetTotal"
	ops, err = AssembleStringWithVersion(source, AssemblerMaxVersion)
	require.NoError(t, err)
	ops.Program[6] = 0x50 // params field
	_, err = Disassemble(ops.Program)
	require.Error(t, err)
	require.Contains(t, err.Error(), "invalid asset params arg index")

	source = "int 0\nasset_params_get AssetTotal"
	ops, err = AssembleStringWithVersion(source, AssemblerMaxVersion)
	require.NoError(t, err)
	_, err = Disassemble(ops.Program)
	require.NoError(t, err)
	ops.Program = ops.Program[0 : len(ops.Program)-1]
	_, err = Disassemble(ops.Program)
	require.Error(t, err)
	require.Contains(t, err.Error(), "unexpected asset_params_get opcode end: missing 1 bytes")

	source = "gtxna 0 Accounts 0"
	ops, err = AssembleStringWithVersion(source, AssemblerMaxVersion)
	require.NoError(t, err)
	_, err = Disassemble(ops.Program)
	require.NoError(t, err)
	ops.Program = ops.Program[0 : len(ops.Program)-2]
	_, err = Disassemble(ops.Program)
	require.Error(t, err)
	require.Contains(t, err.Error(), "unexpected gtxna opcode end: missing 2 bytes")

	source = "txna Accounts 0"
	ops, err = AssembleStringWithVersion(source, AssemblerMaxVersion)
	require.NoError(t, err)
	_, err = Disassemble(ops.Program)
	require.NoError(t, err)
	ops.Program = ops.Program[0 : len(ops.Program)-1]
	_, err = Disassemble(ops.Program)
	require.Error(t, err)
	require.Contains(t, err.Error(), "unexpected txna opcode end: missing 1 bytes")

	source = "byte 0x4141\nsubstring 0 1"
	ops, err = AssembleStringWithVersion(source, AssemblerMaxVersion)
	require.NoError(t, err)
	_, err = Disassemble(ops.Program)
	require.NoError(t, err)
	ops.Program = ops.Program[0 : len(ops.Program)-1]
	_, err = Disassemble(ops.Program)
	require.Error(t, err)
	require.Contains(t, err.Error(), "unexpected substring opcode end: missing 1 bytes")
}

func TestAssembleVersions(t *testing.T) {
	t.Parallel()
	testLine(t, "txna Accounts 0", AssemblerMaxVersion, "")
	testLine(t, "txna Accounts 0", 2, "")
	testLine(t, "txna Accounts 0", 1, "unknown opcode: txna")
}

func TestAssembleBalance(t *testing.T) {
	t.Parallel()

	source := `byte 0x00
balance
int 1
==`
	testProg(t, source, AssemblerMaxVersion, expect{2, "balance arg 0 wanted type uint64 got []byte"})
}

func TestAssembleAsset(t *testing.T) {
	t.Parallel()

	testLine(t, "asset_holding_get ABC 1", AssemblerMaxVersion, "asset_holding_get expects one argument")
	testLine(t, "asset_holding_get ABC", AssemblerMaxVersion, "asset_holding_get unknown arg: ABC")
	testLine(t, "asset_params_get ABC 1", AssemblerMaxVersion, "asset_params_get expects one argument")
	testLine(t, "asset_params_get ABC", AssemblerMaxVersion, "asset_params_get unknown arg: ABC")
}

func TestDisassembleSingleOp(t *testing.T) {
	t.Parallel()
	// test ensures no double arg_0 entries in disassembly listing
	sample := "// version 2\narg_0\n"
	ops, err := AssembleStringWithVersion(sample, AssemblerMaxVersion)
	require.NoError(t, err)
	require.Equal(t, 2, len(ops.Program))
	disassembled, err := Disassemble(ops.Program)
	require.NoError(t, err)
	require.Equal(t, sample, disassembled)
}

func TestDisassembleTxna(t *testing.T) {
	t.Parallel()
	// check txn and txna are properly disassembled
	txnSample := "// version 2\ntxn Sender\n"
	ops, err := AssembleStringWithVersion(txnSample, AssemblerMaxVersion)
	require.NoError(t, err)
	disassembled, err := Disassemble(ops.Program)
	require.NoError(t, err)
	require.Equal(t, txnSample, disassembled)

	txnaSample := "// version 2\ntxna Accounts 0\n"
	ops, err = AssembleStringWithVersion(txnaSample, AssemblerMaxVersion)
	require.NoError(t, err)
	disassembled, err = Disassemble(ops.Program)
	require.NoError(t, err)
	require.Equal(t, txnaSample, disassembled)

	txnSample2 := "// version 2\ntxn Accounts 0\n"
	ops, err = AssembleStringWithVersion(txnSample2, AssemblerMaxVersion)
	require.NoError(t, err)
	disassembled, err = Disassemble(ops.Program)
	require.NoError(t, err)
	// compare with txnaSample, not txnSample2
	require.Equal(t, txnaSample, disassembled)
}

func TestDisassembleGtxna(t *testing.T) {
	t.Parallel()
	// check gtxn and gtxna are properly disassembled
	gtxnSample := "// version 2\ngtxn 0 Sender\n"
	ops, err := AssembleStringWithVersion(gtxnSample, AssemblerMaxVersion)
	require.NoError(t, err)
	disassembled, err := Disassemble(ops.Program)
	require.NoError(t, err)
	require.Equal(t, gtxnSample, disassembled)

	gtxnaSample := "// version 2\ngtxna 0 Accounts 0\n"
	ops, err = AssembleStringWithVersion(gtxnaSample, AssemblerMaxVersion)
	require.NoError(t, err)
	disassembled, err = Disassemble(ops.Program)
	require.NoError(t, err)
	require.Equal(t, gtxnaSample, disassembled)

	gtxnSample2 := "// version 2\ngtxn 0 Accounts 0\n"
	ops, err = AssembleStringWithVersion(gtxnSample2, AssemblerMaxVersion)
	require.NoError(t, err)
	disassembled, err = Disassemble(ops.Program)
	require.NoError(t, err)
	// comapre with gtxnaSample, not gtxnSample2
	require.Equal(t, gtxnaSample, disassembled)
}

func TestDisassembleLastLabel(t *testing.T) {
	t.Parallel()

	// starting from TEAL v2 branching to the last line are legal
	for v := uint64(2); v <= AssemblerMaxVersion; v++ {
		t.Run(fmt.Sprintf("v=%d", v), func(t *testing.T) {
			source := fmt.Sprintf(`// version %d
intcblock 1
intc_0
bnz label1
label1:
`, v)
			ops, err := AssembleStringWithVersion(source, v)
			require.NoError(t, err)
			dis, err := Disassemble(ops.Program)
			require.NoError(t, err)
			require.Equal(t, source, dis)
		})
	}
}

func TestAssembleOffsets(t *testing.T) {
	t.Parallel()
	source := "err"
	ops, err := AssembleStringWithVersion(source, AssemblerMaxVersion)
	require.NoError(t, err)
	require.Equal(t, 2, len(ops.Program))
	require.Equal(t, 1, len(ops.OffsetToLine))
	// vlen
	line, ok := ops.OffsetToLine[0]
	require.False(t, ok)
	require.Equal(t, 0, line)
	// err
	line, ok = ops.OffsetToLine[1]
	require.True(t, ok)
	require.Equal(t, 0, line)

	source = `err
// comment
err
`
	ops, err = AssembleStringWithVersion(source, AssemblerMaxVersion)
	require.NoError(t, err)
	require.Equal(t, 3, len(ops.Program))
	require.Equal(t, 2, len(ops.OffsetToLine))
	// vlen
	line, ok = ops.OffsetToLine[0]
	require.False(t, ok)
	require.Equal(t, 0, line)
	// err 1
	line, ok = ops.OffsetToLine[1]
	require.True(t, ok)
	require.Equal(t, 0, line)
	// err 2
	line, ok = ops.OffsetToLine[2]
	require.True(t, ok)
	require.Equal(t, 2, line)

	source = `err
bnz label1
err
label1:
err
`
	ops, err = AssembleStringWithVersion(source, AssemblerMaxVersion)
	require.NoError(t, err)
	require.Equal(t, 7, len(ops.Program))
	require.Equal(t, 4, len(ops.OffsetToLine))
	// vlen
	line, ok = ops.OffsetToLine[0]
	require.False(t, ok)
	require.Equal(t, 0, line)
	// err 1
	line, ok = ops.OffsetToLine[1]
	require.True(t, ok)
	require.Equal(t, 0, line)
	// bnz
	line, ok = ops.OffsetToLine[2]
	require.True(t, ok)
	require.Equal(t, 1, line)
	// bnz byte 1
	line, ok = ops.OffsetToLine[3]
	require.False(t, ok)
	require.Equal(t, 0, line)
	// bnz byte 2
	line, ok = ops.OffsetToLine[4]
	require.False(t, ok)
	require.Equal(t, 0, line)
	// err 2
	line, ok = ops.OffsetToLine[5]
	require.True(t, ok)
	require.Equal(t, 2, line)
	// err 3
	line, ok = ops.OffsetToLine[6]
	require.True(t, ok)
	require.Equal(t, 4, line)

	source = `int 0
// comment
!
`
	ops, err = AssembleStringWithVersion(source, AssemblerMaxVersion)
	require.NoError(t, err)
	require.Equal(t, 6, len(ops.Program))
	require.Equal(t, 2, len(ops.OffsetToLine))
	// vlen
	line, ok = ops.OffsetToLine[0]
	require.False(t, ok)
	require.Equal(t, 0, line)
	// int 0
	line, ok = ops.OffsetToLine[4]
	require.True(t, ok)
	require.Equal(t, 0, line)
	// !
	line, ok = ops.OffsetToLine[5]
	require.True(t, ok)
	require.Equal(t, 2, line)
}

func TestHasStatefulOps(t *testing.T) {
	t.Parallel()
	source := "int 1"
	ops, err := AssembleStringWithVersion(source, AssemblerMaxVersion)
	require.NoError(t, err)
	has, err := HasStatefulOps(ops.Program)
	require.NoError(t, err)
	require.False(t, has)

	source = `int 1
int 1
app_opted_in
err
`
	ops, err = AssembleStringWithVersion(source, AssemblerMaxVersion)
	require.NoError(t, err)
	has, err = HasStatefulOps(ops.Program)
	require.NoError(t, err)
	require.True(t, has)
}

func TestStringLiteralParsing(t *testing.T) {
	t.Parallel()
	s := `"test"`
	e := []byte(`test`)
	result, err := parseStringLiteral(s)
	require.NoError(t, err)
	require.Equal(t, e, result)

	s = `"test\n"`
	e = []byte(`test
`)
	result, err = parseStringLiteral(s)
	require.NoError(t, err)
	require.Equal(t, e, result)

	s = `"test\x0a"`
	e = []byte(`test
`)
	result, err = parseStringLiteral(s)
	require.NoError(t, err)
	require.Equal(t, e, result)

	s = `"test\n\t\""`
	e = []byte(`test
	"`)
	result, err = parseStringLiteral(s)
	require.NoError(t, err)
	require.Equal(t, e, result)

	s = `"test\ra"`
	e = []byte("test\x0da")
	result, err = parseStringLiteral(s)
	require.NoError(t, err)
	require.Equal(t, e, result)

	s = `"test\\"`
	e = []byte(`test\`)
	result, err = parseStringLiteral(s)
	require.NoError(t, err)
	require.Equal(t, e, result)

	s = `"test 123"`
	e = []byte(`test 123`)
	result, err = parseStringLiteral(s)
	require.NoError(t, err)
	require.Equal(t, e, result)

	s = `"\x74\x65\x73\x74\x31\x32\x33"`
	e = []byte(`test123`)
	result, err = parseStringLiteral(s)
	require.NoError(t, err)
	require.Equal(t, e, result)

	s = `""`
	e = []byte("")
	result, err = parseStringLiteral(s)
	require.NoError(t, err)
	require.Equal(t, e, result)

	s = `"test`
	result, err = parseStringLiteral(s)
	require.EqualError(t, err, "no quotes")
	require.Nil(t, result)

	s = `test`
	result, err = parseStringLiteral(s)
	require.EqualError(t, err, "no quotes")
	require.Nil(t, result)

	s = `test"`
	result, err = parseStringLiteral(s)
	require.EqualError(t, err, "no quotes")
	require.Nil(t, result)

	s = `"test\"`
	result, err = parseStringLiteral(s)
	require.EqualError(t, err, "non-terminated escape seq")
	require.Nil(t, result)

	s = `"test\x\"`
	result, err = parseStringLiteral(s)
	require.EqualError(t, err, "escape seq inside hex number")
	require.Nil(t, result)

	s = `"test\a"`
	result, err = parseStringLiteral(s)
	require.EqualError(t, err, "invalid escape seq \\a")
	require.Nil(t, result)

	s = `"test\x10\x1"`
	result, err = parseStringLiteral(s)
	require.EqualError(t, err, "non-terminated hex seq")
	require.Nil(t, result)
}

func TestPragmaStream(t *testing.T) {
	t.Parallel()
	for v := uint64(1); v <= AssemblerMaxVersion; v++ {
		text := fmt.Sprintf("#pragma version %d", v)
		sr := strings.NewReader(text)
		ps := PragmaStream{}
		err := ps.Process(sr)
		require.NoError(t, err)
		require.Equal(t, v, ps.Version)
	}

	text := `#pragma version 100`
	sr := strings.NewReader(text)
	ps := PragmaStream{}
	err := ps.Process(sr)
	require.Error(t, err)
	require.Contains(t, err.Error(), "1: unsupported version: 100")
	require.Equal(t, uint64(0), ps.Version)

	text = `#pragma version 0`
	sr = strings.NewReader(text)
	ps = PragmaStream{}
	err = ps.Process(sr)
	require.Error(t, err)
	require.Contains(t, err.Error(), "1: unsupported version: 0")
	require.Equal(t, uint64(0), ps.Version)

	text = `#pragma version a`
	sr = strings.NewReader(text)
	ps = PragmaStream{}
	err = ps.Process(sr)
	require.Error(t, err)
	require.Contains(t, err.Error(), "1: strconv.ParseUint")
	require.Equal(t, uint64(0), ps.Version)

	text = `#pragmas version 1`
	sr = strings.NewReader(text)
	ps = PragmaStream{}
	err = ps.Process(sr)
	require.Error(t, err)
	require.Contains(t, err.Error(), "1: invalid syntax")
	require.Equal(t, uint64(0), ps.Version)

	text = `
#pragma version a`
	sr = strings.NewReader(text)
	ps = PragmaStream{}
	err = ps.Process(sr)
	require.Error(t, err)
	require.Contains(t, err.Error(), "2: #pragma version is only allowed on 1st line")
	require.Equal(t, uint64(0), ps.Version)

	text = `#pragma version 1
#pragma version 2`
	sr = strings.NewReader(text)
	ps = PragmaStream{}
	err = ps.Process(sr)
	require.Error(t, err)
	require.Contains(t, err.Error(), "2: #pragma version is only allowed on 1st line")
	require.Equal(t, uint64(1), ps.Version)

	text = `#pragma version 1
#pragma run-mode 2`
	sr = strings.NewReader(text)
	ps = PragmaStream{}
	err = ps.Process(sr)
	require.Error(t, err)
	require.Contains(t, err.Error(), "2: unsupported pragma directive: run-mode")
	require.Equal(t, uint64(1), ps.Version)

	text = `#pragma versions`
	sr = strings.NewReader(text)
	ps = PragmaStream{}
	err = ps.Process(sr)
	require.Error(t, err)
	require.Contains(t, err.Error(), "1: unsupported pragma directive: versions")
	require.Equal(t, uint64(0), ps.Version)

	text = `# pragmas version 1`
	sr = strings.NewReader(text)
	ps = PragmaStream{}
	err = ps.Process(sr)
	require.NoError(t, err)
	require.Equal(t, uint64(0), ps.Version)

	text = `
# pragmas version 1`
	sr = strings.NewReader(text)
	ps = PragmaStream{}
	err = ps.Process(sr)
	require.NoError(t, err)
	require.Equal(t, uint64(0), ps.Version)

	text = `#pragma`
	sr = strings.NewReader(text)
	ps = PragmaStream{}
	err = ps.Process(sr)
	require.Error(t, err)
	require.Contains(t, err.Error(), "1: empty pragma")
	require.Equal(t, uint64(0), ps.Version)

	text = `#pragma version`
	sr = strings.NewReader(text)
	ps = PragmaStream{}
	err = ps.Process(sr)
	require.Error(t, err)
	require.Contains(t, err.Error(), "1: no version")
	require.Equal(t, uint64(0), ps.Version)
}

func TestAssemblePragmaVersion(t *testing.T) {
	t.Parallel()
	text := `#pragma version 1
int 1
`
	ops, err := AssembleStringWithVersion(text, 1)
	require.NoError(t, err)
	ops1, err := AssembleStringWithVersion("int 1", 1)
	require.NoError(t, err)
	require.Equal(t, ops1.Program, ops.Program)

	_, err = AssembleStringWithVersion(text, 0)
	require.Error(t, err)
	require.Contains(t, err.Error(), "version mismatch")

	_, err = AssembleStringWithVersion(text, 2)
	require.Error(t, err)
	require.Contains(t, err.Error(), "version mismatch")

	ops, err = AssembleStringWithVersion(text, assemblerNoVersion)
	require.NoError(t, err)
	require.Equal(t, ops1.Program, ops.Program)

	text = `#pragma version 2
int 1
`
	ops, err = AssembleStringWithVersion(text, 2)
	require.NoError(t, err)
	ops2, err := AssembleStringWithVersion("int 1", 2)
	require.NoError(t, err)
	require.Equal(t, ops2.Program, ops.Program)

	_, err = AssembleStringWithVersion(text, 0)
	require.Error(t, err)
	require.Contains(t, err.Error(), "version mismatch")

	_, err = AssembleStringWithVersion(text, 1)
	require.Error(t, err)
	require.Contains(t, err.Error(), "version mismatch")

	ops, err = AssembleStringWithVersion(text, assemblerNoVersion)
	require.NoError(t, err)
	require.Equal(t, ops2.Program, ops.Program)

	// check if no version it defaults to TEAL v1
	text = `byte "test"
len
`
	ops, err = AssembleStringWithVersion(text, assemblerNoVersion)
	require.NoError(t, err)
	ops1, err = AssembleStringWithVersion(text, 1)
	require.Equal(t, ops1.Program, ops.Program)
	require.NoError(t, err)
	ops2, err = AssembleString(text)
	require.NoError(t, err)
	require.Equal(t, ops2.Program, ops.Program)

	_, err = AssembleString("#pragma unk")
	require.Error(t, err)
	require.Contains(t, err.Error(), "1: unsupported pragma directive: unk")

}

func TestAssembleConstants(t *testing.T) {
	t.Parallel()
	for v := uint64(1); v <= AssemblerMaxVersion; v++ {
		t.Run(fmt.Sprintf("v=%d", v), func(t *testing.T) {
			testLine(t, "intc 1", v, "intc 1 is not defined")
			testProg(t, "intcblock 1 2\nintc 1", v)

			testLine(t, "bytec 1", v, "bytec 1 is not defined")
			testProg(t, "bytecblock 0x01 0x02\nbytec 1", v)
		})
	}
}

func TestErrShortBytecblock(t *testing.T) {
	text := `intcblock 0x1234567812345678 0x1234567812345671 0x1234567812345672 0x1234567812345673 4 5 6 7 8`
	ops, err := AssembleStringWithVersion(text, 1)
	require.NoError(t, err)
	_, _, err = parseIntcblock(ops.Program, 0)
	require.Equal(t, err, errShortIntcblock)

	var cx evalContext
	cx.program = ops.Program
	checkIntConstBlock(&cx)
	require.Equal(t, cx.err, errShortIntcblock)
}

func TestBranchAssemblyTypeCheck(t *testing.T) {
	text := `
	int 0             // current app id  [0]
	int 1             // key  [1, 0]
	itob              // ["\x01", 0]
	app_global_get_ex // [0|1, x]
	pop               // [x]
	btoi              // [n]
`

	sr := strings.NewReader(text)
	ops := OpStream{Version: AssemblerMaxVersion}
	err := ops.assemble(sr)
	require.NoError(t, err)
	require.Empty(t, ops.Warnings)

	text = `
	int 0             // current app id  [0]
	int 1             // key  [1, 0]
	itob              // ["\x01", 0]
	app_global_get_ex // [0|1, x]
	bnz flip          // [x]
flip:                 // [x]
	btoi              // [n]
`

	sr = strings.NewReader(text)
	ops = OpStream{Version: AssemblerMaxVersion}
	err = ops.assemble(sr)
	require.NoError(t, err)
	require.Empty(t, ops.Warnings)
}
