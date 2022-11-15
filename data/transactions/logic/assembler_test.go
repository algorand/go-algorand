// Copyright (C) 2019-2022 Algorand, Inc.
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
	"regexp"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/protocol"
	"github.com/algorand/go-algorand/test/partitiontest"
)

// used by TestAssemble and others, see UPDATE PROCEDURE in TestAssemble()
const v1Nonsense = `
err
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
|
&
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
`

const v2Nonsense = v1Nonsense + `
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
#pragma typetrack false
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

const v3Nonsense = v2Nonsense + `
assert
min_balance
int 0x031337			// get bit 1, negate it, put it back
int 1
getbit
!
int 1
setbit
byte "test"			// get byte 2, increment it, put it back
int 2
getbyte
int 1
+
int 2
setbyte
swap
select
dig 2
int 1
gtxns ConfigAsset
int 2
gtxnsa Accounts 0
pushint 1000
pushbytes "john"
`

// Keep in mind, only use existing int and byte constants, or else use
// push* instead.  The idea is to not cause the *cblocks to change.
const v4Nonsense = v3Nonsense + `
int 1
pushint 2000
int 0
int 2
divmodw
callsub stuff
b next
stuff:
retsub
next:
int 1
int 2
shl
int 1
shr
sqrt
int 2
exp
int 2
expw
bitlen
b+
b-
b/
b*
b<
b>
b<=
b>=
b==
b!=
b%
b|
b&
b^
b~
int 2
bzero
gload 0 0
gloads 0
gaid 0
gaids
int 100
`

const v5Nonsense = v4Nonsense + `
app_params_get AppExtraProgramPages
cover 1
uncover 1
byte 0x0123456789abcd
extract 0 8
int 0
int 8
extract3
int 0
extract_uint64
int 0
extract_uint32
int 0
extract_uint16
log
txn Nonparticipation
gtxn 0 Nonparticipation
itxn_begin
itxn_field Sender
itxn_submit
int 1
txnas ApplicationArgs
int 0
gtxnas 0 ApplicationArgs
int 0
int 0
gtxnsas ApplicationArgs
int 0
args
int 0
loads
int 0
stores
int 32
bzero
ecdsa_pk_decompress Secp256k1
byte 0x0123456789abcd
dup
dup
ecdsa_verify Secp256k1
byte 0x0123456789abcd
dup
dup
ecdsa_pk_recover Secp256k1
itxn Sender
itxna Logs 3
`

const v6Nonsense = v5Nonsense + `
itxn_next
gitxn 4 CreatedAssetID
gitxna 3 Logs 12
int 0
dup
gloadss
byte 0x0123456789abcd
bsqrt
txn Sender
acct_params_get AcctBalance
pushint 8; pushint 8; pushint 32; divw // use pushint to prevent changes to intcblock choices
pushint 1
itxnas Logs
pushint 1
gitxnas 0 Logs
`

const boxNonsense = `
  box_create
  box_extract
  box_replace
  box_del
  box_len
  box_put
  box_get
`

const randomnessNonsense = `
pushint 0xffff
block BlkTimestamp
vrf_verify VrfAlgorand
`

const v7Nonsense = v6Nonsense + `
base64_decode URLEncoding
json_ref JSONUint64
pushint 32
bzero
ecdsa_pk_decompress Secp256r1
pushbytes 0x0123456789abcd
dup
dup
ecdsa_verify Secp256r1
sha3_256
pushbytes 0x012345
dup
dup
ed25519verify_bare
` + randomnessNonsense + `
pushbytes 0x4321
pushbytes 0x77
replace2 2
pushbytes 0x88
pushint 1
replace3
`

const switchNonsense = `
switch_label0:
pushint 1
switch switch_label0 switch_label1
switch_label1:
pushint 1
`

const matchNonsense = `
match_label0:
pushints 1 2 1
match match_label0 match_label1
match_label1:
pushbytess "1" "2" "1"
`

const v8Nonsense = v7Nonsense + switchNonsense + frameNonsense + matchNonsense + boxNonsense

const v9Nonsense = v8Nonsense + pairingNonsense

const v6Compiled = "2004010002b7a60c26050242420c68656c6c6f20776f726c6421070123456789abcd208dae2087fbba51304eb02b91f656948397a7946390e8cb70fc9ea4d95f92251d047465737400320032013202320380021234292929292b0431003101310231043105310731083109310a310b310c310d310e310f3111311231133114311533000033000133000233000433000533000733000833000933000a33000b33000c33000d33000e33000f3300113300123300133300143300152d2e01022581f8acd19181cf959a1281f8acd19181cf951a81f8acd19181cf1581f8acd191810f082209240a220b230c240d250e230f2310231123122313231418191a1b1c28171615400003290349483403350222231d4a484848482b50512a632223524100034200004322602261222704634848222862482864286548482228246628226723286828692322700048482371004848361c0037001a0031183119311b311d311e311f312023221e312131223123312431253126312731283129312a312b312c312d312e312f447825225314225427042455220824564c4d4b0222382124391c0081e80780046a6f686e2281d00f23241f880003420001892224902291922494249593a0a1a2a3a4a5a6a7a8a9aaabacadae24af3a00003b003c003d816472064e014f012a57000823810858235b235a2359b03139330039b1b200b322c01a23c1001a2323c21a23c3233e233f8120af06002a494905002a49490700b400b53a03b6b7043cb8033a0c2349c42a9631007300810881088120978101c53a8101c6003a"

const randomnessCompiled = "81ffff03d101d000"

const v7Compiled = v6Compiled + "5e005f018120af060180070123456789abcd49490501988003012345494984" +
	randomnessCompiled + "800243218001775c0280018881015d"

const boxCompiled = "b9babbbcbdbfbe"

const switchCompiled = "81018d02fff800008101"
const matchCompiled = "83030102018e02fff500008203013101320131"

const v8Compiled = v7Compiled + switchCompiled + frameCompiled + matchCompiled + boxCompiled

const v9Compiled = v8Compiled + pairingCompiled

var nonsense = map[uint64]string{
	1: v1Nonsense,
	2: v2Nonsense,
	3: v3Nonsense,
	4: v4Nonsense,
	5: v5Nonsense,
	6: v6Nonsense,
	7: v7Nonsense,
	8: v8Nonsense,
	9: v9Nonsense,
}

var compiled = map[uint64]string{
	1: "012008b7a60cf8acd19181cf959a12f8acd19181cf951af8acd19181cf15f8acd191810f01020026050212340c68656c6c6f20776f726c6421208dae2087fbba51304eb02b91f656948397a7946390e8cb70fc9ea4d95f92251d024242047465737400320032013202320328292929292a0431003101310231043105310731083109310a310b310c310d310e310f3111311231133114311533000033000133000233000433000533000733000833000933000a33000b33000c33000d33000e33000f3300113300123300133300143300152d2e0102222324252104082209240a220b230c240d250e230f2310231123122313231418191a1b1c2b1716154000032903494",
	2: "022008b7a60cf8acd19181cf959a12f8acd19181cf951af8acd19181cf15f8acd191810f01020026050212340c68656c6c6f20776f726c6421208dae2087fbba51304eb02b91f656948397a7946390e8cb70fc9ea4d95f92251d024242047465737400320032013202320328292929292a0431003101310231043105310731083109310a310b310c310d310e310f3111311231133114311533000033000133000233000433000533000733000833000933000a33000b33000c33000d33000e33000f3300113300123300133300143300152d2e0102222324252104082209240a220b230c240d250e230f2310231123122313231418191a1b1c2b171615400003290349483403350222231d4a484848482a50512a63222352410003420000432105602105612105270463484821052b62482b642b65484821052b2106662b21056721072b682b692107210570004848210771004848361c0037001a0031183119311b311d311e311f3120210721051e312131223123312431253126312731283129312a312b312c312d312e312f",
	3: "032008b7a60cf8acd19181cf959a12f8acd19181cf951af8acd19181cf15f8acd191810f01020026050212340c68656c6c6f20776f726c6421208dae2087fbba51304eb02b91f656948397a7946390e8cb70fc9ea4d95f92251d024242047465737400320032013202320328292929292a0431003101310231043105310731083109310a310b310c310d310e310f3111311231133114311533000033000133000233000433000533000733000833000933000a33000b33000c33000d33000e33000f3300113300123300133300143300152d2e0102222324252104082209240a220b230c240d250e230f2310231123122313231418191a1b1c2b171615400003290349483403350222231d4a484848482a50512a63222352410003420000432105602105612105270463484821052b62482b642b65484821052b2106662b21056721072b682b692107210570004848210771004848361c0037001a0031183119311b311d311e311f3120210721051e312131223123312431253126312731283129312a312b312c312d312e312f4478222105531421055427042106552105082106564c4d4b02210538212106391c0081e80780046a6f686e",
	4: "042004010200b7a60c26040242420c68656c6c6f20776f726c6421208dae2087fbba51304eb02b91f656948397a7946390e8cb70fc9ea4d95f92251d047465737400320032013202320380021234292929292a0431003101310231043105310731083109310a310b310c310d310e310f3111311231133114311533000033000133000233000433000533000733000833000933000a33000b33000c33000d33000e33000f3300113300123300133300143300152d2e01022581f8acd19181cf959a1281f8acd19181cf951a81f8acd19181cf1581f8acd191810f082209240a220b230c240d250e230f2310231123122313231418191a1b1c28171615400003290349483403350222231d4a484848482a50512a632223524100034200004322602261222b634848222862482864286548482228236628226724286828692422700048482471004848361c0037001a0031183119311b311d311e311f312024221e312131223123312431253126312731283129312a312b312c312d312e312f44782522531422542b2355220823564c4d4b0222382123391c0081e80780046a6f686e2281d00f24231f880003420001892223902291922394239593a0a1a2a3a4a5a6a7a8a9aaabacadae23af3a00003b003c003d8164",
	5: "052004010002b7a60c26050242420c68656c6c6f20776f726c6421070123456789abcd208dae2087fbba51304eb02b91f656948397a7946390e8cb70fc9ea4d95f92251d047465737400320032013202320380021234292929292b0431003101310231043105310731083109310a310b310c310d310e310f3111311231133114311533000033000133000233000433000533000733000833000933000a33000b33000c33000d33000e33000f3300113300123300133300143300152d2e01022581f8acd19181cf959a1281f8acd19181cf951a81f8acd19181cf1581f8acd191810f082209240a220b230c240d250e230f2310231123122313231418191a1b1c28171615400003290349483403350222231d4a484848482b50512a632223524100034200004322602261222704634848222862482864286548482228246628226723286828692322700048482371004848361c0037001a0031183119311b311d311e311f312023221e312131223123312431253126312731283129312a312b312c312d312e312f447825225314225427042455220824564c4d4b0222382124391c0081e80780046a6f686e2281d00f23241f880003420001892224902291922494249593a0a1a2a3a4a5a6a7a8a9aaabacadae24af3a00003b003c003d816472064e014f012a57000823810858235b235a2359b03139330039b1b200b322c01a23c1001a2323c21a23c3233e233f8120af06002a494905002a49490700b400b53a03",
	6: "06" + v6Compiled,
	7: "07" + v7Compiled,
	8: "08" + v8Compiled,
	9: "09" + v9Compiled,
}

func pseudoOp(opcode string) bool {
	// We don't test every combination of
	// intcblock,bytecblock,intc*,bytec*,arg* here.  Not all of
	// these are truly pseudops, but it seems a good name.
	return strings.HasPrefix(opcode, "int") ||
		strings.HasPrefix(opcode, "byte") ||
		strings.HasPrefix(opcode, "arg")
}

// Check that assembly output is stable across time.
func TestAssemble(t *testing.T) {
	partitiontest.PartitionTest(t)

	// UPDATE PROCEDURE:
	// Run test. It should pass. If test is not passing, do not change this test, fix the assembler first.
	// Extend this test program text. Append instructions to the end so that the program byte hex is visually similar and also simply extended by some new bytes,
	// and so that version-dependent tests pass.
	// Copy hex string from failing test output into source.
	// Run test. It should pass.
	//
	// This doesn't have to be a sensible program to run, it just has to compile.

	t.Parallel()
	require.LessOrEqual(t, LogicVersion, len(nonsense)) // Allow nonsense for future versions
	for v := uint64(2); v <= AssemblerMaxVersion; v++ {
		t.Run(fmt.Sprintf("v=%d", v), func(t *testing.T) {
			for _, spec := range OpSpecs {
				// Make sure our nonsense covers the ops.
				hasOp, err := regexp.MatchString("\\s"+regexp.QuoteMeta(spec.Name)+"\\s", nonsense[v])
				require.NoError(t, err)
				if !hasOp &&
					!pseudoOp(spec.Name) && spec.Version <= v {
					t.Errorf("v%d nonsense test should contain op %v", v, spec.Name)
				}
			}

			ops := testProg(t, nonsense[v], v)
			// check that compilation is stable over
			// time. we must assemble to the same bytes
			// this month that we did last month.
			bytecode, ok := compiled[v]
			require.True(t, ok, "Need v%d bytecode", v)
			expectedBytes, _ := hex.DecodeString(bytecode)
			require.NotEmpty(t, expectedBytes)
			// the hex is for convenience if the program has been changed. the
			// hex string can be copy pasted back in as a new expected result.
			require.Equal(t, expectedBytes, ops.Program, hex.EncodeToString(ops.Program))
		})
	}
}

var experiments = []uint64{pairingVersion}

// TestExperimental forces a conscious choice to promote "experimental" opcode
// groups. This will fail when we increment vFuture's LogicSigVersion. If we had
// intended to release the opcodes, they should have been removed from
// `experiments`.
func TestExperimental(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	futureV := config.Consensus[protocol.ConsensusFuture].LogicSigVersion
	for _, v := range experiments {
		// Allows less, so we can push something out, even before vFuture has been updated.
		require.LessOrEqual(t, futureV, v)
	}
}

func TestAssembleAlias(t *testing.T) {
	partitiontest.PartitionTest(t)

	t.Parallel()
	source1 := `txn Accounts 0  // alias to txna
pop
gtxn 0 ApplicationArgs 0 // alias to gtxna
pop
`
	ops1 := testProg(t, source1, AssemblerMaxVersion)
	ops2 := testProg(t, strings.Replace(source1, "txn", "txna", -1), AssemblerMaxVersion)

	require.Equal(t, ops1.Program, ops2.Program)
}

type Expect struct {
	l int
	s string
}

func testMatch(t testing.TB, actual, expected string) (ok bool) {
	defer func() {
		if !ok {
			t.Logf("'%s' does not match '%s'", actual, expected)
		}
	}()
	t.Helper()
	if strings.HasPrefix(expected, "...") && strings.HasSuffix(expected, "...") {
		return strings.Contains(actual, expected[3:len(expected)-3])
	} else if strings.HasPrefix(expected, "...") {
		return strings.Contains(actual+"^", expected[3:]+"^")
	} else if strings.HasSuffix(expected, "...") {
		return strings.Contains("^"+actual, "^"+expected[:len(expected)-3])
	} else {
		return expected == actual
	}
}

func assembleWithTrace(text string, ver uint64) (*OpStream, error) {
	ops := newOpStream(ver)
	ops.Trace = &strings.Builder{}
	err := ops.assemble(text)
	return &ops, err
}

func lines(s string, num int) (bool, string) {
	if num < 1 {
		return true, ""
	}
	found := 0
	for i := 0; i < len(s); i++ {
		if s[i] == '\n' {
			found++
			if found == num {
				return true, s[0 : i+1]
			}
		}
	}
	return false, s
}

func summarize(trace *strings.Builder) string {
	truncated, msg := lines(trace.String(), 50)
	if !truncated {
		return msg
	}
	return msg + "(trace truncated)\n"
}

func testProg(t testing.TB, source string, ver uint64, expected ...Expect) *OpStream {
	t.Helper()
	ops, err := assembleWithTrace(source, ver)
	if len(expected) == 0 {
		if len(ops.Errors) > 0 || err != nil || ops == nil || ops.Program == nil {
			t.Log(summarize(ops.Trace))
		}
		if len(ops.Errors) > 10 {
			ops.Errors = ops.Errors[:10] // Truncate to reasonable
		}
		require.Empty(t, ops.Errors)
		require.NoError(t, err)
		require.NotNil(t, ops)
		require.NotNil(t, ops.Program)
		// It should always be possible to Disassemble
		dis, err := Disassemble(ops.Program)
		require.NoError(t, err, source)
		// And, while the disassembly may not match input
		// exactly, the assembly of the disassembly should
		// give the same bytecode
		ops2, err := AssembleStringWithVersion(notrack(dis), ver)
		if len(ops2.Errors) > 0 || err != nil || ops2 == nil || ops2.Program == nil {
			t.Log(source)
			t.Log(dis)
		}
		require.Empty(t, ops2.Errors)
		require.NoError(t, err)
		require.Equal(t, ops.Program, ops2.Program)
	} else {
		if err == nil {
			t.Log(source)
		}
		require.Error(t, err)
		errors := ops.Errors
		for _, exp := range expected {
			if exp.l == 0 {
				// line 0 means: "must match some line"
				require.Len(t, expected, 1)
				fail := true
				for _, err := range errors {
					msg := err.Unwrap().Error()
					if testMatch(t, msg, exp.s) {
						fail = false
					}
				}
				if fail {
					t.Log(summarize(ops.Trace))
					t.FailNow()
				}
			} else {
				var found *lineError
				for _, err := range errors {
					if err.Line == exp.l {
						found = &err
						break
					}
				}
				if found == nil {
					t.Log(fmt.Sprintf("Errors: %v", errors))
				}
				require.NotNil(t, found, "Error %s was not found on line %d", exp.s, exp.l)
				msg := found.Unwrap().Error()
				if !testMatch(t, msg, exp.s) {
					t.Log(summarize(ops.Trace))
					t.FailNow()
				}
			}
		}
		require.Nil(t, ops.Program)
	}
	return ops
}

func testLine(t *testing.T, line string, ver uint64, expected string) {
	t.Helper()
	// By embedding the source line between two other lines, the
	// test for the correct line number in the error is more
	// meaningful.
	source := "int 1\n" + line + "\nint 1\n"
	if expected == "" {
		testProg(t, source, ver)
		return
	}
	testProg(t, source, ver, Expect{2, expected})
}

func TestAssembleTxna(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	testLine(t, "txna Accounts 256", AssemblerMaxVersion, "txna i beyond 255: 256")
	testLine(t, "txna ApplicationArgs 256", AssemblerMaxVersion, "txna i beyond 255: 256")
	testLine(t, "txna Sender 256", AssemblerMaxVersion, "txna unknown field: \"Sender\"")
	testLine(t, "gtxna 0 Accounts 256", AssemblerMaxVersion, "gtxna i beyond 255: 256")
	testLine(t, "gtxna 0 ApplicationArgs 256", AssemblerMaxVersion, "gtxna i beyond 255: 256")
	testLine(t, "gtxna 256 Accounts 0", AssemblerMaxVersion, "gtxna t beyond 255: 256")
	testLine(t, "gtxna 0 Sender 256", AssemblerMaxVersion, "gtxna unknown field: \"Sender\"")
	testLine(t, "gtxna ApplicationArgs 0 255", AssemblerMaxVersion, "gtxna can only use \"ApplicationArgs\" as immediate 2")
	testLine(t, "gtxna 0 255 ApplicationArgs", AssemblerMaxVersion, "gtxna can only use \"255\" as immediate 1 or 3")

	testLine(t, "txn Accounts 256", AssemblerMaxVersion, "txn i beyond 255: 256")
	testLine(t, "txn ApplicationArgs 256", AssemblerMaxVersion, "txn i beyond 255: 256")
	testLine(t, "txn 255 ApplicationArgs", AssemblerMaxVersion, "txn with 2 immediates can only use \"255\" as immediate 2")
	testLine(t, "txn Sender 256", AssemblerMaxVersion, "\"Sender\" field of txn can only be used with 1 immediate")
	testLine(t, "gtxn 0 Accounts 256", AssemblerMaxVersion, "gtxn i beyond 255: 256")
	testLine(t, "gtxn 0 ApplicationArgs 256", AssemblerMaxVersion, "gtxn i beyond 255: 256")
	testLine(t, "gtxn 256 Accounts 0", AssemblerMaxVersion, "gtxn t beyond 255: 256")
	testLine(t, "gtxn 0 Sender 256", AssemblerMaxVersion, "\"Sender\" field of gtxn can only be used with 2 immediates")
	testLine(t, "gtxn ApplicationArgs 0 255", AssemblerMaxVersion, "gtxn with 3 immediates can only use \"ApplicationArgs\" as immediate 2")
	testLine(t, "gtxn 0 255 ApplicationArgs", AssemblerMaxVersion, "gtxn with 3 immediates can only use \"255\" as immediate 1 or 3")

	testLine(t, "txn Accounts 0", 1, "txn opcode with 2 immediates was introduced in v2")
	testLine(t, "txn Accounts 0 1", 2, "txn expects 1 or 2 immediate arguments")
	testLine(t, "txna Accounts 0 1", AssemblerMaxVersion, "txna expects 2 immediate arguments")
	testLine(t, "txn Accounts 0 1", AssemblerMaxVersion, "txn expects 1 or 2 immediate arguments")
	testLine(t, "txnas Accounts 1", AssemblerMaxVersion, "txnas expects 1 immediate argument")
	testLine(t, "txna Accounts a", AssemblerMaxVersion, "txna unable to parse...")
	testLine(t, "txn Accounts a", AssemblerMaxVersion, "txn unable to parse...")
	testLine(t, "gtxn 0 Sender 0", 1, "gtxn opcode with 3 immediates was introduced in v2")
	testLine(t, "gtxn 0 Sender 1 2", 2, "gtxn expects 2 or 3 immediate arguments")
	testLine(t, "gtxna 0 Accounts 1 2", AssemblerMaxVersion, "gtxna expects 3 immediate arguments")
	testLine(t, "gtxna a Accounts 0", AssemblerMaxVersion, "gtxna unable to parse...")
	testLine(t, "gtxna 0 Accounts a", AssemblerMaxVersion, "gtxna unable to parse...")

	testLine(t, "gtxn 0 Accounts 1 2", AssemblerMaxVersion, "gtxn expects 2 or 3 immediate arguments")
	testLine(t, "gtxn a Accounts 0", AssemblerMaxVersion, "gtxn unable to parse...")
	testLine(t, "gtxn 0 Accounts a", AssemblerMaxVersion, "gtxn unable to parse...")

	testLine(t, "gtxnas Accounts 1 2", AssemblerMaxVersion, "gtxnas expects 2 immediate arguments")
	testLine(t, "txn ABC", 2, "txn unknown field: \"ABC\"")
	testLine(t, "gtxn 0 ABC", 2, "gtxn unknown field: \"ABC\"")
	testLine(t, "gtxn a ABC", 2, "gtxn unable to parse...")
	// For now not going to additionally report version issue until version is only problem
	testLine(t, "txn Accounts", 1, "\"Accounts\" field of txn can only be used with 2 immediates")
	testLine(t, "txn Accounts", AssemblerMaxVersion, "\"Accounts\" field of txn can only be used with 2 immediates")
	testLine(t, "txn Accounts 0", AssemblerMaxVersion, "")
	testLine(t, "gtxn 0 Accounts", AssemblerMaxVersion, "\"Accounts\" field of gtxn can only be used with 3 immediates")
	testLine(t, "gtxn 0 Accounts", 1, "\"Accounts\" field of gtxn can only be used with 3 immediates")
	testLine(t, "gtxn 0 Accounts 1", AssemblerMaxVersion, "")
}

func TestAssembleGlobal(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	testLine(t, "global", AssemblerMaxVersion, "global expects 1 immediate argument")
	testLine(t, "global a", AssemblerMaxVersion, "global unknown field: \"a\"")
	testProg(t, "global MinTxnFee; int 2; +", AssemblerMaxVersion)
	testProg(t, "global ZeroAddress; byte 0x12; concat; len", AssemblerMaxVersion)
	testProg(t, "global MinTxnFee; byte 0x12; concat", AssemblerMaxVersion,
		Expect{1, "concat arg 0 wanted type []byte..."})
	testProg(t, "int 2; global ZeroAddress; +", AssemblerMaxVersion,
		Expect{1, "+ arg 1 wanted type uint64..."})
}

func TestAssembleDefault(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	source := `byte 0x1122334455
int 1
+
// comment
`
	testProg(t, source, AssemblerMaxVersion, Expect{3, "+ arg 0 wanted type uint64 got []byte"})
}

// mutateProgVersion replaces version (first two symbols) in hex-encoded program
func mutateProgVersion(version uint64, prog string) string {
	return fmt.Sprintf("%02x%s", version, prog[2:])
}

func TestOpUint(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	for v := uint64(1); v <= AssemblerMaxVersion; v++ {
		t.Run(fmt.Sprintf("v=%d", v), func(t *testing.T) {
			ops := newOpStream(v)
			ops.IntLiteral(0xcafebabe)
			prog := ops.prependCBlocks()
			require.NotNil(t, prog)
			s := hex.EncodeToString(prog)
			expected := mutateProgVersion(v, "012001bef5fad70c22")
			require.Equal(t, expected, s)
		})
	}
}

func TestOpUint64(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	for v := uint64(1); v <= AssemblerMaxVersion; v++ {
		t.Run(fmt.Sprintf("v=%d", v), func(t *testing.T) {
			ops := newOpStream(v)
			ops.IntLiteral(0xcafebabecafebabe)
			prog := ops.prependCBlocks()
			require.NotNil(t, prog)
			s := hex.EncodeToString(prog)
			require.Equal(t, mutateProgVersion(v, "012001bef5fad7ecd7aeffca0122"), s)
		})
	}
}

func TestOpBytes(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	for v := uint64(1); v <= AssemblerMaxVersion; v++ {
		t.Run(fmt.Sprintf("v=%d", v), func(t *testing.T) {
			ops := newOpStream(v)
			ops.ByteLiteral([]byte("abcdef"))
			prog := ops.prependCBlocks()
			require.NotNil(t, prog)
			s := hex.EncodeToString(prog)
			require.Equal(t, mutateProgVersion(v, "0126010661626364656628"), s)
			testProg(t, "byte 0x7; len", v, Expect{1, "...odd length hex string"})
		})
	}
}

func TestAssembleInt(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	expectedDefaultConsts := "012001bef5fad70c22"
	expectedOptimizedConsts := "0181bef5fad70c"

	for v := uint64(1); v <= AssemblerMaxVersion; v++ {
		t.Run(fmt.Sprintf("v=%d", v), func(t *testing.T) {
			expected := expectedDefaultConsts
			if v >= optimizeConstantsEnabledVersion {
				expected = expectedOptimizedConsts
			}

			text := "int 0xcafebabe"
			ops := testProg(t, text, v)
			s := hex.EncodeToString(ops.Program)
			require.Equal(t, mutateProgVersion(v, expected), s)
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
	partitiontest.PartitionTest(t)
	t.Parallel()

	variations := []string{
		"byte b32 MFRGGZDFMY",
		"byte base32 MFRGGZDFMY",
		"byte base32  MFRGGZDFMY",
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

	expectedDefaultConsts := "0126010661626364656628"
	expectedOptimizedConsts := "018006616263646566"

	bad := [][]string{
		{"byte", "...needs byte literal argument"},
		{`byte "john" "doe"`, "...with extraneous argument"},
	}

	for v := uint64(1); v <= AssemblerMaxVersion; v++ {
		t.Run(fmt.Sprintf("v=%d", v), func(t *testing.T) {
			expected := expectedDefaultConsts
			if v >= optimizeConstantsEnabledVersion {
				expected = expectedOptimizedConsts
			}

			for _, vi := range variations {
				ops := testProg(t, vi, v)
				s := hex.EncodeToString(ops.Program)
				require.Equal(t, mutateProgVersion(v, expected), s)
				// pushbytes should take the same input
				if v >= 3 {
					testProg(t, strings.Replace(vi, "byte", "pushbytes", 1), v)
				}
			}

			for _, b := range bad {
				testProg(t, b[0], v, Expect{1, b[1]})
				// pushbytes should produce the same errors
				if v >= 3 {
					testProg(t, strings.Replace(b[0], "byte", "pushbytes", 1), v, Expect{1, b[1]})
				}
			}
		})
	}
}

func TestAssembleBytesString(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	for v := uint64(1); v <= AssemblerMaxVersion; v++ {
		t.Run(fmt.Sprintf("v=%d", v), func(t *testing.T) {
			testLine(t, `byte "foo bar"`, v, "")
			testLine(t, `byte "foo bar // not a comment"`, v, "")
		})
	}
}

func TestManualCBlocks(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	// Despite appearing twice, 500s are pushints because of manual intcblock
	ops := testProg(t, "intcblock 1; int 500; int 500; ==", AssemblerMaxVersion)
	require.Equal(t, ops.Program[4], OpsByName[ops.Version]["pushint"].Opcode)

	ops = testProg(t, "intcblock 2 3; intcblock 4 10; int 5", AssemblerMaxVersion)
	text, err := Disassemble(ops.Program)
	require.NoError(t, err)
	require.Contains(t, text, "pushint 5")

	ops = testProg(t, "intcblock 2 3; intcblock 4 10; intc_3", AssemblerMaxVersion)
	text, err = Disassemble(ops.Program)
	require.NoError(t, err)
	require.Contains(t, text, "intc_3\n") // That is, no commented value for intc_3 is shown

	// In old straight-line versions, allow mixing int and intc if the ints all
	// reference manual block.  Since conditionals do make it possible that
	// different cblocks could be in effect depending on earlier path choices,
	// maybe we should not even allow this.
	checkSame(t, 3,
		"intcblock 4 5 1; intc_0; intc_2; +; intc_1; ==",
		"intcblock 4 5 1; int 4; int 1; +; intc_1; ==",
		"intcblock 4 5 1; intc_0; int 1; +; int 5; ==")
	checkSame(t, 3,
		"bytecblock 0x44 0x55 0x4455; bytec_0; bytec_1; concat; bytec_2; ==",
		"bytecblock 0x44 0x55 0x4455; byte 0x44; bytec_1; concat; byte 0x4455; ==",
		"bytecblock 0x44 0x55 0x4455; bytec_0; byte 0x55; concat; bytec_2; ==")

	// But complain if they do not
	testProg(t, "intcblock 4; int 3;", 3, Expect{1, "int 3 used without 3 in intcblock"})
	testProg(t, "bytecblock 0x44; byte 0x33;", 3, Expect{1, "byte/addr/method used without value in bytecblock"})

	// Or if the ref comes before the constant block, even if they match
	testProg(t, "int 5; intcblock 4;", 3, Expect{1, "intcblock following int"})
	testProg(t, "int 4; intcblock 4;", 3, Expect{1, "intcblock following int"})
	testProg(t, "addr RWXCBB73XJITATVQFOI7MVUUQOL2PFDDSDUMW4H4T2SNSX4SEUOQ2MM7F4; bytecblock 0x44", 3, Expect{1, "bytecblock following byte/addr/method"})

	// But we can't complain precisely once backjumps are allowed, so we force
	// compile to push*. (We don't analyze the CFG, so we don't know if we can
	// use what is in the user defined block. Perhaps we could special case
	// single cblocks at start of program.
	checkSame(t, 4,
		"intcblock 4 5 1; int 4; int 1; +; int 5; ==",
		"intcblock 4 5 1; pushint 4; pushint 1; +; pushint 5; ==")
	checkSame(t, 4,
		"bytecblock 0x44 0x55 0x4455; byte 0x44; byte 0x55; concat; byte 0x4455; ==",
		"bytecblock 0x44 0x55 0x4455; pushbytes 0x44; pushbytes 0x55; concat; pushbytes 0x4455; ==")
	// Can't switch to push* after the fact.
	testProg(t, "int 5; intcblock 4;", 4, Expect{1, "intcblock following int"})
	testProg(t, "int 4; intcblock 4;", 4, Expect{1, "intcblock following int"})
	testProg(t, "addr RWXCBB73XJITATVQFOI7MVUUQOL2PFDDSDUMW4H4T2SNSX4SEUOQ2MM7F4; bytecblock 0x44", 4, Expect{1, "bytecblock following byte/addr/method"})

	// Ignore manually added cblocks in deadcode, so they can be added easily to
	// existing programs. There are proposals to put metadata there.
	ops = testProg(t, "int 4; int 4; +; int 8; ==; return; intcblock 10", AssemblerMaxVersion)
	require.Equal(t, ops.Program[1], OpsByName[ops.Version]["intcblock"].Opcode)
	require.EqualValues(t, ops.Program[3], 4) // <intcblock> 1 4 <intc_0>
	require.Equal(t, ops.Program[4], OpsByName[ops.Version]["intc_0"].Opcode)
	ops = testProg(t, "b skip; intcblock 10; skip: int 4; int 4; +; int 8; ==;", AssemblerMaxVersion)
	require.Equal(t, ops.Program[1], OpsByName[ops.Version]["intcblock"].Opcode)
	require.EqualValues(t, ops.Program[3], 4)

	ops = testProg(t, "byte 0x44; byte 0x44; concat; len; return; bytecblock 0x11", AssemblerMaxVersion)
	require.Equal(t, ops.Program[1], OpsByName[ops.Version]["bytecblock"].Opcode)
	require.EqualValues(t, ops.Program[4], 0x44) // <bytecblock> 1 1 0x44 <bytec_0>
	require.Equal(t, ops.Program[5], OpsByName[ops.Version]["bytec_0"].Opcode)
	ops = testProg(t, "b skip; bytecblock 0x11; skip: byte 0x44; byte 0x44; concat; len; int 4; ==", AssemblerMaxVersion)
	require.Equal(t, ops.Program[1], OpsByName[ops.Version]["bytecblock"].Opcode)
	require.EqualValues(t, ops.Program[4], 0x44)
}

func TestManualCBlocksPreBackBranch(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	// Before backbranch enabled, the assembler is willing to assemble an `int`
	// reference after an intcblock as an intc. It uses the most recent seen
	// non-deadcode intcblock, so it *could* be wrong.
	testProg(t, "intcblock 10 20; int 10;", backBranchEnabledVersion-1)
	// By the same token, assembly complains if that intcblock doesn't have the
	// constant. In v3, and v3 only, it *could* pushint.
	testProg(t, "intcblock 10 20; int 30;", backBranchEnabledVersion-1, Expect{1, "int 30 used..."})

	// Since the second intcblock is dead, the `int 10` "sees" the first block, not the second
	testProg(t, "intcblock 10 20; b skip; intcblock 3 4 5; skip: int 10;", backBranchEnabledVersion-1)
	testProg(t, "intcblock 10 20; b skip; intcblock 3 4 5; skip: int 3;", backBranchEnabledVersion-1,
		Expect{1, "int 3 used..."})

	// Here, the intcblock in effect is unknowable, better to force the user to
	// use intc (unless pushint is available to save the day).

	// backBranchEnabledVersion-1 contains pushint
	testProg(t, "intcblock 10 20; txn NumAppArgs; bz skip; intcblock 3 4 5; skip: int 10;", backBranchEnabledVersion-1)
	testProg(t, "intcblock 10 20; txn NumAppArgs; bz skip; intcblock 3 4 5; skip: int 3;", backBranchEnabledVersion-1)

	// backBranchEnabledVersion-2 does not
	testProg(t, "intcblock 10 20; txn NumAppArgs; bz skip; intcblock 3 4 5; skip: int 10;", backBranchEnabledVersion-2,
		Expect{1, "int 10 used with manual intcblocks. Use intc."})
	testProg(t, "intcblock 10 20; txn NumAppArgs; bz skip; intcblock 3 4 5; skip: int 3;", backBranchEnabledVersion-2,
		Expect{1, "int 3 used with manual intcblocks. Use intc."})

	// REPEAT ABOVE, BUT FOR BYTE BLOCKS

	testProg(t, "bytecblock 0x10 0x20; byte 0x10;", backBranchEnabledVersion-1)
	testProg(t, "bytecblock 0x10 0x20; byte 0x30;", backBranchEnabledVersion-1, Expect{1, "byte/addr/method used..."})
	testProg(t, "bytecblock 0x10 0x20; b skip; bytecblock 0x03 0x04 0x05; skip: byte 0x10;", backBranchEnabledVersion-1)
	testProg(t, "bytecblock 0x10 0x20; b skip; bytecblock 0x03 0x04 0x05; skip: byte 0x03;", backBranchEnabledVersion-1,
		Expect{1, "byte/addr/method used..."})
	testProg(t, "bytecblock 0x10 0x20; txn NumAppArgs; bz skip; bytecblock 0x03 0x04 0x05; skip: byte 0x10;", backBranchEnabledVersion-1)
	testProg(t, "bytecblock 0x10 0x20; txn NumAppArgs; bz skip; bytecblock 0x03 0x04 0x05; skip: byte 0x03;", backBranchEnabledVersion-1)
	testProg(t, "bytecblock 0x10 0x20; txn NumAppArgs; bz skip; bytecblock 0x03 0x04 0x05; skip: byte 0x10;", backBranchEnabledVersion-2,
		Expect{1, "byte 0x10 used with manual bytecblocks. Use bytec."})
	testProg(t, "bytecblock 0x10 0x20; txn NumAppArgs; bz skip; bytecblock 0x03 0x04 0x05; skip: byte 0x03;", backBranchEnabledVersion-2,
		Expect{1, "byte 0x03 used with manual bytecblocks. Use bytec."})
}

func TestAssembleOptimizedConstants(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	t.Run("Bytes", func(t *testing.T) {
		t.Parallel()

		program := `
byte 0x0102
byte base64(AQI=) // 0x0102
byte base32(AEBA====) // 0x0102
byte "test"
byte base32(ORSXG5A=) // "test"
addr WSJHNPJ6YCLX5K4GUMQ4ISPK3ABMS3AL3F6CSVQTCUI5F4I65PWEMCWT3M
byte 0x0103
byte base64(AQM=) // 0x0103
byte base32(AEBQ====) // 0x0103
`
		// 0x0102 and 0x0103 are tied for most frequent bytes, but 0x0102 should win because it appears first
		expected := `
bytecblock 0x0102 0x0103 0x74657374
bytec_0 // 0x0102
bytec_0 // 0x0102
bytec_0 // 0x0102
bytec_2 // "test"
bytec_2 // "test"
pushbytes 0xb49276bd3ec0977eab86a321c449ead802c96c0bd97c2956131511d2f11eebec // addr WSJHNPJ6YCLX5K4GUMQ4ISPK3ABMS3AL3F6CSVQTCUI5F4I65PWEMCWT3M
bytec_1 // 0x0103
bytec_1 // 0x0103
bytec_1 // 0x0103
`
		for v := uint64(optimizeConstantsEnabledVersion); v <= AssemblerMaxVersion; v++ {
			t.Run(fmt.Sprintf("v=%d", v), func(t *testing.T) {
				expectedOps := testProg(t, expected, v)
				expectedHex := hex.EncodeToString(expectedOps.Program)

				actualOps := testProg(t, program, v)
				actualHex := hex.EncodeToString(actualOps.Program)

				require.Equal(t, expectedHex, actualHex)
			})
		}
	})

	t.Run("Ints", func(t *testing.T) {
		t.Parallel()

		program := `
int 1
int OptIn // 1
int 2
int 3
int 4
int ClearState // 3
int 4
int 3
int 4
`
		// 3 and 4 are tied for most frequent int, but 3 should win because it appears first
		expected := `
intcblock 3 4 1
intc_2 // 1
intc_2 // 1
pushint 2
intc_0 // 3
intc_1 // 4
intc_0 // 3
intc_1 // 4
intc_0 // 3
intc_1 // 4
`
		for v := uint64(optimizeConstantsEnabledVersion); v <= AssemblerMaxVersion; v++ {
			t.Run(fmt.Sprintf("v=%d", v), func(t *testing.T) {
				expectedOps := testProg(t, expected, v)
				expectedHex := hex.EncodeToString(expectedOps.Program)

				actualOps := testProg(t, program, v)
				actualHex := hex.EncodeToString(actualOps.Program)

				require.Equal(t, expectedHex, actualHex)
			})
		}
	})

	t.Run("All", func(t *testing.T) {
		t.Parallel()

		program := `
int 1
byte 0x0102
int OptIn // 1
byte base64(AQI=) // 0x0102
int 2
byte base32(AEBA====) // 0x0102
int 3
byte "test"
int 4
byte base32(ORSXG5A=) // "test"
int ClearState // 3
addr WSJHNPJ6YCLX5K4GUMQ4ISPK3ABMS3AL3F6CSVQTCUI5F4I65PWEMCWT3M
int 4
byte 0x0103
int 3
byte base64(AQM=) // 0x0103
int 4
byte base32(AEBQ====) // 0x0103
`
		// interleaving of previous tests
		expected := `
intcblock 3 4 1
bytecblock 0x0102 0x0103 0x74657374
intc_2 // 1
bytec_0 // 0x0102
intc_2 // 1
bytec_0 // 0x0102
pushint 2
bytec_0 // 0x0102
intc_0 // 3
bytec_2 // "test"
intc_1 // 4
bytec_2 // "test"
intc_0 // 3
pushbytes 0xb49276bd3ec0977eab86a321c449ead802c96c0bd97c2956131511d2f11eebec // addr WSJHNPJ6YCLX5K4GUMQ4ISPK3ABMS3AL3F6CSVQTCUI5F4I65PWEMCWT3M
intc_1 // 4
bytec_1 // 0x0103
intc_0 // 3
bytec_1 // 0x0103
intc_1 // 4
bytec_1 // 0x0103
`
		for v := uint64(optimizeConstantsEnabledVersion); v <= AssemblerMaxVersion; v++ {
			t.Run(fmt.Sprintf("v=%d", v), func(t *testing.T) {
				expectedOps := testProg(t, expected, v)
				expectedHex := hex.EncodeToString(expectedOps.Program)

				actualOps := testProg(t, program, v)
				actualHex := hex.EncodeToString(actualOps.Program)

				require.Equal(t, expectedHex, actualHex)
			})
		}
	})

	t.Run("Back jumps", func(t *testing.T) {
		t.Parallel()

		program := `
int 1
byte 0x0102
int OptIn // 1
byte base64(AQI=) // 0x0102
int 2
byte base32(AEBA====) // 0x0102
int 3
byte "test"
target:
retsub
int 4
byte base32(ORSXG5A=) // "test"
int ClearState // 3
addr WSJHNPJ6YCLX5K4GUMQ4ISPK3ABMS3AL3F6CSVQTCUI5F4I65PWEMCWT3M
int 4
byte 0x0103
int 3
byte base64(AQM=) // 0x0103
int 4
callsub target
byte base32(AEBQ====) // 0x0103
`
		expected := `
intcblock 3 4 1
bytecblock 0x0102 0x0103 0x74657374
intc_2 // 1
bytec_0 // 0x0102
intc_2 // 1
bytec_0 // 0x0102
pushint 2
bytec_0 // 0x0102
intc_0 // 3
bytec_2 // "test"
target:
retsub
intc_1 // 4
bytec_2 // "test"
intc_0 // 3
pushbytes 0xb49276bd3ec0977eab86a321c449ead802c96c0bd97c2956131511d2f11eebec // addr WSJHNPJ6YCLX5K4GUMQ4ISPK3ABMS3AL3F6CSVQTCUI5F4I65PWEMCWT3M
intc_1 // 4
bytec_1 // 0x0103
intc_0 // 3
bytec_1 // 0x0103
intc_1 // 4
callsub target
bytec_1 // 0x0103
`
		for v := uint64(optimizeConstantsEnabledVersion); v <= AssemblerMaxVersion; v++ {
			t.Run(fmt.Sprintf("v=%d", v), func(t *testing.T) {
				expectedOps := testProg(t, expected, v)
				expectedHex := hex.EncodeToString(expectedOps.Program)

				actualOps := testProg(t, program, v)
				actualHex := hex.EncodeToString(actualOps.Program)

				require.Equal(t, expectedHex, actualHex)
			})
		}
	})
}

func TestAssembleOptimizedUint(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	program := `
int 1
int OptIn
int 2
int 3
int 3
int ClearState
`
	expected := "042002030123238102222222"

	for v := uint64(optimizeConstantsEnabledVersion); v <= AssemblerMaxVersion; v++ {
		t.Run(fmt.Sprintf("v=%d", v), func(t *testing.T) {
			ops := testProg(t, program, v)
			s := hex.EncodeToString(ops.Program)
			require.Equal(t, mutateProgVersion(v, expected), s)
		})
	}
}

func TestFieldsFromLine(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	check := func(line string, tokens ...string) {
		t.Helper()
		assert.Equal(t, tokensFromLine(line), tokens)
	}

	check("op arg", "op", "arg")
	check("op arg // test", "op", "arg")
	check("op base64 ABC//==", "op", "base64", "ABC//==")
	check("op base64 base64", "op", "base64", "base64")
	check("op base64 base64 //comment", "op", "base64", "base64")
	check("op base64 base64; op2 //done", "op", "base64", "base64", ";", "op2")
	check("op base64 ABC/==", "op", "base64", "ABC/==")
	check("op base64 ABC/== /", "op", "base64", "ABC/==", "/")
	check("op base64 ABC/== //", "op", "base64", "ABC/==")
	check("op base64 ABC//== //", "op", "base64", "ABC//==")
	check("op b64 ABC//== //", "op", "b64", "ABC//==")
	check("op b64(ABC//==) // comment", "op", "b64(ABC//==)")
	check("op base64(ABC//==) // comment", "op", "base64(ABC//==)")
	check("op b64(ABC/==) // comment", "op", "b64(ABC/==)")
	check("op base64(ABC/==) // comment", "op", "base64(ABC/==)")
	check("base64(ABC//==)", "base64(ABC//==)")
	check("b(ABC//==)", "b(ABC")
	check("b(ABC//==) //", "b(ABC")
	check("b(ABC ==) //", "b(ABC", "==)")
	check("op base64 ABC)", "op", "base64", "ABC)")
	check("op base64 ABC) // comment", "op", "base64", "ABC)")
	check("op base64 ABC//) // comment", "op", "base64", "ABC//)")
	check(`op "test"`, "op", `"test"`)
	check(`op "test1 test2"`, "op", `"test1 test2"`)
	check(`op "test1 test2" // comment`, "op", `"test1 test2"`)
	check(`op "test1 test2 // not a comment"`, "op", `"test1 test2 // not a comment"`)
	check(`op "test1 test2 // not a comment" // comment`, "op", `"test1 test2 // not a comment"`)
	check(`op "test1 test2" //`, "op", `"test1 test2"`)
	check(`op "test1 test2"//`, "op", `"test1 test2"`)
	check(`op "test1 test2`, "op", `"test1 test2`)          // non-terminated string literal
	check(`op "test1 test2\"`, "op", `"test1 test2\"`)      // non-terminated string literal
	check(`op \"test1 test2\"`, "op", `\"test1`, `test2\"`) // not a string literal
	check(`"test1 test2"`, `"test1 test2"`)
	check(`\"test1 test2"`, `\"test1`, `test2"`)
	check(`"" // test`, `""`)
	check("int 1; int 2", "int", "1", ";", "int", "2")
	check("int 1;;;int 2", "int", "1", ";", ";", ";", "int", "2")
	check("int 1; ;int 2;; ; ;; ", "int", "1", ";", ";", "int", "2", ";", ";", ";", ";", ";")
	check(";", ";")
	check("; ; ;;;;", ";", ";", ";", ";", ";", ";")
	check(" ;", ";")
	check(" ; ", ";")
}

func TestSplitTokens(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	check := func(tokens []string, left []string, right []string) {
		t.Helper()
		current, next := splitTokens(tokens)
		assert.Equal(t, left, current)
		assert.Equal(t, right, next)
	}

	check([]string{"hey,", "how's", ";", ";", "it", "going", ";"},
		[]string{"hey,", "how's"},
		[]string{";", "it", "going", ";"},
	)

	check([]string{";"},
		[]string{},
		[]string{},
	)

	check([]string{";", "it", "going"},
		[]string{},
		[]string{"it", "going"},
	)

	check([]string{"hey,", "how's"},
		[]string{"hey,", "how's"},
		nil,
	)

	check([]string{`"hey in quotes;"`, "getting", `";"`, ";", "tricky"},
		[]string{`"hey in quotes;"`, "getting", `";"`},
		[]string{"tricky"},
	)

}

func TestAssembleRejectNegJump(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	source := `wat:
int 1
bnz wat
int 2`
	for v := uint64(1); v < backBranchEnabledVersion; v++ {
		t.Run(fmt.Sprintf("v=%d", v), func(t *testing.T) {
			testProg(t, source, v, Expect{3, "label \"wat\" is a back reference..."})
		})
	}
	for v := uint64(backBranchEnabledVersion); v <= AssemblerMaxVersion; v++ {
		t.Run(fmt.Sprintf("v=%d", v), func(t *testing.T) {
			testProg(t, source, v)
		})
	}
}

func TestAssembleBase64(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	text := `byte base64 //GWRM+yy3BCavBDXO/FYTNZ6o2Jai5edsMCBdDEz+0=
byte base64 avGWRM+yy3BCavBDXO/FYTNZ6o2Jai5edsMCBdDEz//=
//
//text
==
int 1 //sometext
&& //somemoretext
int 1
==
byte b64 //GWRM+yy3BCavBDXO/FYTNZ6o2Jai5edsMCBdDEz+8=
byte b64 avGWRM+yy3BCavBDXO/FYTNZ6o2Jai5edsMCBdDEz//=
==
||`

	expectedDefaultConsts := "01200101260320fff19644cfb2cb70426af0435cefc5613359ea8d896a2e5e76c30205d0c4cfed206af19644cfb2cb70426af0435cefc5613359ea8d896a2e5e76c30205d0c4cfff20fff19644cfb2cb70426af0435cefc5613359ea8d896a2e5e76c30205d0c4cfef282912221022122a291211"
	expectedOptimizedConsts := "012001012601206af19644cfb2cb70426af0435cefc5613359ea8d896a2e5e76c30205d0c4cfff8020fff19644cfb2cb70426af0435cefc5613359ea8d896a2e5e76c30205d0c4cfed2812221022128020fff19644cfb2cb70426af0435cefc5613359ea8d896a2e5e76c30205d0c4cfef281211"

	for v := uint64(1); v <= AssemblerMaxVersion; v++ {
		t.Run(fmt.Sprintf("v=%d", v), func(t *testing.T) {
			expected := expectedDefaultConsts
			if v >= optimizeConstantsEnabledVersion {
				expected = expectedOptimizedConsts
			}

			ops := testProg(t, text, v)
			s := hex.EncodeToString(ops.Program)
			require.Equal(t, mutateProgVersion(v, expected), s)
		})
	}
}

func TestAssembleRejectUnkLabel(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	source := `int 1
bnz nowhere
int 2`
	for v := uint64(1); v <= AssemblerMaxVersion; v++ {
		t.Run(fmt.Sprintf("v=%d", v), func(t *testing.T) {
			testProg(t, source, v, Expect{2, "reference to undefined label \"nowhere\""})
		})
	}
}

func TestAssembleJumpToTheEnd(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	source := `intcblock 1
intc 0
intc 0
bnz done
done:`
	ops := testProg(t, source, AssemblerMaxVersion)
	require.Equal(t, 9, len(ops.Program))
	expectedProgBytes := []byte("\x01\x20\x01\x01\x22\x22\x40\x00\x00")
	expectedProgBytes[0] = byte(AssemblerMaxVersion)
	require.Equal(t, expectedProgBytes, ops.Program)
}

func TestMultipleErrors(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	source := `int 1
bnz nowhere
// comment
txn XYZ
int 2`
	for v := uint64(1); v <= AssemblerMaxVersion; v++ {
		t.Run(fmt.Sprintf("v=%d", v), func(t *testing.T) {
			testProg(t, source, v,
				Expect{2, "reference to undefined label \"nowhere\""},
				Expect{4, "txn unknown field: \"XYZ\""})
		})
	}
}

func TestAssembleDisassemble(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	// Specifically constructed program text that should be recreated by Disassemble()
	text := fmt.Sprintf(`#pragma version %d
intcblock 0 1 2 3 4 5
bytecblock 0xcafed00d 0x1337 0x68656c6c6f 0xdeadbeef 0x70077007 0x0102030405060708091011121314151617181920212223242526272829303132
bytec_2 // "hello"
pop
bytec 5 // addr AEBAGBAFAYDQQCIQCEJBGFAVCYLRQGJAEERCGJBFEYTSQKJQGEZHVJ5ZZY
pop
intc_1 // 1
intc_0 // 0
+
intc 4 // 4
*
bytec_1 // 0x1337
bytec_0 // 0xcafed00d
==
bytec 4 // 0x70077007
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
global CreatorAddress
global GroupID
global OpcodeBudget
global CallerApplicationID
global CallerApplicationAddress
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
txn StateProofPK
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
txna Assets 0
txn NumAssets
txna Applications 0
txn NumApplications
txn GlobalNumUint
txn GlobalNumByteSlice
txn LocalNumUint
txn LocalNumByteSlice
gtxn 12 Fee
txn ExtraProgramPages
txn Nonparticipation
global CurrentApplicationAddress
itxna Logs 1
itxn NumLogs
itxn CreatedAssetID
itxn CreatedApplicationID
itxn LastLog
txn NumApprovalProgramPages
txna ApprovalProgramPages 0
txn NumClearStateProgramPages
txna ClearStateProgramPages 0
`, AssemblerMaxVersion)
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
	ops := testProg(t, text, AssemblerMaxVersion)
	t2, err := Disassemble(ops.Program)
	require.Equal(t, text, t2)
	require.NoError(t, err)
}

func TestAssembleDisassembleCycle(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	// Test that disassembly re-assembles to the same program bytes.
	// Disassembly won't necessarily perfectly recreate the source text, but assembling the result of Disassemble() should be the same program bytes.
	// This confirms that each program compiles to the same bytes
	// (except the leading version indicator), when compiled under
	// original version, unspecified version (so it should pick up
	// the pragma) and current version with pragma removed. That
	// doesn't *have* to be true, as we can introduce
	// optimizations in later versions that change the bytecode
	// emitted. But currently it is, so we test it for now to
	// catch any suprises.
	require.LessOrEqual(t, LogicVersion, len(nonsense)) // Allow nonsense for future versions
	for v, source := range nonsense {
		if v > LogicVersion {
			continue // We allow them to be set, but can't test assembly beyond LogicVersion
		}
		t.Run(fmt.Sprintf("v=%d", v), func(t *testing.T) {
			ops := testProg(t, source, v)
			t2, err := Disassemble(ops.Program)
			require.NoError(t, err)
			none := testProg(t, notrack(t2), assemblerNoVersion)
			require.Equal(t, ops.Program[1:], none.Program[1:])
			t3 := "// " + t2 // This comments out the #pragma version
			current := testProg(t, notrack(t3), AssemblerMaxVersion)
			require.Equal(t, ops.Program[1:], current.Program[1:])
		})
	}
}

func TestConstantDisassembly(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	ops := testProg(t, "int 47", AssemblerMaxVersion)
	out, err := Disassemble(ops.Program)
	require.NoError(t, err)
	require.Contains(t, out, "pushint 47")

	ops = testProg(t, "byte \"john\"", AssemblerMaxVersion)
	out, err = Disassemble(ops.Program)
	require.NoError(t, err)
	require.Contains(t, out, "pushbytes 0x6a6f686e // \"john\"")

	ops = testProg(t, "byte \"!&~\"", AssemblerMaxVersion)
	out, err = Disassemble(ops.Program)
	require.NoError(t, err)
	require.Contains(t, out, "pushbytes 0x21267e // \"!&~\"")

	ops = testProg(t, "byte 0x010720", AssemblerMaxVersion)
	out, err = Disassemble(ops.Program)
	require.NoError(t, err)
	require.Contains(t, out, "pushbytes 0x010720 // 0x010720")

	ops = testProg(t, "addr AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAY5HFKQ", AssemblerMaxVersion)
	out, err = Disassemble(ops.Program)
	require.NoError(t, err)
	require.Contains(t, out, "pushbytes 0x0000000000000000000000000000000000000000000000000000000000000000 // addr AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAY5HFKQ")

}

func TestConstantArgs(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	for v := uint64(1); v <= AssemblerMaxVersion; v++ {
		testProg(t, "int", v, Expect{1, "int needs one immediate argument, was given 0"})
		testProg(t, "int 1 2", v, Expect{1, "int needs one immediate argument, was given 2"})
		testProg(t, "intc", v, Expect{1, "intc needs one immediate argument, was given 0"})
		testProg(t, "intc hi bye", v, Expect{1, "intc needs one immediate argument, was given 2"})
		testProg(t, "byte", v, Expect{1, "byte needs byte literal argument"})
		testProg(t, "bytec", v, Expect{1, "bytec needs one immediate argument, was given 0"})
		testProg(t, "bytec 1 x", v, Expect{1, "bytec needs one immediate argument, was given 2"})
		testProg(t, "addr", v, Expect{1, "addr needs one immediate argument, was given 0"})
		testProg(t, "addr x y", v, Expect{1, "addr needs one immediate argument, was given 2"})
	}
	for v := uint64(3); v <= AssemblerMaxVersion; v++ {
		testProg(t, "pushint", v, Expect{1, "pushint needs one immediate argument, was given 0"})
		testProg(t, "pushint 3 4", v, Expect{1, "pushint needs one immediate argument, was given 2"})
		testProg(t, "pushbytes", v, Expect{1, "pushbytes needs byte literal argument"})
	}
}

func TestBranchArgs(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	for v := uint64(2); v <= AssemblerMaxVersion; v++ {
		testProg(t, "b", v, Expect{1, "b needs a single label argument"})
		testProg(t, "b lab1 lab2", v, Expect{1, "b needs a single label argument"})
		testProg(t, "int 1; bz", v, Expect{1, "bz needs a single label argument"})
		testProg(t, "int 1; bz a b", v, Expect{1, "bz needs a single label argument"})
		testProg(t, "int 1; bnz", v, Expect{1, "bnz needs a single label argument"})
		testProg(t, "int 1; bnz c d", v, Expect{1, "bnz needs a single label argument"})
	}

	for v := uint64(4); v <= AssemblerMaxVersion; v++ {
		testProg(t, "callsub", v, Expect{1, "callsub needs a single label argument"})
		testProg(t, "callsub one two", v, Expect{1, "callsub needs a single label argument"})
	}
}

func TestAssembleDisassembleErrors(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	source := `txn Sender`
	ops, err := AssembleStringWithVersion(source, AssemblerMaxVersion)
	require.NoError(t, err)
	ops.Program[2] = 0x50 // txn field
	_, err = Disassemble(ops.Program)
	require.Error(t, err)
	require.Contains(t, err.Error(), "invalid immediate f for txn")

	source = `txna Accounts 0`
	ops, err = AssembleStringWithVersion(source, AssemblerMaxVersion)
	require.NoError(t, err)
	ops.Program[2] = 0x50 // txn field
	_, err = Disassemble(ops.Program)
	require.Error(t, err)
	require.Contains(t, err.Error(), "invalid immediate f for txna")

	source = `gtxn 0 Sender`
	ops, err = AssembleStringWithVersion(source, AssemblerMaxVersion)
	require.NoError(t, err)
	ops.Program[3] = 0x50 // txn field
	_, err = Disassemble(ops.Program)
	require.Error(t, err)
	require.Contains(t, err.Error(), "invalid immediate f for gtxn")

	source = `gtxna 0 Accounts 0`
	ops, err = AssembleStringWithVersion(source, AssemblerMaxVersion)
	require.NoError(t, err)
	ops.Program[3] = 0x50 // txn field
	_, err = Disassemble(ops.Program)
	require.Error(t, err)
	require.Contains(t, err.Error(), "invalid immediate f for gtxna")

	source = `global MinTxnFee`
	ops, err = AssembleStringWithVersion(source, AssemblerMaxVersion)
	require.NoError(t, err)
	ops.Program[2] = 0x50 // txn field
	_, err = Disassemble(ops.Program)
	require.Error(t, err)
	require.Contains(t, err.Error(), "invalid immediate f for global")

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
	require.Contains(t, err.Error(), "invalid immediate f for asset_holding_get")

	source = "int 0\nasset_params_get AssetTotal"
	ops, err = AssembleStringWithVersion(source, AssemblerMaxVersion)
	require.NoError(t, err)
	ops.Program[4] = 0x50 // params field
	_, err = Disassemble(ops.Program)
	require.Error(t, err)
	require.Contains(t, err.Error(), "invalid immediate f for asset_params_get")

	source = "int 0\nasset_params_get AssetTotal"
	ops, err = AssembleStringWithVersion(source, AssemblerMaxVersion)
	require.NoError(t, err)
	_, err = Disassemble(ops.Program)
	require.NoError(t, err)
	ops.Program = ops.Program[0 : len(ops.Program)-1]
	_, err = Disassemble(ops.Program)
	require.Error(t, err)
	require.Contains(t, err.Error(), "program end while reading immediate f for asset_params_get")

	source = "gtxna 0 Accounts 0"
	ops, err = AssembleStringWithVersion(source, AssemblerMaxVersion)
	require.NoError(t, err)
	_, err = Disassemble(ops.Program)
	require.NoError(t, err)
	_, err = Disassemble(ops.Program[0 : len(ops.Program)-1])
	require.Error(t, err)
	require.Contains(t, err.Error(), "program end while reading immediate i for gtxna")
	_, err = Disassemble(ops.Program[0 : len(ops.Program)-2])
	require.Error(t, err)
	require.Contains(t, err.Error(), "program end while reading immediate f for gtxna")
	_, err = Disassemble(ops.Program[0 : len(ops.Program)-3])
	require.Error(t, err)
	require.Contains(t, err.Error(), "program end while reading immediate t for gtxna")

	source = "txna Accounts 0"
	ops, err = AssembleStringWithVersion(source, AssemblerMaxVersion)
	require.NoError(t, err)
	_, err = Disassemble(ops.Program)
	require.NoError(t, err)
	ops.Program = ops.Program[0 : len(ops.Program)-1]
	_, err = Disassemble(ops.Program)
	require.Error(t, err)
	require.Contains(t, err.Error(), "program end while reading immediate i for txna")

	source = "byte 0x4141\nsubstring 0 1"
	ops, err = AssembleStringWithVersion(source, AssemblerMaxVersion)
	require.NoError(t, err)
	_, err = Disassemble(ops.Program)
	require.NoError(t, err)
	ops.Program = ops.Program[0 : len(ops.Program)-1]
	_, err = Disassemble(ops.Program)
	require.Error(t, err)
	require.Contains(t, err.Error(), "program end while reading immediate e for substring")
}

func TestAssembleVersions(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	testLine(t, "txna Accounts 0", AssemblerMaxVersion, "")
	testLine(t, "txna Accounts 0", 2, "")
	testLine(t, "txna Accounts 0", 1, "txna opcode was introduced in v2")
}

func TestAssembleBalance(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	source := `byte 0x00
balance
int 1
==`
	for v := uint64(2); v < directRefEnabledVersion; v++ {
		testProg(t, source, v, Expect{2, "balance arg 0 wanted type uint64 got []byte"})
	}
	for v := uint64(directRefEnabledVersion); v <= AssemblerMaxVersion; v++ {
		testProg(t, source, v)
	}
}

func TestAssembleMinBalance(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	source := `byte 0x00
min_balance
int 1
==`
	for v := uint64(3); v < directRefEnabledVersion; v++ {
		testProg(t, source, v, Expect{2, "min_balance arg 0 wanted type uint64 got []byte"})
	}
	for v := uint64(directRefEnabledVersion); v <= AssemblerMaxVersion; v++ {
		testProg(t, source, v)
	}
}

func TestAssembleAsset(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	for v := uint64(2); v <= AssemblerMaxVersion; v++ {
		testProg(t, "asset_holding_get ABC 1", v,
			Expect{1, "asset_holding_get ABC 1 expects 2 stack arguments..."})
		testProg(t, "int 1; asset_holding_get ABC 1", v,
			Expect{1, "asset_holding_get ABC 1 expects 2 stack arguments..."})
		testProg(t, "int 1; int 1; asset_holding_get ABC 1", v,
			Expect{1, "asset_holding_get expects 1 immediate argument"})
		testProg(t, "int 1; int 1; asset_holding_get ABC", v,
			Expect{1, "asset_holding_get unknown field: \"ABC\""})

		testProg(t, "byte 0x1234; asset_params_get ABC 1", v,
			Expect{1, "asset_params_get ABC 1 arg 0 wanted type uint64..."})

		// Test that AssetUnitName is known to return bytes
		testProg(t, "int 1; asset_params_get AssetUnitName; pop; int 1; +", v,
			Expect{1, "+ arg 0 wanted type uint64..."})

		// Test that AssetTotal is known to return uint64
		testProg(t, "int 1; asset_params_get AssetTotal; pop; byte 0x12; concat", v,
			Expect{1, "concat arg 0 wanted type []byte..."})

		testLine(t, "asset_params_get ABC 1", v, "asset_params_get expects 1 immediate argument")
		testLine(t, "asset_params_get ABC", v, "asset_params_get unknown field: \"ABC\"")
	}
}

func TestDisassembleSingleOp(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	for v := uint64(1); v <= AssemblerMaxVersion; v++ {
		// test ensures no double arg_0 entries in disassembly listing
		sample := fmt.Sprintf("#pragma version %d\narg_0\n", v)
		ops, err := AssembleStringWithVersion(sample, v)
		require.NoError(t, err)
		require.Equal(t, 2, len(ops.Program))
		disassembled, err := Disassemble(ops.Program)
		require.NoError(t, err)
		require.Equal(t, sample, disassembled)
	}
}

func TestDisassembleInt(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	txnSample := fmt.Sprintf("#pragma version %d\nint 17\nint 27\nint 37\nint 47\nint 5\nint 17\n", AssemblerMaxVersion)
	ops := testProg(t, txnSample, AssemblerMaxVersion)
	disassembled, err := Disassemble(ops.Program)
	require.NoError(t, err)
	// Would ne nice to check that these appear in the
	// disassembled output in the right order, but I don't want to
	// hardcode checks that they are in certain intc slots.
	require.Contains(t, disassembled, "// 17")
	require.Contains(t, disassembled, "pushint 27")
	require.Contains(t, disassembled, "pushint 37")
	require.Contains(t, disassembled, "pushint 47")
	require.Contains(t, disassembled, "pushint 5")
}

func TestDisassembleTxna(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	// txn was 1, but this tests both
	introduction := OpsByName[LogicVersion]["gtxna"].Version
	for v := introduction; v <= AssemblerMaxVersion; v++ {
		// check txn and txna are properly disassembled
		txnSample := fmt.Sprintf("#pragma version %d\ntxn Sender\n", v)
		ops := testProg(t, txnSample, v)
		disassembled, err := Disassemble(ops.Program)
		require.NoError(t, err)
		require.Equal(t, txnSample, disassembled)

		txnaSample := fmt.Sprintf("#pragma version %d\ntxna Accounts 0\n", v)
		ops = testProg(t, txnaSample, v)
		disassembled, err = Disassemble(ops.Program)
		require.NoError(t, err)
		require.Equal(t, txnaSample, disassembled)

		txnSample2 := fmt.Sprintf("#pragma version %d\ntxn Accounts 0\n", v)
		ops = testProg(t, txnSample2, v)
		disassembled, err = Disassemble(ops.Program)
		require.NoError(t, err)
		// compare with txnaSample, not txnSample2
		require.Equal(t, txnaSample, disassembled)
	}
}

func TestDisassembleGtxna(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	// check gtxn and gtxna are properly disassembled

	introduction := OpsByName[LogicVersion]["gtxna"].Version
	for v := introduction; v <= AssemblerMaxVersion; v++ {
		gtxnSample := fmt.Sprintf("#pragma version %d\ngtxn 0 Sender\n", v)
		ops := testProg(t, gtxnSample, v)
		disassembled, err := Disassemble(ops.Program)
		require.NoError(t, err)
		require.Equal(t, gtxnSample, disassembled)

		gtxnaSample := fmt.Sprintf("#pragma version %d\ngtxna 0 Accounts 0\n", v)
		ops = testProg(t, gtxnaSample, v)
		disassembled, err = Disassemble(ops.Program)
		require.NoError(t, err)
		require.Equal(t, gtxnaSample, disassembled)

		gtxnSample2 := fmt.Sprintf("#pragma version %d\ngtxn 0 Accounts 0\n", v)
		ops = testProg(t, gtxnSample2, v)
		disassembled, err = Disassemble(ops.Program)
		require.NoError(t, err)
		// compare with gtxnaSample, not gtxnSample2
		require.Equal(t, gtxnaSample, disassembled)
	}
}

func TestDisassemblePushConst(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	// check pushint and pushbytes are properly disassembled
	intSample := fmt.Sprintf("#pragma version %d\npushint 1\n", AssemblerMaxVersion)
	expectedIntSample := intSample
	ops, err := AssembleStringWithVersion(intSample, AssemblerMaxVersion)
	require.NoError(t, err)
	disassembled, err := Disassemble(ops.Program)
	require.NoError(t, err)
	require.Equal(t, expectedIntSample, disassembled)

	hexBytesSample := fmt.Sprintf("#pragma version %d\npushbytes 0x01\n", AssemblerMaxVersion)
	expectedHexBytesSample := fmt.Sprintf("#pragma version %d\npushbytes 0x01 // 0x01\n", AssemblerMaxVersion)
	ops, err = AssembleStringWithVersion(hexBytesSample, AssemblerMaxVersion)
	require.NoError(t, err)
	disassembled, err = Disassemble(ops.Program)
	require.NoError(t, err)
	require.Equal(t, expectedHexBytesSample, disassembled)

	stringBytesSample := fmt.Sprintf("#pragma version %d\npushbytes \"a\"\n", AssemblerMaxVersion)
	expectedStringBytesSample := fmt.Sprintf("#pragma version %d\npushbytes 0x61 // \"a\"\n", AssemblerMaxVersion)
	ops, err = AssembleStringWithVersion(stringBytesSample, AssemblerMaxVersion)
	require.NoError(t, err)
	disassembled, err = Disassemble(ops.Program)
	require.NoError(t, err)
	require.Equal(t, expectedStringBytesSample, disassembled)
}

func TestDisassembleLastLabel(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	// starting from v2 branching to the last line are legal
	for v := uint64(2); v <= AssemblerMaxVersion; v++ {
		t.Run(fmt.Sprintf("v=%d", v), func(t *testing.T) {
			source := fmt.Sprintf(`#pragma version %d
intcblock 1
intc_0 // 1
bnz label1
label1:
`, v)
			ops := testProg(t, source, v)
			dis, err := Disassemble(ops.Program)
			require.NoError(t, err)
			require.Equal(t, source, dis)
		})
	}
}

func TestAssembleOffsets(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	source := "err"
	ops := testProg(t, source, AssemblerMaxVersion)
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
	ops = testProg(t, source, AssemblerMaxVersion)
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
b label1
err
label1:
err
`
	ops = testProg(t, source, AssemblerMaxVersion)
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
	// b
	line, ok = ops.OffsetToLine[2]
	require.True(t, ok)
	require.Equal(t, 1, line)
	// b byte 1
	line, ok = ops.OffsetToLine[3]
	require.False(t, ok)
	require.Equal(t, 0, line)
	// b byte 2
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

	source = `pushint 0
// comment
!
`
	ops = testProg(t, source, AssemblerMaxVersion)
	require.Equal(t, 4, len(ops.Program))
	require.Equal(t, 2, len(ops.OffsetToLine))
	// vlen
	line, ok = ops.OffsetToLine[0]
	require.False(t, ok)
	require.Equal(t, 0, line)
	// pushint
	line, ok = ops.OffsetToLine[1]
	require.True(t, ok)
	require.Equal(t, 0, line)
	// pushint byte 1
	line, ok = ops.OffsetToLine[2]
	require.False(t, ok)
	require.Equal(t, 0, line)
	// !
	line, ok = ops.OffsetToLine[3]
	require.True(t, ok)
	require.Equal(t, 2, line)
}

func TestHasStatefulOps(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	source := "int 1"
	ops := testProg(t, source, AssemblerMaxVersion)
	has, err := HasStatefulOps(ops.Program)
	require.NoError(t, err)
	require.False(t, has)

	source = `int 1
int 1
app_opted_in
err
`
	ops = testProg(t, source, AssemblerMaxVersion)
	has, err = HasStatefulOps(ops.Program)
	require.NoError(t, err)
	require.True(t, has)
}

func TestStringLiteralParsing(t *testing.T) {
	partitiontest.PartitionTest(t)
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

func TestPragmas(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	for v := uint64(1); v <= AssemblerMaxVersion; v++ {
		text := fmt.Sprintf("#pragma version %d", v)
		ops := testProg(t, text, v)
		require.Equal(t, v, ops.Version)
	}

	testProg(t, `#pragma version 100`, assemblerNoVersion,
		Expect{1, "unsupported version: 100"})

	testProg(t, `int 1`, 99, Expect{0, "Can not assemble version 99"})

	// Allow this on the off chance someone needs to reassemble an old logigsig
	testProg(t, `#pragma version 0`, assemblerNoVersion)

	testProg(t, `#pragma version a`, assemblerNoVersion,
		Expect{1, `bad #pragma version: "a"`})

	// will default to 1
	ops := testProg(t, "int 3", assemblerNoVersion)
	require.Equal(t, uint64(1), ops.Version)
	require.Equal(t, uint8(1), ops.Program[0])

	ops = testProg(t, "\n#pragma version 2", assemblerNoVersion)
	require.Equal(t, uint64(2), ops.Version)

	ops = testProg(t, "\n//comment\n#pragma version 2", assemblerNoVersion)
	require.Equal(t, uint64(2), ops.Version)

	// changing version is not allowed
	testProg(t, "#pragma version 1", 2, Expect{1, "version mismatch..."})
	testProg(t, "#pragma version 2", 1, Expect{1, "version mismatch..."})

	testProg(t, "#pragma version 2\n#pragma version 1", assemblerNoVersion,
		Expect{2, "version mismatch..."})

	// repetitive, but fine
	ops = testProg(t, "#pragma version 2\n#pragma version 2", assemblerNoVersion)
	require.Equal(t, uint64(2), ops.Version)

	testProg(t, "\nint 1\n#pragma version 2", assemblerNoVersion,
		Expect{3, "#pragma version is only allowed before instructions"})

	testProg(t, "#pragma run-mode 2", assemblerNoVersion,
		Expect{1, `unsupported pragma directive: "run-mode"`})

	testProg(t, "#pragma versions", assemblerNoVersion,
		Expect{1, `unsupported pragma directive: "versions"`})

	ops = testProg(t, "#pragma version 1", assemblerNoVersion)
	require.Equal(t, uint64(1), ops.Version)

	ops = testProg(t, "\n#pragma version 1", assemblerNoVersion)
	require.Equal(t, uint64(1), ops.Version)

	testProg(t, "#pragma", assemblerNoVersion, Expect{1, "empty pragma"})

	testProg(t, "#pragma version", assemblerNoVersion,
		Expect{1, "no version value"})

	ops = testProg(t, "    #pragma version 5     ", assemblerNoVersion)
	require.Equal(t, uint64(5), ops.Version)
}

func TestAssemblePragmaVersion(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	text := `#pragma version 1
int 1
`
	ops := testProg(t, text, 1)
	ops1 := testProg(t, "int 1", 1)
	require.Equal(t, ops1.Program, ops.Program)

	testProg(t, text, 0, Expect{1, "version mismatch..."})
	testProg(t, text, 2, Expect{1, "version mismatch..."})
	testProg(t, text, assemblerNoVersion)

	ops = testProg(t, text, assemblerNoVersion)
	require.Equal(t, ops1.Program, ops.Program)

	text = `#pragma version 2
int 1
`
	ops = testProg(t, text, 2)
	ops2 := testProg(t, "int 1", 2)
	require.Equal(t, ops2.Program, ops.Program)

	testProg(t, text, 0, Expect{1, "version mismatch..."})
	testProg(t, text, 1, Expect{1, "version mismatch..."})

	ops = testProg(t, text, assemblerNoVersion)
	require.Equal(t, ops2.Program, ops.Program)

	// check if no version it defaults to v1
	text = `byte "test"
len
`
	ops = testProg(t, text, assemblerNoVersion)
	ops1 = testProg(t, text, 1)
	require.Equal(t, ops1.Program, ops.Program)
	ops2, err := AssembleString(text)
	require.NoError(t, err)
	require.Equal(t, ops2.Program, ops.Program)

	testProg(t, "#pragma unk", assemblerNoVersion,
		Expect{1, `unsupported pragma directive: "unk"`})
}

func TestAssembleConstants(t *testing.T) {
	partitiontest.PartitionTest(t)
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
	partitiontest.PartitionTest(t)
	t.Parallel()

	text := `intcblock 0x1234567812345678 0x1234567812345671 0x1234567812345672 0x1234567812345673 4 5 6 7 8`
	ops := testProg(t, text, 1)
	_, _, err := parseIntImmArgs(ops.Program, 1)
	require.Equal(t, err, errShortIntImmArgs)

	var cx EvalContext
	cx.program = ops.Program
	err = checkIntImmArgs(&cx)
	require.Equal(t, err, errShortIntImmArgs)
}

func TestMethodWarning(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	tests := []struct {
		method string
		pass   bool
	}{
		{
			method: "abc(uint64)void",
			pass:   true,
		},
		{
			method: "abc(uint64)",
			pass:   false,
		},
		{
			method: "abc(uint65)void",
			pass:   false,
		},
		{
			method: "(uint64)void",
			pass:   false,
		},
		{
			method: "abc(uint65,void",
			pass:   false,
		},
	}

	for _, test := range tests {
		for v := uint64(1); v <= AssemblerMaxVersion; v++ {
			src := fmt.Sprintf("method \"%s\"\nint 1", test.method)
			ops := testProg(t, src, v)

			if test.pass {
				require.Len(t, ops.Warnings, 0)
				continue
			}

			require.Len(t, ops.Warnings, 1)
			require.Contains(t, ops.Warnings[0].Error(), "Invalid ARC-4 ABI method signature for method op")
		}
	}
}

func TestBranchAssemblyTypeCheck(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	text := `
	int 0             // current app id  [0]
	int 1             // key  [1, 0]
	itob              // ["\x01", 0]
	app_global_get_ex // [0|1, x]
	pop               // [x]
	btoi              // [n]
`

	ops := newOpStream(AssemblerMaxVersion)
	err := ops.assemble(text)
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

	ops = newOpStream(AssemblerMaxVersion)
	err = ops.assemble(text)
	require.NoError(t, err)
	require.Empty(t, ops.Warnings)
}

func TestSwapTypeCheck(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	/* reconfirm that we detect this type error */
	testProg(t, "int 1; byte 0x1234; +", AssemblerMaxVersion, Expect{1, "+ arg 1..."})
	/* despite swap, we track types */
	testProg(t, "int 1; byte 0x1234; swap; +", AssemblerMaxVersion, Expect{1, "+ arg 0..."})
	testProg(t, "byte 0x1234; int 1; swap; +", AssemblerMaxVersion, Expect{1, "+ arg 1..."})
}

func TestDigAsm(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()
	testProg(t, "int 1; dig; +", AssemblerMaxVersion, Expect{1, "dig expects 1 immediate..."})
	testProg(t, "int 1; dig junk; +", AssemblerMaxVersion, Expect{1, "dig unable to parse..."})

	testProg(t, "int 1; byte 0x1234; int 2; dig 2; +", AssemblerMaxVersion)
	testProg(t, "byte 0x32; byte 0x1234; int 2; dig 2; +", AssemblerMaxVersion,
		Expect{1, "+ arg 1..."})
	testProg(t, "byte 0x32; byte 0x1234; int 2; dig 3; +", AssemblerMaxVersion,
		Expect{1, "dig 3 expects 4..."})
	testProg(t, "int 1; byte 0x1234; int 2; dig 12; +", AssemblerMaxVersion,
		Expect{1, "dig 12 expects 13..."})

	// Confirm that digging something out does not ruin our knowledge about the types in the middle
	testProg(t, "int 1; byte 0x1234; byte 0x1234; dig 2; dig 3; +; pop; +", AssemblerMaxVersion,
		Expect{1, "+ arg 1..."})
	testProg(t, "int 3; pushbytes \"123456\"; int 1; dig 2; substring3", AssemblerMaxVersion)

}

func TestBuryAsm(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()
	testProg(t, "int 1; bury; +", AssemblerMaxVersion, Expect{1, "bury expects 1 immediate..."})
	testProg(t, "int 1; bury junk; +", AssemblerMaxVersion, Expect{1, "bury unable to parse..."})

	testProg(t, "int 1; byte 0x1234; int 2; bury 1; +", AssemblerMaxVersion) // the 2 replaces the byte string
	testProg(t, "int 2; int 2; byte 0x1234; bury 1; +", AssemblerMaxVersion,
		Expect{1, "+ arg 1..."})
	testProg(t, "byte 0x32; byte 0x1234; int 2; bury 3; +", AssemblerMaxVersion,
		Expect{1, "bury 3 expects 4..."})
	testProg(t, "int 1; byte 0x1234; int 2; bury 12; +", AssemblerMaxVersion,
		Expect{1, "bury 12 expects 13..."})

	// We do not lose track of the ints between ToS and bury index
	testProg(t, "int 0; int 1; int 2; int 4; bury 3; concat", AssemblerMaxVersion,
		Expect{1, "concat arg 1 wanted type []byte..."})

	// Even when we are burying into unknown (seems repetitive, but is an easy bug)
	testProg(t, "int 0; int 0; b LABEL; LABEL: int 1; int 2; int 4; bury 4; concat", AssemblerMaxVersion,
		Expect{1, "concat arg 1 wanted type []byte..."})
}

func TestEqualsTypeCheck(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()
	testProg(t, "int 1; byte 0x1234; ==", AssemblerMaxVersion, Expect{1, "== arg 0..."})
	testProg(t, "int 1; byte 0x1234; !=", AssemblerMaxVersion, Expect{1, "!= arg 0..."})
	testProg(t, "byte 0x1234; int 1; ==", AssemblerMaxVersion, Expect{1, "== arg 0..."})
	testProg(t, "byte 0x1234; int 1; !=", AssemblerMaxVersion, Expect{1, "!= arg 0..."})
}

func TestDupTypeCheck(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()
	testProg(t, "byte 0x1234; dup; int 1; +", AssemblerMaxVersion, Expect{1, "+ arg 0..."})
	testProg(t, "byte 0x1234; int 1; dup; +", AssemblerMaxVersion)
	testProg(t, "byte 0x1234; int 1; dup2; +", AssemblerMaxVersion, Expect{1, "+ arg 0..."})
	testProg(t, "int 1; byte 0x1234; dup2; +", AssemblerMaxVersion, Expect{1, "+ arg 1..."})

	testProg(t, "byte 0x1234; int 1; dup; dig 1; len", AssemblerMaxVersion, Expect{1, "len arg 0..."})
	testProg(t, "int 1; byte 0x1234; dup; dig 1; !", AssemblerMaxVersion, Expect{1, "! arg 0..."})

	testProg(t, "byte 0x1234; int 1; dup2; dig 2; len", AssemblerMaxVersion, Expect{1, "len arg 0..."})
	testProg(t, "int 1; byte 0x1234; dup2; dig 2; !", AssemblerMaxVersion, Expect{1, "! arg 0..."})
}

func TestSelectTypeCheck(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()
	testProg(t, "int 1; int 2; int 3; select; len", AssemblerMaxVersion, Expect{1, "len arg 0..."})
	testProg(t, "byte 0x1234; byte 0x5678; int 3; select; !", AssemblerMaxVersion, Expect{1, "! arg 0..."})
}

func TestSetBitTypeCheck(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()
	testProg(t, "int 1; int 2; int 3; setbit; len", AssemblerMaxVersion, Expect{1, "len arg 0..."})
	testProg(t, "byte 0x1234; int 2; int 3; setbit; !", AssemblerMaxVersion, Expect{1, "! arg 0..."})
}

func TestScratchTypeCheck(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()
	// All scratch slots should start as uint64
	testProg(t, "load 0; int 1; +", AssemblerMaxVersion)
	// Check load and store accurately using the scratch space
	testProg(t, "byte 0x01; store 0; load 0; int 1; +", AssemblerMaxVersion, Expect{1, "+ arg 0..."})
	// Loads should know the type it's loading if all the slots are the same type
	testProg(t, "int 0; loads; btoi", AssemblerMaxVersion, Expect{1, "btoi arg 0..."})
	// Loads doesn't know the type when slot types vary
	testProg(t, "byte 0x01; store 0; int 1; loads; btoi", AssemblerMaxVersion)
	// Stores should only set slots to StackAny if they are not the same type as what is being stored
	testProg(t, "byte 0x01; store 0; int 3; byte 0x01; stores; load 0; int 1; +", AssemblerMaxVersion, Expect{1, "+ arg 0..."})
	// ScratchSpace should reset after hitting label in deadcode
	testProg(t, "byte 0x01; store 0; b label1; label1:; load 0; int 1; +", AssemblerMaxVersion)
	// But it should reset to StackAny not uint64
	testProg(t, "int 1; store 0; b label1; label1:; load 0; btoi", AssemblerMaxVersion)
	// Callsubs should also reset the scratch space
	testProg(t, "callsub A; load 0; btoi; return; A: byte 0x01; store 0; retsub", AssemblerMaxVersion)
	// But the scratchspace should still be tracked after the callsub
	testProg(t, "callsub A; int 1; store 0; load 0; btoi; return; A: retsub", AssemblerMaxVersion, Expect{1, "btoi arg 0..."})
}

// TestProtoAsm confirms that the assembler will yell at you if you are
// clearly dipping into the arguments when using `proto`.  You should be using
// `frame_dig`.
func TestProtoAsm(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()
	testProg(t, "proto 0 0", AssemblerMaxVersion, Expect{1, "proto must be unreachable..."})
	testProg(t, notrack("proto 0 0"), AssemblerMaxVersion)
	testProg(t, "b a; int 1; a: proto 0 0", AssemblerMaxVersion) // we could flag a `b` to `proto`

	testProg(t, `
 int 10
 int 20
 callsub main
 int 1
 return
main:
 proto 2 1
 +                              // This consumes the top arg. We complain.
 dup; dup						// Even though the dup;dup restores it, so it _evals_ fine.
 retsub
`, AssemblerMaxVersion)

}

func TestCoverAsm(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()
	testProg(t, `int 4; byte "john"; int 5; cover 2; pop; +`, AssemblerMaxVersion)
	testProg(t, `int 4; byte "ayush"; int 5; cover 1; pop; +`, AssemblerMaxVersion)
	testProg(t, `int 4; byte "john"; int 5; cover 2; +`, AssemblerMaxVersion, Expect{1, "+ arg 1..."})

	testProg(t, `int 4; cover junk`, AssemblerMaxVersion, Expect{1, "cover unable to parse n ..."})
	testProg(t, notrack(`int 4; int 5; cover 0`), AssemblerMaxVersion)
}

func TestUncoverAsm(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()
	testProg(t, `int 4; byte "john"; int 5; uncover 2; +`, AssemblerMaxVersion)
	testProg(t, `int 4; byte "ayush"; int 5; uncover 1; pop; +`, AssemblerMaxVersion)
	testProg(t, `int 1; byte "jj"; byte "ayush"; byte "john"; int 5; uncover 4; +`, AssemblerMaxVersion)
	testProg(t, `int 4; byte "ayush"; int 5; uncover 1; +`, AssemblerMaxVersion, Expect{1, "+ arg 1..."})
}

func TestTxTypes(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()
	testProg(t, "itxn_begin; itxn_field Sender", 5, Expect{1, "itxn_field Sender expects 1 stack argument..."})
	testProg(t, "itxn_begin; int 1; itxn_field Sender", 5, Expect{1, "...wanted type []byte got uint64"})
	testProg(t, "itxn_begin; byte 0x56127823; itxn_field Sender", 5)

	testProg(t, "itxn_begin; itxn_field Amount", 5, Expect{1, "itxn_field Amount expects 1 stack argument..."})
	testProg(t, "itxn_begin; byte 0x87123376; itxn_field Amount", 5, Expect{1, "...wanted type uint64 got []byte"})
	testProg(t, "itxn_begin; int 1; itxn_field Amount", 5)
}

func TestBadInnerFields(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()
	testProg(t, "itxn_begin; int 1000; itxn_field FirstValid", 5, Expect{1, "...is not allowed."})
	testProg(t, "itxn_begin; int 1000; itxn_field FirstValidTime", 5, Expect{1, "...is not allowed."})
	testProg(t, "itxn_begin; int 1000; itxn_field LastValid", 5, Expect{1, "...is not allowed."})
	testProg(t, "itxn_begin; int 32; bzero; itxn_field Lease", 5, Expect{1, "...is not allowed."})
	testProg(t, "itxn_begin; byte 0x7263; itxn_field Note", 5, Expect{1, "...Note field was introduced in v6..."})
	testProg(t, "itxn_begin; byte 0x7263; itxn_field VotePK", 5, Expect{1, "...VotePK field was introduced in v6..."})
	testProg(t, "itxn_begin; int 32; bzero; itxn_field TxID", 5, Expect{1, "...is not allowed."})

	testProg(t, "itxn_begin; int 1000; itxn_field FirstValid", 6, Expect{1, "...is not allowed."})
	testProg(t, "itxn_begin; int 1000; itxn_field LastValid", 6, Expect{1, "...is not allowed."})
	testProg(t, "itxn_begin; int 32; bzero; itxn_field Lease", 6, Expect{1, "...is not allowed."})
	testProg(t, "itxn_begin; byte 0x7263; itxn_field Note", 6)
	testProg(t, "itxn_begin; byte 0x7263; itxn_field VotePK", 6)
	testProg(t, "itxn_begin; int 32; bzero; itxn_field TxID", 6, Expect{1, "...is not allowed."})
}

func TestTypeTracking(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()
	testProg(t, "+", LogicVersion, Expect{1, "+ expects 2 stack arguments..."})

	// hitting a label in deadcode starts analyzing again, with unknown stack
	testProg(t, "b end; label: +; end: b label", LogicVersion)

	// callsub also wipes our stack knowledge, this tests shows why: it's properly typed
	testProg(t, "callsub A; +; return; A: int 1; int 2; retsub", LogicVersion)

	// but we do want to ensure we're not just treating the code after callsub as dead
	testProg(t, "callsub A; int 1; concat; return; A: int 1; int 2; retsub", LogicVersion,
		Expect{1, "concat arg 1 wanted..."})

	// retsub deadens code, like any unconditional branch
	testProg(t, "callsub A; +; return; A: int 1; int 2; retsub; concat", LogicVersion)

	// Branching would have confused the old analysis, but the problem is local
	// to a basic block, so it makes sense to report it.
	testProg(t, `
 int 1
 b confusion
label:
 byte "john"					// detectable mistake
 int 2
 +
confusion:
 b label
`, LogicVersion, Expect{7, "+ arg 0 wanted type uint64..."})

	// Unless that same error is in dead code.
	testProg(t, `
 int 1
 b confusion
label:
 err							// deadens the apparent error at +
 byte "john"
 int 2
 +
confusion:
 b label
`, LogicVersion)

	// Unconditional branches also deaden
	testProg(t, `
 int 1
 b confusion
label:
 b done							// deadens the apparent error at +
 byte "john"
 int 2
 +
confusion:
 b label
done:
`, LogicVersion)

	// Turning type tracking off and then back on, allows any follow-on code.
	testProg(t, `
 int 1
 int 2
#pragma typetrack false
 concat
`, LogicVersion)

	testProg(t, `
 int 1
 int 2
#pragma typetrack false
 concat
#pragma typetrack true
 concat
`, LogicVersion)

	// Declaring type tracking on consecutively does _not_ reset type tracking state.
	testProg(t, `
 int 1
 int 2
#pragma typetrack true
 concat
#pragma typetrack true
 concat
`, LogicVersion, Expect{5, "concat arg 1 wanted type []byte..."})
}

func TestMergeProtos(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()
	iVi := OpSpec{Proto: proto("i:i")}
	bVb := OpSpec{Proto: proto("b:b")}
	aaVa := OpSpec{Proto: proto("aa:a")}
	aVaa := OpSpec{Proto: proto("a:aa")}
	p, _, _ := mergeProtos(map[int]OpSpec{0: iVi, 1: bVb})
	require.Equal(t, proto("a:a"), p)
	_, _, ok := mergeProtos(map[int]OpSpec{0: aaVa, 1: iVi})
	require.False(t, ok)
	_, _, ok = mergeProtos(map[int]OpSpec{0: aVaa, 1: iVi})
	require.False(t, ok)
	medley := OpSpec{Proto: proto("aibibabai:aibibabai")}
	medley2 := OpSpec{Proto: proto("biabbaiia:biabbaiia")}
	p, _, _ = mergeProtos(map[int]OpSpec{0: medley, 1: medley2})
	require.Equal(t, proto("aiaabaaaa:aiaabaaaa"), p)
	v1 := OpSpec{Version: 1, Proto: proto(":")}
	v2 := OpSpec{Version: 2, Proto: proto(":")}
	_, v, _ := mergeProtos(map[int]OpSpec{0: v2, 1: v1})
	require.Equal(t, uint64(1), v)
}

// Extra tests for features of getSpec that are currently not tested elsewhere
func TestGetSpec(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()
	ops := testProg(t, "int 1", AssemblerMaxVersion)
	ops.versionedPseudoOps["dummyPseudo"] = make(map[int]OpSpec)
	ops.versionedPseudoOps["dummyPseudo"][1] = OpSpec{Name: "b:", Version: AssemblerMaxVersion, Proto: proto("b:")}
	ops.versionedPseudoOps["dummyPseudo"][2] = OpSpec{Name: ":", Version: AssemblerMaxVersion}
	_, _, ok := getSpec(ops, "dummyPseudo", []string{})
	require.False(t, ok)
	_, _, ok = getSpec(ops, "nonsense", []string{})
	require.False(t, ok)
	require.Equal(t, 2, len(ops.Errors))
	require.Equal(t, "unknown opcode: nonsense", ops.Errors[1].Err.Error())
}

func TestAddPseudoDocTags(t *testing.T) { //nolint:paralleltest // Not parallel because it modifies pseudoOps and opDocByName which are global maps
	partitiontest.PartitionTest(t)
	defer func() {
		delete(pseudoOps, "tests")
		delete(opDocByName, "multiple")
		delete(opDocByName, "single")
		delete(opDocByName, "none")
		delete(opDocByName, "any")
	}()

	pseudoOps["tests"] = map[int]OpSpec{2: {Name: "multiple"}, 1: {Name: "single"}, 0: {Name: "none"}, anyImmediates: {Name: "any"}}
	addPseudoDocTags()
	require.Equal(t, "`multiple` can be called using `tests` with 2 immediates.", opDocByName["multiple"])
	require.Equal(t, "`single` can be called using `tests` with 1 immediate.", opDocByName["single"])
	require.Equal(t, "`none` can be called using `tests` with no immediates.", opDocByName["none"])
	require.Equal(t, "", opDocByName["any"])
}
func TestReplacePseudo(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()
	replaceVersion := 7
	for v := uint64(replaceVersion); v <= AssemblerMaxVersion; v++ {
		testProg(t, "byte 0x0000; byte 0x1234; replace 0", v)
		testProg(t, "byte 0x0000; int 0; byte 0x1234; replace", v)
		testProg(t, "byte 0x0000; byte 0x1234; replace", v, Expect{1, "replace without immediates expects 3 stack arguments but stack height is 2"})
		testProg(t, "byte 0x0000; int 0; byte 0x1234; replace 0", v, Expect{1, "replace 0 arg 0 wanted type []byte got uint64"})
	}
}

func checkSame(t *testing.T, version uint64, first string, compares ...string) {
	t.Helper()
	if version == 0 {
		version = assemblerNoVersion
	}
	ops := testProg(t, first, version)
	for _, compare := range compares {
		other := testProg(t, compare, version)
		if bytes.Compare(other.Program, ops.Program) != 0 {
			t.Log(Disassemble(ops.Program))
			t.Log(Disassemble(other.Program))
		}
		assert.Equal(t, ops.Program, other.Program, "%s unlike %s", first, compare)
	}
}

func TestSemiColon(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	checkSame(t, AssemblerMaxVersion,
		"pushint 0 ; pushint 1 ; +; int 3 ; *",
		"pushint 0\npushint 1\n+\nint 3\n*",
		"pushint 0; pushint 1; +; int 3; *; // comment; int 2",
		"pushint 0; ; ; pushint 1 ; +; int 3 ; *//check",
	)

	checkSame(t, 0,
		"#pragma version 7\nint 1",
		"// junk;\n#pragma version 7\nint 1",
		"// junk;\n #pragma version 7\nint 1",
	)

	checkSame(t, AssemblerMaxVersion,
		`byte "test;this"; pop;`,
		`byte "test;this"; ; pop;`,
		`byte "test;this";;;pop;`,
	)
}

func TestAssembleSwitch(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	// fail when target doesn't correspond to existing label
	source := `
	pushint 1
	switch label1 label2
	label1:
	`
	testProg(t, source, AssemblerMaxVersion, NewExpect(3, "reference to undefined label \"label2\""))

	// fail when target index != uint64
	testProg(t, `
	byte "fail"
    switch label1
    labe11:
	`, AssemblerMaxVersion, Expect{3, "switch label1 arg 0 wanted type uint64..."})

	// No labels is pretty degenerate, but ok, I suppose. It's just a no-op
	testProg(t, `
int 0
switch
int 1
`, AssemblerMaxVersion)

	// confirm arg limit
	source = `
	pushint 1
	switch label1 label2
	label1:
	label2:
	`
	ops := testProg(t, source, AssemblerMaxVersion)
	require.Len(t, ops.Program, 9) // ver (1) + pushint (2) + opcode (1) + length (1) + labels (2*2)

	var labels []string
	for i := 0; i < 255; i++ {
		labels = append(labels, fmt.Sprintf("label%d", i))
	}

	// test that 255 labels is ok
	source = fmt.Sprintf(`
	pushint 1
	switch %s
	%s
	`, strings.Join(labels, " "), strings.Join(labels, ":\n")+":\n")
	ops = testProg(t, source, AssemblerMaxVersion)
	require.Len(t, ops.Program, 515) // ver (1) + pushint (2) + opcode (1) + length (1) + labels (2*255)

	// 256 is too many
	source = fmt.Sprintf(`
	pushint 1
	switch %s extra
	%s
	`, strings.Join(labels, " "), strings.Join(labels, ":\n")+":\n")
	ops = testProg(t, source, AssemblerMaxVersion, Expect{3, "switch cannot take more than 255 labels"})

	// allow duplicate label reference
	source = `
	pushint 1
	switch label1 label1
	label1:
	`
	testProg(t, source, AssemblerMaxVersion)
}

func TestAssembleMatch(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	// fail when target doesn't correspond to existing label
	source := `
	pushints 1 1 1
	match label1 label2
	label1:
	`
	testProg(t, source, AssemblerMaxVersion, NewExpect(3, "reference to undefined label \"label2\""))

	// No labels is pretty degenerate, but ok, I suppose. It's just a no-op
	testProg(t, `
int 0
match
int 1
`, AssemblerMaxVersion)

	// confirm arg limit
	source = `
	pushints 1 2 1
	match label1 label2
	label1:
	label2:
	`
	ops := testProg(t, source, AssemblerMaxVersion)
	require.Len(t, ops.Program, 12) // ver (1) + pushints (5) + opcode (1) + length (1) + labels (2*2)

	// confirm byte array args are assembled successfully
	source = `
	pushbytess "1" "2" "1"
	match label1 label2
	label1:
	label2:
	`
	testProg(t, source, AssemblerMaxVersion)

	var labels []string
	for i := 0; i < 255; i++ {
		labels = append(labels, fmt.Sprintf("label%d", i))
	}

	// test that 255 labels is ok
	source = fmt.Sprintf(`
	pushint 1
	match %s
	%s
	`, strings.Join(labels, " "), strings.Join(labels, ":\n")+":\n")
	ops = testProg(t, source, AssemblerMaxVersion)
	require.Len(t, ops.Program, 515) // ver (1) + pushint (2) + opcode (1) + length (1) + labels (2*255)

	// 256 is too many
	source = fmt.Sprintf(`
	pushint 1
	match %s extra
	%s
	`, strings.Join(labels, " "), strings.Join(labels, ":\n")+":\n")
	testProg(t, source, AssemblerMaxVersion, Expect{3, "match cannot take more than 255 labels"})

	// allow duplicate label reference
	source = `
	pushint 1
	match label1 label1
	label1:
	`
	testProg(t, source, AssemblerMaxVersion)
}

func TestAssemblePushConsts(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	// allow empty const int list
	source := `pushints`
	testProg(t, source, AssemblerMaxVersion)

	// allow empty const bytes list
	source = `pushbytess`
	testProg(t, source, AssemblerMaxVersion)

	// basic test
	source = `pushints 1 2 3`
	ops := testProg(t, source, AssemblerMaxVersion)
	require.Len(t, ops.Program, 6) // ver (1) + pushints (5)
	source = `pushbytess "1" "2" "33"`
	ops = testProg(t, source, AssemblerMaxVersion)
	require.Len(t, ops.Program, 10) // ver (1) + pushbytess (9)

	// 256 increases size of encoded length to two bytes
	valsStr := make([]string, 256)
	for i := range valsStr {
		valsStr[i] = fmt.Sprintf("%d", 1)
	}
	source = fmt.Sprintf(`pushints %s`, strings.Join(valsStr, " "))
	ops = testProg(t, source, AssemblerMaxVersion)
	require.Len(t, ops.Program, 260) // ver (1) + opcode (1) + len (2) + ints (256)

	for i := range valsStr {
		valsStr[i] = fmt.Sprintf("\"%d\"", 1)
	}
	source = fmt.Sprintf(`pushbytess %s`, strings.Join(valsStr, " "))
	ops = testProg(t, source, AssemblerMaxVersion)
	require.Len(t, ops.Program, 516) // ver (1) + opcode (1) + len (2) + bytess (512)

	// enforce correct types
	source = `pushints "1" "2" "3"`
	testProg(t, source, AssemblerMaxVersion, Expect{1, `strconv.ParseUint: parsing "\"1\"": invalid syntax`})
	source = `pushbytess 1 2 3`
	testProg(t, source, AssemblerMaxVersion, Expect{1, "byte arg did not parse: 1"})
	source = `pushints 6 4; concat`
	testProg(t, source, AssemblerMaxVersion, Expect{1, "concat arg 1 wanted type []byte got uint64"})
	source = `pushbytess "x" "y"; +`
	testProg(t, source, AssemblerMaxVersion, Expect{1, "+ arg 1 wanted type uint64 got []byte"})
}
