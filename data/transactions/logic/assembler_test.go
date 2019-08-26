package logic

import (
	"bytes"
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestAssemble(t *testing.T) {
	text := `err
global Round
global MinTxnFee
global MinBalance
global MaxTxnLife
global TimeStamp
byte 0x1234
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
arg 0
arg 1
//account Balance
sha256
keccak256
int 0x031337
int 0x1234567812345678
int 0x0034567812345678
int 0x0000567812345678
int 0x0000007812345678
+
// extra int pushes to satisfy typechecking on the ops that pop two ints
int 0
-
int 2
/
int 1
*
int 1
<
int 1
>
int 1
<=
int 1
>=
int 1
&&
int 1
||
int 1
==
int 1
!=
int 1
!
byte 0x4242
len
byte 0x4242
btoi
`
	program, err := AssembleString(text)
	require.NoError(t, err)
	// check that compilation is stable over time and we assemble to the same bytes this month that we did last month.
	expectedBytes, _ := hex.DecodeString("2008b7a60cf8acd19181cf959a12f8acd19181cf951af8acd19181cf15f8acd191810f00020126020212340242420032003201320232033204283100310131023103310431053106310731083109310a310b2d2e01022223242521040821050921060a21070b21070c21070d21070e21070f21071021071121071221071321071429152917")
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
	require.Equal(t, "2001bef5fad70c22", s)
}

func TestOpUint64(t *testing.T) {
	ops := OpStream{}
	err := ops.Uint(0xcafebabecafebabe)
	require.NoError(t, err)
	program, err := ops.Bytes()
	require.NoError(t, err)
	s := hex.EncodeToString(program)
	require.Equal(t, "2001bef5fad7ecd7aeffca0122", s)
}

func TestOpBytes(t *testing.T) {
	ops := OpStream{}
	err := ops.ByteLiteral([]byte("abcdef"))
	program, err := ops.Bytes()
	require.NoError(t, err)
	s := hex.EncodeToString(program)
	require.Equal(t, "26010661626364656628", s)
}

func TestAssembleInt(t *testing.T) {
	text := "int 0xcafebabe"
	program, err := AssembleString(text)
	require.NoError(t, err)
	s := hex.EncodeToString(program)
	require.Equal(t, "2001bef5fad70c22", s)
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
		require.Equal(t, "26010661626364656628", s)
	}
}
