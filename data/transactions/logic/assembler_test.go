package logic

import (
	"bytes"
	"encoding/hex"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestAssemble(t *testing.T) {
	text := `err
global Round
global MinTxnFee
global MinBalance
global MaxTxnLife
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
account Balance
sha256
keccak256
int 0x031337
int 0x1234567812345678
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
	sr := strings.NewReader(text)
	pbytes := bytes.Buffer{}
	ops := OpStream{Out: &pbytes}
	err := ops.Assemble(sr)
	require.NoError(t, err)
	//t.Log(hex.EncodeToString(pbytes.Bytes()))
}

func TestOpUint(t *testing.T) {
	pbytes := bytes.Buffer{}
	ops := OpStream{Out: &pbytes}
	err := ops.Uint(0xcafebabe)
	require.NoError(t, err)
	s := hex.EncodeToString(pbytes.Bytes())
	require.Equal(t, "24cafebabe", s)
}

func TestOpUint64(t *testing.T) {
	pbytes := bytes.Buffer{}
	ops := OpStream{Out: &pbytes}
	err := ops.Uint(0xcafebabecafebabe)
	require.NoError(t, err)
	s := hex.EncodeToString(pbytes.Bytes())
	require.Equal(t, "27cafebabecafebabe", s)
}

func TestOpBytes(t *testing.T) {
	pbytes := bytes.Buffer{}
	ops := OpStream{Out: &pbytes}
	err := ops.ByteLiteral([]byte("abcdef"))
	require.NoError(t, err)
	s := hex.EncodeToString(pbytes.Bytes())
	require.Equal(t, "2906616263646566", s)
}

func TestAssembleInt(t *testing.T) {
	text := "int 0xcafebabe"
	sr := strings.NewReader(text)
	pbytes := bytes.Buffer{}
	ops := OpStream{Out: &pbytes}
	err := ops.Assemble(sr)
	require.NoError(t, err)
	s := hex.EncodeToString(pbytes.Bytes())
	require.Equal(t, "24cafebabe", s)
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
		sr := strings.NewReader(vi)
		pbytes := bytes.Buffer{}
		ops := OpStream{Out: &pbytes}
		err := ops.Assemble(sr)
		require.NoError(t, err)
		s := hex.EncodeToString(pbytes.Bytes())
		require.Equal(t, "2906616263646566", s)
	}
}
