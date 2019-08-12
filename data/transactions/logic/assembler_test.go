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
sha256
keccak256
+
-
/
*
<
>
<=
>=
&&
||
==
!=
!
len
btoi
int 0x031337
byte 0x1234
`
	sr := strings.NewReader(text)
	pbytes := bytes.Buffer{}
	ops := OpStream{out: &pbytes}
	err := ops.Assemble(sr)
	require.NoError(t, err)
	s := hex.EncodeToString(pbytes.Bytes())
	t.Log(s)
}

func TestOpUint(t *testing.T) {
	pbytes := bytes.Buffer{}
	ops := OpStream{out: &pbytes}
	err := ops.Uint(0xcafebabe)
	require.NoError(t, err)
	s := hex.EncodeToString(pbytes.Bytes())
	require.Equal(t, "24cafebabe", s)
}

func TestOpBytes(t *testing.T) {
	pbytes := bytes.Buffer{}
	ops := OpStream{out: &pbytes}
	err := ops.ByteLiteral([]byte("abcdef"))
	require.NoError(t, err)
	s := hex.EncodeToString(pbytes.Bytes())
	require.Equal(t, "2906616263646566", s)
}

func TestAssembleInt(t *testing.T) {
	text := "int 0xcafebabe"
	sr := strings.NewReader(text)
	pbytes := bytes.Buffer{}
	ops := OpStream{out: &pbytes}
	err := ops.Assemble(sr)
	require.NoError(t, err)
	s := hex.EncodeToString(pbytes.Bytes())
	require.Equal(t, "24cafebabe", s)
}

func TestAssembleBytes(t *testing.T) {
	variations := []string{
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
		sr := strings.NewReader(vi)
		pbytes := bytes.Buffer{}
		ops := OpStream{out: &pbytes}
		err := ops.Assemble(sr)
		require.NoError(t, err)
		s := hex.EncodeToString(pbytes.Bytes())
		require.Equal(t, "2906616263646566", s)
	}
}
