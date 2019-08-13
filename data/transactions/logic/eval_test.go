package logic

import (
	"encoding/hex"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/transactions"
)

func TestTrivialMath(t *testing.T) {
	program, err := AssembleString(`int 2
int 3
+
int 5
==`)
	require.NoError(t, err)
	pass := Eval(program, EvalParams{})
	require.True(t, pass)
}

func TestSha256EqArg(t *testing.T) {
	program, err := AssembleString(`arg 0
sha256
byte base64 5rZMNsevs5sULO+54aN+OvU6lQ503z2X+SSYUABIx7E=
==`)
	require.NoError(t, err)
	var txn transactions.SignedTxn
	txn.Lsig.Logic.Logic = program
	txn.Lsig.Args = [][]byte{[]byte("=0\x97S\x85H\xe9\x91B\xfd\xdb;1\xf5Z\xaec?\xae\xf2I\x93\x08\x12\x94\xaa~\x06\x08\x849b")}
	sb := strings.Builder{}
	ep := EvalParams{Txn: &txn, Trace: &sb}
	pass := Eval(program, ep)
	require.True(t, pass)
	//t.Log(sb.String())
}

func TestTLHC(t *testing.T) {
	a1, _ := basics.UnmarshalChecksumAddress("OC6IROKUJ7YCU5NV76AZJEDKYQG33V2CJ7HAPVQ4ENTAGMLIOINSQ6EKGE")
	a2, _ := basics.UnmarshalChecksumAddress("RWXCBB73XJITATVQFOI7MVUUQOL2PFDDSDUMW4H4T2SNSX4SEUOQ2MM7F4")
	program, err := AssembleString(`txn CloseRemainderTo
addr OC6IROKUJ7YCU5NV76AZJEDKYQG33V2CJ7HAPVQ4ENTAGMLIOINSQ6EKGE
==
arg 0
len
int 32
==
&&
arg 0
sha256
byte base64 5rZMNsevs5sULO+54aN+OvU6lQ503z2X+SSYUABIx7E=
==
&&
txn CloseRemainderTo
addr RWXCBB73XJITATVQFOI7MVUUQOL2PFDDSDUMW4H4T2SNSX4SEUOQ2MM7F4
==
global Round
int 100000
>
&&
||`)
	require.NoError(t, err)
	var txn transactions.SignedTxn
	txn.Lsig.Logic.Logic = program
	// right answer
	txn.Lsig.Args = [][]byte{[]byte("=0\x97S\x85H\xe9\x91B\xfd\xdb;1\xf5Z\xaec?\xae\xf2I\x93\x08\x12\x94\xaa~\x06\x08\x849b")}
	sb := strings.Builder{}
	ep := EvalParams{Txn: &txn, Trace: &sb, Round: 999999}
	pass := Eval(program, ep)
	if pass {
		t.Log(sb.String())
	}
	require.False(t, pass)

	txn.Txn.CloseRemainderTo = a2
	sb = strings.Builder{}
	ep = EvalParams{Txn: &txn, Trace: &sb, Round: 999999}
	pass = Eval(program, ep)
	if !pass {
		t.Log(sb.String())
	}
	require.True(t, pass)

	txn.Txn.CloseRemainderTo = a2
	sb = strings.Builder{}
	ep = EvalParams{Txn: &txn, Trace: &sb, Round: 1}
	pass = Eval(program, ep)
	if pass {
		t.Log(sb.String())
	}
	require.False(t, pass)

	txn.Txn.CloseRemainderTo = a1
	sb = strings.Builder{}
	ep = EvalParams{Txn: &txn, Trace: &sb, Round: 999999}
	pass = Eval(program, ep)
	if !pass {
		t.Log(sb.String())
	}
	require.True(t, pass)

	// wrong answer
	txn.Lsig.Args = [][]byte{[]byte("=0\x97S\x85H\xe9\x91B\xfd\xdb;1\xf5Z\xaec?\xae\xf2I\x93\x08\x12\x94\xaa~\x06\x08\x849a")}
	sb = strings.Builder{}
	ep = EvalParams{Txn: &txn, Trace: &sb, Round: 1}
	pass = Eval(program, ep)
	if pass {
		t.Log(sb.String())
	}
	require.False(t, pass)
}

func TestU64Math(t *testing.T) {
	program, err := AssembleString(`int 0x1234567812345678
int 0x100000000
/
int 0x12345678
==`)
	require.NoError(t, err)
	sb := strings.Builder{}
	pass := Eval(program, EvalParams{Trace: &sb})
	if !pass {
		t.Log(hex.EncodeToString(program))
		t.Log(sb.String())
	}
	require.True(t, pass)
}
