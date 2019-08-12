package logic

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

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
	t.Log(sb.String())
}
