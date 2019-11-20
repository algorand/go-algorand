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
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/bookkeeping"
	"github.com/algorand/go-algorand/data/transactions"
	"github.com/algorand/go-algorand/logging"
	"github.com/algorand/go-algorand/protocol"
)

func defaultEvalProto() config.ConsensusParams {
	return config.ConsensusParams{LogicSigVersion: 1, LogicSigMaxCost: 20000}
}

func defaultEvalParams(sb *strings.Builder, txn *transactions.SignedTxn) EvalParams {
	proto := defaultEvalProto()

	var pt *transactions.SignedTxn
	if txn != nil {
		pt = txn
	} else {
		var at transactions.SignedTxn
		pt = &at
	}

	if sb == nil { // have to do this since go's nil semantics: https://golang.org/doc/faq#nil_error
		return EvalParams{Proto: &proto, Txn: pt}
	}

	return EvalParams{Proto: &proto, Trace: sb, Txn: pt}
}

func TestTooManyArgs(t *testing.T) {
	t.Parallel()
	program, err := AssembleString(`int 1`)
	require.NoError(t, err)
	var txn transactions.SignedTxn
	txn.Lsig.Logic = program
	args := [EvalMaxArgs + 1][]byte{}
	txn.Lsig.Args = args[:]
	sb := strings.Builder{}
	pass, err := Eval(program, defaultEvalParams(&sb, &txn))
	require.Error(t, err)
	require.False(t, pass)
}

func TestWrongProtoVersion(t *testing.T) {
	t.Parallel()
	program, err := AssembleString(`int 1`)
	require.NoError(t, err)
	var txn transactions.SignedTxn
	txn.Lsig.Logic = program
	sb := strings.Builder{}
	proto := defaultEvalProto()
	proto.LogicSigVersion = 0
	pass, err := Eval(program, EvalParams{Proto: &proto, Trace: &sb, Txn: &txn})
	require.Error(t, err)
	require.False(t, pass)
}

func TestTrivialMath(t *testing.T) {
	t.Parallel()
	program, err := AssembleString(`int 2
int 3
+
int 5
==`)
	require.NoError(t, err)
	cost, err := Check(program, defaultEvalParams(nil, nil))
	require.NoError(t, err)
	require.True(t, cost < 1000)
	var txn transactions.SignedTxn
	txn.Lsig.Logic = program
	pass, err := Eval(program, defaultEvalParams(nil, &txn))
	require.True(t, pass)
	require.NoError(t, err)
}

func TestSha256EqArg(t *testing.T) {
	t.Parallel()
	program, err := AssembleString(`arg 0
sha256
byte base64 5rZMNsevs5sULO+54aN+OvU6lQ503z2X+SSYUABIx7E=
==`)
	require.NoError(t, err)
	var txn transactions.SignedTxn
	txn.Lsig.Logic = program
	txn.Lsig.Args = [][]byte{[]byte("=0\x97S\x85H\xe9\x91B\xfd\xdb;1\xf5Z\xaec?\xae\xf2I\x93\x08\x12\x94\xaa~\x06\x08\x849b")}
	sb := strings.Builder{}
	proto := defaultEvalProto()
	ep := EvalParams{Proto: &proto, Txn: &txn, Trace: &sb}
	cost, err := Check(program, ep)
	require.NoError(t, err)
	require.True(t, cost < 1000)
	pass, err := Eval(program, ep)
	require.True(t, pass)
	require.NoError(t, err)
}

const tlhcProgramText = `txn CloseRemainderTo
addr DFPKC2SJP3OTFVJFMCD356YB7BOT4SJZTGWLIPPFEWL3ZABUFLTOY6ILYE
==
txn Receiver
addr DFPKC2SJP3OTFVJFMCD356YB7BOT4SJZTGWLIPPFEWL3ZABUFLTOY6ILYE
==
&&
arg 0
len
int 32
==
&&
arg 0
sha256
byte base64 r8St7smOQ0LV55o8AUmGGrpgnYwVmg4wCxeLA/H8Z+s=
==
&&
txn CloseRemainderTo
addr YYKRMERAFXMXCDWMBNR6BUUWQXDCUR53FPUGXLUYS7VNASRTJW2ENQ7BMQ
==
txn Receiver
addr YYKRMERAFXMXCDWMBNR6BUUWQXDCUR53FPUGXLUYS7VNASRTJW2ENQ7BMQ
==
&&
txn FirstValid
int 3000
>
&&
||
txn Fee
int 1000000
<
&&`

func TestTLHC(t *testing.T) {
	t.Parallel()
	a1, _ := basics.UnmarshalChecksumAddress("DFPKC2SJP3OTFVJFMCD356YB7BOT4SJZTGWLIPPFEWL3ZABUFLTOY6ILYE")
	a2, _ := basics.UnmarshalChecksumAddress("YYKRMERAFXMXCDWMBNR6BUUWQXDCUR53FPUGXLUYS7VNASRTJW2ENQ7BMQ")
	secret, _ := base64.StdEncoding.DecodeString("xPUB+DJir1wsH7g2iEY1QwYqHqYH1vUJtzZKW4RxXsY=")
	program, err := AssembleString(tlhcProgramText)
	require.NoError(t, err)
	var txn transactions.SignedTxn
	txn.Lsig.Logic = program
	// right answer
	txn.Lsig.Args = [][]byte{secret}
	txn.Txn.FirstValid = 999999
	sb := strings.Builder{}
	block := bookkeeping.Block{}
	proto := defaultEvalProto()
	ep := EvalParams{Proto: &proto, Txn: &txn, Trace: &sb}
	cost, err := Check(program, ep)
	if err != nil {
		t.Log(hex.EncodeToString(program))
		t.Log(sb.String())
	}
	require.NoError(t, err)
	require.True(t, cost < 1000)
	pass, err := Eval(program, ep)
	if pass {
		t.Log(hex.EncodeToString(program))
		t.Log(sb.String())
	}
	require.False(t, pass)
	isNotPanic(t, err)

	txn.Txn.Receiver = a2
	txn.Txn.CloseRemainderTo = a2
	sb = strings.Builder{}
	ep = EvalParams{Proto: &proto, Txn: &txn, Trace: &sb}
	pass, err = Eval(program, ep)
	if !pass {
		t.Log(hex.EncodeToString(program))
		t.Log(sb.String())
	}
	require.True(t, pass)
	require.NoError(t, err)

	txn.Txn.Receiver = a2
	txn.Txn.CloseRemainderTo = a2
	sb = strings.Builder{}
	txn.Txn.FirstValid = 1
	ep = EvalParams{Proto: &proto, Txn: &txn, Trace: &sb}
	pass, err = Eval(program, ep)
	if pass {
		t.Log(hex.EncodeToString(program))
		t.Log(sb.String())
	}
	require.False(t, pass)
	isNotPanic(t, err)

	txn.Txn.Receiver = a1
	txn.Txn.CloseRemainderTo = a1
	sb = strings.Builder{}
	txn.Txn.FirstValid = 999999
	ep = EvalParams{Proto: &proto, Txn: &txn, Trace: &sb}
	pass, err = Eval(program, ep)
	if !pass {
		t.Log(hex.EncodeToString(program))
		t.Log(sb.String())
	}
	require.True(t, pass)
	require.NoError(t, err)

	// wrong answer
	txn.Lsig.Args = [][]byte{[]byte("=0\x97S\x85H\xe9\x91B\xfd\xdb;1\xf5Z\xaec?\xae\xf2I\x93\x08\x12\x94\xaa~\x06\x08\x849a")}
	sb = strings.Builder{}
	block.BlockHeader.Round = 1
	ep = EvalParams{Proto: &proto, Txn: &txn, Trace: &sb}
	pass, err = Eval(program, ep)
	if pass {
		t.Log(hex.EncodeToString(program))
		t.Log(sb.String())
	}
	require.False(t, pass)
	isNotPanic(t, err)
}

func TestU64Math(t *testing.T) {
	t.Parallel()
	program, err := AssembleString(`int 0x1234567812345678
int 0x100000000
/
int 0x12345678
==`)
	require.NoError(t, err)
	sb := strings.Builder{}
	pass, err := Eval(program, defaultEvalParams(&sb, nil))
	if !pass {
		t.Log(hex.EncodeToString(program))
		t.Log(sb.String())
	}
	require.True(t, pass)
	require.NoError(t, err)
}

func TestItob(t *testing.T) {
	t.Parallel()
	program, err := AssembleString(`byte 0x1234567812345678
int 0x1234567812345678
itob
==`)
	require.NoError(t, err)
	sb := strings.Builder{}
	pass, err := Eval(program, defaultEvalParams(&sb, nil))
	if !pass {
		t.Log(hex.EncodeToString(program))
		t.Log(sb.String())
	}
	require.NoError(t, err)
	require.True(t, pass)
}

func TestBtoi(t *testing.T) {
	t.Parallel()
	program, err := AssembleString(`int 0x1234567812345678
byte 0x1234567812345678
btoi
==`)
	require.NoError(t, err)
	sb := strings.Builder{}
	pass, err := Eval(program, defaultEvalParams(&sb, nil))
	if !pass {
		t.Log(hex.EncodeToString(program))
		t.Log(sb.String())
	}
	require.NoError(t, err)
	require.True(t, pass)
}

func TestBtoiTooLong(t *testing.T) {
	t.Parallel()
	program, err := AssembleString(`int 0x1234567812345678
byte 0x1234567812345678aaaa
btoi
==`)
	require.NoError(t, err)
	sb := strings.Builder{}
	pass, err := Eval(program, defaultEvalParams(&sb, nil))
	if pass {
		t.Log(hex.EncodeToString(program))
		t.Log(sb.String())
	}
	require.False(t, pass)
	require.Error(t, err)
	isNotPanic(t, err)
}

func TestBnz(t *testing.T) {
	t.Parallel()
	program, err := AssembleString(`int 1
dup
bnz safe
err
safe:
int 1
+`)
	require.NoError(t, err)
	cost, err := Check(program, defaultEvalParams(nil, nil))
	require.NoError(t, err)
	require.True(t, cost < 1000)
	sb := strings.Builder{}
	pass, err := Eval(program, defaultEvalParams(&sb, nil))
	if !pass {
		t.Log(hex.EncodeToString(program))
		t.Log(sb.String())
	}
	require.NoError(t, err)
	require.True(t, pass)
}

func TestBnz2(t *testing.T) {
	t.Parallel()
	program, err := AssembleString(`int 1
int 2
int 1
int 2
>
bnz planb
*
int 1
bnz after
planb:
+
after:
dup
pop
`)
	require.NoError(t, err)
	cost, err := Check(program, defaultEvalParams(nil, nil))
	require.NoError(t, err)
	require.True(t, cost < 1000)
	sb := strings.Builder{}
	pass, err := Eval(program, defaultEvalParams(&sb, nil))
	if !pass {
		t.Log(hex.EncodeToString(program))
		t.Log(sb.String())
	}
	require.NoError(t, err)
	require.True(t, pass)
}

func TestSubUnderflow(t *testing.T) {
	t.Parallel()
	program, err := AssembleString(`int 1
int 0x100000000
-
pop
int 1`)
	require.NoError(t, err)
	cost, err := Check(program, defaultEvalParams(nil, nil))
	require.NoError(t, err)
	require.True(t, cost < 1000)
	sb := strings.Builder{}
	pass, err := Eval(program, defaultEvalParams(&sb, nil))
	if pass {
		t.Log(hex.EncodeToString(program))
		t.Log(sb.String())
	}
	require.False(t, pass)
	require.Error(t, err)
	isNotPanic(t, err)
}

func TestAddOverflow(t *testing.T) {
	t.Parallel()
	program, err := AssembleString(`int 0xf000000000000000
int 0x1111111111111111
+
pop
int 1`)
	require.NoError(t, err)
	cost, err := Check(program, defaultEvalParams(nil, nil))
	require.NoError(t, err)
	require.True(t, cost < 1000)
	sb := strings.Builder{}
	pass, err := Eval(program, defaultEvalParams(&sb, nil))
	if pass {
		t.Log(hex.EncodeToString(program))
		t.Log(sb.String())
	}
	require.False(t, pass)
	require.Error(t, err)
	isNotPanic(t, err)
}

func TestMulOverflow(t *testing.T) {
	t.Parallel()
	program, err := AssembleString(`int 0x111111111
int 0x222222222
*
pop
int 1`)
	require.NoError(t, err)
	cost, err := Check(program, defaultEvalParams(nil, nil))
	require.NoError(t, err)
	require.True(t, cost < 1000)
	sb := strings.Builder{}
	pass, err := Eval(program, defaultEvalParams(&sb, nil))
	if pass {
		t.Log(hex.EncodeToString(program))
		t.Log(sb.String())
	}
	require.False(t, pass)
	require.Error(t, err)
	isNotPanic(t, err)
}

func TestMulwImpl(t *testing.T) {
	t.Parallel()
	high, low, err := opMulwImpl(1, 2)
	require.NoError(t, err)
	require.Equal(t, uint64(0), high)
	require.Equal(t, uint64(2), low)

	high, low, err = opMulwImpl(0x111111111, 0x222222222)
	require.NoError(t, err)
	require.Equal(t, uint64(2), high)
	require.Equal(t, uint64(0x468acf130eca8642), low)

	high, low, err = opMulwImpl(1, 0)
	require.NoError(t, err)
	require.Equal(t, uint64(0), high)
	require.Equal(t, uint64(0), low)

	high, low, err = opMulwImpl((1<<64)-1, (1<<64)-1)
	require.NoError(t, err)
	require.Equal(t, uint64(0xfffffffffffffffe), high)
	require.Equal(t, uint64(1), low)
}

func TestMulw(t *testing.T) {
	t.Parallel()
	// multiply two numbers, ensure high is 2 and low is 0x468acf130eca8642
	program, err := AssembleString(`int 0x111111111
int 0x222222222
mulw
int 0x468acf130eca8642  // compare low (top of the stack)
==
bnz continue
err
continue:
int 2                   // compare high
==
bnz done
err
done:
int 1                   // ret 1
`)
	require.NoError(t, err)
	cost, err := Check(program, defaultEvalParams(nil, nil))
	require.NoError(t, err)
	require.True(t, cost < 1000)
	sb := strings.Builder{}
	pass, err := Eval(program, defaultEvalParams(&sb, nil))
	if !pass {
		t.Log(hex.EncodeToString(program))
		t.Log(sb.String())
	}
	require.True(t, pass)
	require.NoError(t, err)
}

func TestDivZero(t *testing.T) {
	t.Parallel()
	program, err := AssembleString(`int 0x111111111
int 0
/
pop
int 1`)
	require.NoError(t, err)
	sb := strings.Builder{}
	cost, err := Check(program, defaultEvalParams(&sb, nil))
	if err != nil {
		t.Log(hex.EncodeToString(program))
		t.Log(sb.String())
	}
	require.NoError(t, err)
	require.True(t, cost < 1000)
	pass, err := Eval(program, defaultEvalParams(&sb, nil))
	if pass {
		t.Log(hex.EncodeToString(program))
		t.Log(sb.String())
	}
	require.False(t, pass)
	require.Error(t, err)
	isNotPanic(t, err)
}

func TestModZero(t *testing.T) {
	t.Parallel()
	program, err := AssembleString(`int 0x111111111
int 0
%
pop
int 1`)
	require.NoError(t, err)
	cost, err := Check(program, defaultEvalParams(nil, nil))
	require.NoError(t, err)
	require.True(t, cost < 1000)
	sb := strings.Builder{}
	pass, err := Eval(program, defaultEvalParams(&sb, nil))
	if pass {
		t.Log(hex.EncodeToString(program))
		t.Log(sb.String())
	}
	require.False(t, pass)
	require.Error(t, err)
	isNotPanic(t, err)
}

func TestErr(t *testing.T) {
	t.Parallel()
	program, err := AssembleString(`err
int 1`)
	require.NoError(t, err)
	cost, err := Check(program, defaultEvalParams(nil, nil))
	require.NoError(t, err)
	require.True(t, cost < 1000)
	sb := strings.Builder{}
	pass, err := Eval(program, defaultEvalParams(&sb, nil))
	if pass {
		t.Log(hex.EncodeToString(program))
		t.Log(sb.String())
	}
	require.False(t, pass)
	require.Error(t, err)
	isNotPanic(t, err)
}

func TestModSubMulOk(t *testing.T) {
	t.Parallel()
	program, err := AssembleString(`int 35
int 16
%
int 1
-
int 2
*
int 4
==`)
	require.NoError(t, err)
	cost, err := Check(program, defaultEvalParams(nil, nil))
	require.NoError(t, err)
	require.True(t, cost < 1000)
	sb := strings.Builder{}
	pass, err := Eval(program, defaultEvalParams(&sb, nil))
	if !pass {
		t.Log(hex.EncodeToString(program))
		t.Log(sb.String())
	}
	require.NoError(t, err)
	require.True(t, pass)
}

func TestPop(t *testing.T) {
	t.Parallel()
	program, err := AssembleString(`int 1
int 0
pop`)
	require.NoError(t, err)
	sb := strings.Builder{}
	cost, err := Check(program, defaultEvalParams(&sb, nil))
	require.NoError(t, err)
	require.True(t, cost < 1000)
	sb = strings.Builder{}
	pass, err := Eval(program, defaultEvalParams(&sb, nil))
	if !pass {
		t.Log(hex.EncodeToString(program))
		t.Log(sb.String())
	}
	require.NoError(t, err)
	require.True(t, pass)
}

func TestStackLeftover(t *testing.T) {
	t.Parallel()
	program, err := AssembleString(`int 1
int 1`)
	require.NoError(t, err)
	sb := strings.Builder{}
	cost, err := Check(program, defaultEvalParams(&sb, nil))
	require.NoError(t, err)
	require.True(t, cost < 1000)
	sb = strings.Builder{}
	pass, err := Eval(program, defaultEvalParams(&sb, nil))
	if pass {
		t.Log(hex.EncodeToString(program))
		t.Log(sb.String())
	}
	require.Error(t, err)
	require.False(t, pass)
	isNotPanic(t, err)
}

func TestStackBytesLeftover(t *testing.T) {
	t.Parallel()
	program, err := AssembleString(`byte 0x10101010`)
	require.NoError(t, err)
	sb := strings.Builder{}
	cost, err := Check(program, defaultEvalParams(&sb, nil))
	require.NoError(t, err)
	require.True(t, cost < 1000)
	sb = strings.Builder{}
	pass, err := Eval(program, defaultEvalParams(&sb, nil))
	if pass {
		t.Log(hex.EncodeToString(program))
		t.Log(sb.String())
	}
	require.Error(t, err)
	require.False(t, pass)
	isNotPanic(t, err)
}

func TestStackEmpty(t *testing.T) {
	t.Parallel()
	program, err := AssembleString(`int 1
int 1
pop
pop`)
	require.NoError(t, err)
	cost, err := Check(program, defaultEvalParams(nil, nil))
	require.NoError(t, err)
	require.True(t, cost < 1000)
	sb := strings.Builder{}
	pass, err := Eval(program, defaultEvalParams(&sb, nil))
	if pass {
		t.Log(hex.EncodeToString(program))
		t.Log(sb.String())
	}
	require.Error(t, err)
	require.False(t, pass)
	isNotPanic(t, err)
}

func TestArgTooFar(t *testing.T) {
	t.Parallel()
	program, err := AssembleString(`arg_1
btoi`)
	require.NoError(t, err)
	cost, err := Check(program, defaultEvalParams(nil, nil))
	//require.Error(t, err)
	require.True(t, cost < 1000)
	sb := strings.Builder{}
	var txn transactions.SignedTxn
	txn.Lsig.Logic = program
	txn.Lsig.Args = nil
	pass, err := Eval(program, defaultEvalParams(&sb, &txn))
	if pass {
		t.Log(hex.EncodeToString(program))
		t.Log(sb.String())
	}
	require.Error(t, err)
	require.False(t, pass)
	isNotPanic(t, err)
}

func TestIntcTooFar(t *testing.T) {
	t.Parallel()
	program, err := AssembleString(`intc_1`)
	require.NoError(t, err)
	cost, err := Check(program, defaultEvalParams(nil, nil))
	//require.Error(t, err)
	require.True(t, cost < 1000)
	sb := strings.Builder{}
	var txn transactions.SignedTxn
	txn.Lsig.Logic = program
	txn.Lsig.Args = nil
	proto := defaultEvalProto()
	pass, err := Eval(program, EvalParams{Proto: &proto, Trace: &sb, Txn: &txn})
	if pass {
		t.Log(hex.EncodeToString(program))
		t.Log(sb.String())
	}
	require.Error(t, err)
	require.False(t, pass)
	isNotPanic(t, err)
}

func TestBytecTooFar(t *testing.T) {
	t.Parallel()
	program, err := AssembleString(`bytec_1
btoi`)
	require.NoError(t, err)
	cost, err := Check(program, defaultEvalParams(nil, nil))
	//require.Error(t, err)
	require.True(t, cost < 1000)
	sb := strings.Builder{}
	var txn transactions.SignedTxn
	txn.Lsig.Logic = program
	txn.Lsig.Args = nil
	pass, err := Eval(program, defaultEvalParams(&sb, &txn))
	if pass {
		t.Log(hex.EncodeToString(program))
		t.Log(sb.String())
	}
	require.Error(t, err)
	require.False(t, pass)
	isNotPanic(t, err)
}

func TestTxnBadField(t *testing.T) {
	t.Parallel()
	program := []byte{0x01, 0x31, 0x7f}
	cost, err := Check(program, defaultEvalParams(nil, nil))
	//require.Error(t, err)
	require.True(t, cost < 1000)
	sb := strings.Builder{}
	var txn transactions.SignedTxn
	txn.Lsig.Logic = program
	txn.Lsig.Args = nil
	proto := defaultEvalProto()
	pass, err := Eval(program, EvalParams{Proto: &proto, Trace: &sb, Txn: &txn})
	if pass {
		t.Log(hex.EncodeToString(program))
		t.Log(sb.String())
	}
	require.Error(t, err)
	require.False(t, pass)
	isNotPanic(t, err)
}

func TestGtxnBadIndex(t *testing.T) {
	t.Parallel()
	program := []byte{0x01, 0x33, 0x1, 0x01}
	cost, err := Check(program, defaultEvalParams(nil, nil))
	//require.Error(t, err)
	require.True(t, cost < 1000)
	sb := strings.Builder{}
	var txn transactions.SignedTxn
	txn.Lsig.Logic = program
	txn.Lsig.Args = nil
	txgroup := make([]transactions.SignedTxn, 1)
	txgroup[0] = txn
	proto := defaultEvalProto()
	pass, err := Eval(program, EvalParams{Proto: &proto, Trace: &sb, Txn: &txn, TxnGroup: txgroup})
	if pass {
		t.Log(hex.EncodeToString(program))
		t.Log(sb.String())
	}
	require.Error(t, err)
	require.False(t, pass)
	isNotPanic(t, err)
}

func TestGtxnBadField(t *testing.T) {
	t.Parallel()
	program := []byte{0x01, 0x33, 0x0, 0x7f}
	cost, err := Check(program, defaultEvalParams(nil, nil))
	//require.Error(t, err)
	require.True(t, cost < 1000)
	sb := strings.Builder{}
	var txn transactions.SignedTxn
	txn.Lsig.Logic = program
	txn.Lsig.Args = nil
	txgroup := make([]transactions.SignedTxn, 1)
	txgroup[0] = txn
	proto := defaultEvalProto()
	pass, err := Eval(program, EvalParams{Proto: &proto, Trace: &sb, Txn: &txn, TxnGroup: txgroup})
	if pass {
		t.Log(hex.EncodeToString(program))
		t.Log(sb.String())
	}
	require.Error(t, err)
	require.False(t, pass)
	isNotPanic(t, err)
}

func TestGlobalBadField(t *testing.T) {
	t.Parallel()
	program := []byte{0x01, 0x32, 0x7f}
	cost, err := Check(program, defaultEvalParams(nil, nil))
	//require.Error(t, err)
	require.True(t, cost < 1000)
	sb := strings.Builder{}
	var txn transactions.SignedTxn
	txn.Lsig.Logic = program
	txn.Lsig.Args = nil
	pass, err := Eval(program, defaultEvalParams(&sb, &txn))
	if pass {
		t.Log(hex.EncodeToString(program))
		t.Log(sb.String())
	}
	require.Error(t, err)
	require.False(t, pass)
	isNotPanic(t, err)
}

func TestArg(t *testing.T) {
	t.Parallel()
	program, err := AssembleString(`arg 0
arg 1
==
arg 2
arg 3
!=
&&
arg 4
len
int 9
<
&&`)
	require.NoError(t, err)
	cost, err := Check(program, defaultEvalParams(nil, nil))
	require.NoError(t, err)
	require.True(t, cost < 1000)
	var txn transactions.SignedTxn
	txn.Lsig.Logic = program
	txn.Lsig.Args = [][]byte{
		[]byte("aoeu"),
		[]byte("aoeu"),
		[]byte("aoeu2"),
		[]byte("aoeu3"),
		[]byte("aoeu4"),
	}
	sb := strings.Builder{}
	pass, err := Eval(program, defaultEvalParams(&sb, &txn))
	if !pass {
		t.Log(hex.EncodeToString(program))
		t.Log(sb.String())
	}
	require.NoError(t, err)
	require.True(t, pass)
}

const globalTestProgram = `global MinTxnFee
int 123
==
global MinBalance
int 1000000
==
&&
global MaxTxnLife
int 999
==
&&
global ZeroAddress
txn CloseRemainderTo
==
//&&
//global TimeStamp
//int 2069
//==
//&&
//global Round
//int 999999
//==
&&
global GroupSize
int 1
==
&&`

func TestGlobal(t *testing.T) {
	t.Parallel()
	for _, globalField := range GlobalFieldNames {
		if !strings.Contains(globalTestProgram, globalField) {
			t.Errorf("TestGlobal missing field %v", globalField)
		}
	}
	program, err := AssembleString(globalTestProgram)
	require.NoError(t, err)
	cost, err := Check(program, defaultEvalParams(nil, nil))
	require.NoError(t, err)
	require.True(t, cost < 1000)
	var txn transactions.SignedTxn
	txn.Lsig.Logic = program
	txgroup := make([]transactions.SignedTxn, 1)
	txgroup[0] = txn
	sb := strings.Builder{}
	block := bookkeeping.Block{}
	block.BlockHeader.Round = 999999
	block.BlockHeader.TimeStamp = 2069
	proto := config.ConsensusParams{
		MinTxnFee:       123,
		MinBalance:      1000000,
		MaxTxnLife:      999,
		LogicSigVersion: 1,
		LogicSigMaxCost: 20000,
	}
	ep := EvalParams{
		Trace:    &sb,
		Txn:      &txn,
		Proto:    &proto,
		TxnGroup: txgroup,
	}
	pass, err := Eval(program, ep)
	if !pass {
		t.Log(hex.EncodeToString(program))
		t.Log(sb.String())
	}
	require.NoError(t, err)
	require.True(t, pass)
}

func TestTypeEnum(t *testing.T) {
	t.Parallel()
	ttypes := []protocol.TxType{
		protocol.PaymentTx,
		protocol.KeyRegistrationTx,
		protocol.AssetConfigTx,
		protocol.AssetTransferTx,
		protocol.AssetFreezeTx,
	}
	// this is explicitly a local copy of the list so that someone
	// doesn't accidentally disconnect the doc.go
	// typeEnumDescriptions from its need in assembler.go
	typeNames := []string{
		"Payment",
		"KeyRegistration",
		"AssetConfig",
		"AssetTransfer",
		"AssetFreeze",
	}
	for i, tt := range ttypes {
		symbol := typeNames[i]
		t.Run(string(symbol), func(t *testing.T) {
			text := fmt.Sprintf(`txn TypeEnum
int %s
==
txn TypeEnum
int %s
==
&&`, symbol, string(tt))
			program, err := AssembleString(text)
			require.NoError(t, err)
			cost, err := Check(program, defaultEvalParams(nil, nil))
			require.NoError(t, err)
			require.True(t, cost < 1000)
			var txn transactions.SignedTxn
			txn.Txn.Type = tt
			sb := strings.Builder{}
			proto := defaultEvalProto()
			pass, err := Eval(program, EvalParams{Proto: &proto, Trace: &sb, Txn: &txn, GroupIndex: 3})
			if !pass {
				t.Log(hex.EncodeToString(program))
				t.Log(sb.String())
			}
			require.NoError(t, err)
			require.True(t, pass)
		})
	}
}

const testTxnProgramText = `txn Sender
arg 0
==
txn Receiver
arg 1
==
&&
txn CloseRemainderTo
arg 2
==
&&
txn VotePK
arg 3
==
&&
txn SelectionPK
arg 4
==
&&
txn Note
arg 5
==
&&
txn Fee
int 1337
==
&&
txn FirstValid
int 42
==
&&
txn LastValid
int 1066
==
&&
txn Amount
int 1000000
==
&&
txn VoteFirst
int 1317
==
&&
txn VoteLast
int 17776
==
&&
txn VoteKeyDilution
int 1
==
&&
txn Type
byte 0x706179
==
&&
txn TypeEnum
int 1
==
&&
txn XferAsset
int 10
==
&&
txn AssetAmount
int 1234
==
&&
txn AssetSender
arg 1
==
&&
txn AssetReceiver
arg 2
==
&&
txn AssetCloseTo
arg 0
==
&&
txn GroupIndex
int 3
==
&&
txn TxID
arg 7
==
&&
txn Lease
arg 8
==
&&`

func TestTxn(t *testing.T) {
	t.Parallel()
	for _, txnField := range TxnFieldNames {
		if !strings.Contains(testTxnProgramText, txnField) {
			if txnField != FirstValidTime.String() {
				t.Errorf("TestTxn missing field %v", txnField)
			}
		}
	}
	program, err := AssembleString(testTxnProgramText)
	require.NoError(t, err)
	cost, err := Check(program, defaultEvalParams(nil, nil))
	require.NoError(t, err)
	require.True(t, cost < 1000)
	var txn transactions.SignedTxn
	copy(txn.Txn.Sender[:], []byte("aoeuiaoeuiaoeuiaoeuiaoeuiaoeui00"))
	copy(txn.Txn.Receiver[:], []byte("aoeuiaoeuiaoeuiaoeuiaoeuiaoeui01"))
	copy(txn.Txn.CloseRemainderTo[:], []byte("aoeuiaoeuiaoeuiaoeuiaoeuiaoeui02"))
	copy(txn.Txn.VotePK[:], []byte("aoeuiaoeuiaoeuiaoeuiaoeuiaoeui03"))
	copy(txn.Txn.SelectionPK[:], []byte("aoeuiaoeuiaoeuiaoeuiaoeuiaoeui04"))
	txn.Txn.XferAsset = 10
	// This is not a valid transaction to have all these fields set this way
	txn.Txn.Note = []byte("fnord")
	copy(txn.Txn.Lease[:], []byte("woofwoof"))
	txn.Txn.Fee.Raw = 1337
	txn.Txn.FirstValid = 42
	txn.Txn.LastValid = 1066
	txn.Txn.Amount.Raw = 1000000
	txn.Txn.VoteFirst = 1317
	txn.Txn.VoteLast = 17776
	txn.Txn.VoteKeyDilution = 1
	txn.Txn.Type = protocol.PaymentTx
	txn.Txn.AssetAmount = 1234
	txn.Txn.AssetSender = txn.Txn.Receiver
	txn.Txn.AssetReceiver = txn.Txn.CloseRemainderTo
	txn.Txn.AssetCloseTo = txn.Txn.Sender
	txn.Lsig.Logic = program
	txid := txn.Txn.ID()
	txn.Lsig.Args = [][]byte{
		txn.Txn.Sender[:],
		txn.Txn.Receiver[:],
		txn.Txn.CloseRemainderTo[:],
		txn.Txn.VotePK[:],
		txn.Txn.SelectionPK[:],
		txn.Txn.Note,
		[]byte{0, 0, 0, 0, 0, 0, 0, 1},
		txid[:],
		txn.Txn.Lease[:],
	}
	sb := strings.Builder{}
	proto := defaultEvalProto()
	pass, err := Eval(program, EvalParams{Proto: &proto, Trace: &sb, Txn: &txn, GroupIndex: 3})
	if !pass {
		t.Log(hex.EncodeToString(program))
		t.Log(sb.String())
	}
	require.NoError(t, err)
	require.True(t, pass)
}

func TestGtxn(t *testing.T) {
	t.Parallel()
	program, err := AssembleString(`gtxn 1 Amount
int 42
==
gtxn 1 Fee
int 1066
==
&&
gtxn 1 FirstValid
int 42
==
&&
gtxn 1 LastValid
int 1066
==
&&
gtxn 1 Sender
arg 1
==
&&
gtxn 1 Receiver
arg 0
==
&&
gtxn 0 Sender
txn Sender
==
&&
txn Sender
arg 0
==
&&
gtxn 0 Receiver
txn Receiver
==
&&
txn Receiver
arg 1
==
&&
gtxn 0 GroupIndex
int 0
==
&&
gtxn 1 GroupIndex
int 1
==
&&
global GroupSize
int 2
==
&&`)
	require.NoError(t, err)
	sb := strings.Builder{}
	cost, err := Check(program, defaultEvalParams(&sb, nil))
	if err != nil {
		t.Log(hex.EncodeToString(program))
		t.Log(sb.String())
	}
	require.NoError(t, err)
	require.True(t, cost < 1000)
	txgroup := make([]transactions.SignedTxn, 2)
	var txn transactions.SignedTxn
	copy(txn.Txn.Sender[:], []byte("aoeuiaoeuiaoeuiaoeuiaoeuiaoeui00"))
	copy(txn.Txn.Receiver[:], []byte("aoeuiaoeuiaoeuiaoeuiaoeuiaoeui01"))
	copy(txn.Txn.CloseRemainderTo[:], []byte("aoeuiaoeuiaoeuiaoeuiaoeuiaoeui02"))
	copy(txn.Txn.VotePK[:], []byte("aoeuiaoeuiaoeuiaoeuiaoeuiaoeui03"))
	copy(txn.Txn.SelectionPK[:], []byte("aoeuiaoeuiaoeuiaoeuiaoeuiaoeui04"))
	txn.Txn.Note = []byte("fnord")
	txn.Txn.Fee.Raw = 1337
	txn.Txn.FirstValid = 42
	txn.Txn.LastValid = 1066
	txn.Txn.Amount.Raw = 1000000
	txn.Txn.VoteFirst = 1317
	txn.Txn.VoteLast = 17776
	txn.Txn.VoteKeyDilution = 1
	txgroup[0] = txn
	txgroup[1].Txn.Amount.Raw = 42
	txgroup[1].Txn.Fee.Raw = 1066
	txgroup[1].Txn.FirstValid = 42
	txgroup[1].Txn.LastValid = 1066
	txgroup[1].Txn.Sender = txn.Txn.Receiver
	txgroup[1].Txn.Receiver = txn.Txn.Sender
	txn.Lsig.Logic = program
	txn.Lsig.Args = [][]byte{
		txn.Txn.Sender[:],
		txn.Txn.Receiver[:],
		txn.Txn.CloseRemainderTo[:],
		txn.Txn.VotePK[:],
		txn.Txn.SelectionPK[:],
		txn.Txn.Note,
	}
	sb = strings.Builder{}
	proto := defaultEvalProto()
	pass, err := Eval(program, EvalParams{Proto: &proto, Trace: &sb, Txn: &txn, TxnGroup: txgroup})
	if !pass || err != nil {
		t.Log(hex.EncodeToString(program))
		t.Log(sb.String())
	}
	require.NoError(t, err)
	require.True(t, pass)
}

func TestBitOps(t *testing.T) {
	t.Parallel()
	program, err := AssembleString(`int 0x17
int 0x3e
& // == 0x16
int 0x0a
^ // == 0x1c
int 0x0f
~
&
int 0x300
|
int 0x310
==`)
	require.NoError(t, err)
	cost, err := Check(program, defaultEvalParams(nil, nil))
	require.NoError(t, err)
	require.True(t, cost < 1000)
	sb := strings.Builder{}
	pass, err := Eval(program, defaultEvalParams(&sb, nil))
	if !pass {
		t.Log(hex.EncodeToString(program))
		t.Log(sb.String())
	}
	require.NoError(t, err)
	require.True(t, pass)
}

func TestLoadStore(t *testing.T) {
	t.Parallel()
	program, err := AssembleString(`int 37
int 37
store 1
byte 0xabbacafe
store 42
int 37
==
store 0
load 42
byte 0xabbacafe
==
load 0
load 1
+
&&`)
	require.NoError(t, err)
	cost, err := Check(program, defaultEvalParams(nil, nil))
	require.NoError(t, err)
	require.True(t, cost < 1000)
	sb := strings.Builder{}
	pass, err := Eval(program, defaultEvalParams(&sb, nil))
	if !pass {
		t.Log(hex.EncodeToString(program))
		t.Log(sb.String())
	}
	require.NoError(t, err)
	require.True(t, pass)
}

func assembleStringWithTrace(t testing.TB, text string) ([]byte, error) {
	sr := strings.NewReader(text)
	sb := strings.Builder{}
	ops := OpStream{Trace: &sb}
	err := ops.Assemble(sr)
	if err != nil {
		t.Log(sb.String())
		return nil, err
	}
	return ops.Bytes()
}

func TestLoadStore2(t *testing.T) {
	t.Parallel()
	program, err := assembleStringWithTrace(t, `int 2
int 3
byte 0xaa
store 44
store 43
store 42
load 43
load 42
+
int 5
==`)
	require.NoError(t, err)
	cost, err := Check(program, defaultEvalParams(nil, nil))
	require.NoError(t, err)
	require.True(t, cost < 1000)
	sb := strings.Builder{}
	pass, err := Eval(program, defaultEvalParams(&sb, nil))
	if !pass {
		t.Log(hex.EncodeToString(program))
		t.Log(sb.String())
	}
	require.NoError(t, err)
	require.True(t, pass)
}

const testCompareProgramText = `int 35
int 16
>
int 1
int 2
>
!
!
!
&&
int 1
int 2
<
int 35
int 1
<
!
&&
&&
int 2
int 2
<=
int 16
int 1
<=
!
&&
&&
int 2
int 2
>=
int 1
int 16
>=
!
&&
&&
int 2
int 1
!=
&&
byte 0xaaaa
byte 0xbbbb
==
!
&&
byte 0x1337
byte 0x1337
==
byte 0xabba
byte 0xabba
!=
!
&&
byte 0xcafe
byte 0xf00d
!=
&&
&&`

func TestCompares(t *testing.T) {
	t.Parallel()
	program, err := AssembleString(testCompareProgramText)
	require.NoError(t, err)
	cost, err := Check(program, defaultEvalParams(nil, nil))
	require.NoError(t, err)
	require.True(t, cost < 1000)
	sb := strings.Builder{}
	pass, err := Eval(program, defaultEvalParams(nil, nil))
	if !pass {
		t.Log(hex.EncodeToString(program))
		t.Log(sb.String())
	}
	require.NoError(t, err)
	require.True(t, pass)
}

func TestKeccak256(t *testing.T) {
	t.Parallel()
	/*
		pip install sha3
		import sha3
		blob=b'fnord'
		sha3.keccak_256(blob).hexdigest()
	*/
	program, err := AssembleString(`byte 0x666E6F7264
keccak256
byte 0xc195eca25a6f4c82bfba0287082ddb0d602ae9230f9cf1f1a40b68f8e2c41567
==`)
	require.NoError(t, err)
	cost, err := Check(program, defaultEvalParams(nil, nil))
	require.NoError(t, err)
	require.True(t, cost < 1000)
	sb := strings.Builder{}
	pass, err := Eval(program, defaultEvalParams(nil, nil))
	if !pass {
		t.Log(hex.EncodeToString(program))
		t.Log(sb.String())
	}
	require.NoError(t, err)
	require.True(t, pass)
}

func TestSHA512_256(t *testing.T) {
	t.Parallel()
	/*
		pip cryptography
		from cryptography.hazmat.backends import default_backend
		from cryptography.hazmat.primitives import hashes
		import base64
		digest = hashes.Hash(hashes.SHA512_256(), backend=default_backend())
		digest.update(b'fnord')
		base64.b16encode(digest.finalize())
	*/
	program, err := AssembleString(`byte 0x666E6F7264
sha512_256

byte 0x98D2C31612EA500279B6753E5F6E780CA63EBA8274049664DAD66A2565ED1D2A
==`)
	require.NoError(t, err)
	cost, err := Check(program, defaultEvalParams(nil, nil))
	require.NoError(t, err)
	require.True(t, cost < 1000)
	sb := strings.Builder{}
	pass, err := Eval(program, defaultEvalParams(&sb, nil))
	if !pass {
		t.Log(hex.EncodeToString(program))
		t.Log(sb.String())
	}
	require.NoError(t, err)
	require.True(t, pass)
}

func isNotPanic(t *testing.T, err error) {
	if err == nil {
		return
	}
	if pe, ok := err.(PanicError); ok {
		t.Error(pe)
	}
}

func TestStackUnderflow(t *testing.T) {
	t.Parallel()
	program, err := AssembleString(`int 1`)
	program = append(program, 0x08) // +
	require.NoError(t, err)
	cost, err := Check(program, defaultEvalParams(nil, nil))
	require.NoError(t, err)
	require.True(t, cost < 1000)
	sb := strings.Builder{}
	pass, err := Eval(program, defaultEvalParams(&sb, nil))
	if pass {
		t.Log(hex.EncodeToString(program))
		t.Log(sb.String())
	}
	require.False(t, pass)
	isNotPanic(t, err)
}

func TestWrongStackTypeRuntime(t *testing.T) {
	t.Parallel()
	program, err := AssembleString(`int 1`)
	require.NoError(t, err)
	program = append(program, 0x01, 0x15) // sha256, len
	cost, err := Check(program, defaultEvalParams(nil, nil))
	require.NoError(t, err)
	require.True(t, cost < 1000)
	sb := strings.Builder{}
	pass, err := Eval(program, defaultEvalParams(&sb, nil))
	if pass {
		t.Log(hex.EncodeToString(program))
		t.Log(sb.String())
	}
	require.False(t, pass)
	isNotPanic(t, err)
}

func TestEqMismatch(t *testing.T) {
	t.Parallel()
	program, err := AssembleString(`byte 0x1234
int 1`)
	require.NoError(t, err)
	program = append(program, 0x12) // ==
	cost, err := Check(program, defaultEvalParams(nil, nil))
	//require.Error(t, err) // Check should know the type stack was wrong
	require.True(t, cost < 1000)
	sb := strings.Builder{}
	pass, err := Eval(program, defaultEvalParams(&sb, nil))
	if pass {
		t.Log(hex.EncodeToString(program))
		t.Log(sb.String())
	}
	require.False(t, pass)
	isNotPanic(t, err)
}

func TestNeqMismatch(t *testing.T) {
	t.Parallel()
	program, err := AssembleString(`byte 0x1234
int 1`)
	require.NoError(t, err)
	program = append(program, 0x13) // !=
	cost, err := Check(program, defaultEvalParams(nil, nil))
	//require.Error(t, err) // Check should know the type stack was wrong
	require.True(t, cost < 1000)
	sb := strings.Builder{}
	pass, err := Eval(program, defaultEvalParams(&sb, nil))
	if pass {
		t.Log(hex.EncodeToString(program))
		t.Log(sb.String())
	}
	require.False(t, pass)
	isNotPanic(t, err)
}

func TestWrongStackTypeRuntime2(t *testing.T) {
	t.Parallel()
	program, err := AssembleString(`byte 0x1234
int 1`)
	require.NoError(t, err)
	program = append(program, 0x08) // +
	cost, err := Check(program, defaultEvalParams(nil, nil))
	require.NoError(t, err)
	require.True(t, cost < 1000)
	sb := strings.Builder{}
	pass, _ := Eval(program, defaultEvalParams(&sb, nil))
	if pass {
		t.Log(hex.EncodeToString(program))
		t.Log(sb.String())
	}
	require.False(t, pass)
	isNotPanic(t, err)
}

func TestIllegalOp(t *testing.T) {
	t.Parallel()
	program, err := AssembleString(`int 1`)
	require.NoError(t, err)
	for opcode, spec := range opsByOpcode {
		if spec.op == nil {
			program = append(program, byte(opcode))
			break
		}
	}
	cost, err := Check(program, defaultEvalParams(nil, nil))
	require.Error(t, err)
	require.True(t, cost < 1000)
	sb := strings.Builder{}
	pass, err := Eval(program, defaultEvalParams(&sb, nil))
	if pass {
		t.Log(hex.EncodeToString(program))
		t.Log(sb.String())
	}
	require.False(t, pass)
	isNotPanic(t, err)
}

func TestShortProgram(t *testing.T) {
	t.Parallel()
	program, err := AssembleString(`int 1
bnz done
done:`)
	require.NoError(t, err)
	program = program[:len(program)-1]
	cost, err := Check(program, defaultEvalParams(nil, nil))
	require.Error(t, err)
	require.True(t, cost < 1000)
	sb := strings.Builder{}
	pass, err := Eval(program, defaultEvalParams(&sb, nil))
	if pass {
		t.Log(hex.EncodeToString(program))
		t.Log(sb.String())
	}
	require.False(t, pass)
	isNotPanic(t, err)
}

func TestShortBytecblock(t *testing.T) {
	t.Parallel()
	fullprogram, err := AssembleString(`bytecblock 0x123456 0xababcdcd`)
	require.NoError(t, err)
	fullprogram[2] = 50 // fake 50 elements
	for i := 2; i < len(fullprogram); i++ {
		program := fullprogram[:i]
		t.Run(hex.EncodeToString(program), func(t *testing.T) {
			cost, err := Check(program, defaultEvalParams(nil, nil))
			require.Error(t, err)
			isNotPanic(t, err)
			require.True(t, cost < 1000)
			sb := strings.Builder{}
			pass, err := Eval(program, defaultEvalParams(&sb, nil))
			if pass {
				t.Log(hex.EncodeToString(program))
				t.Log(sb.String())
			}
			require.False(t, pass)
			isNotPanic(t, err)
		})
	}
}

func TestShortBytecblock2(t *testing.T) {
	t.Parallel()
	sources := []string{
		"01260180fe83f88fe0bf80ff01aa",
		"0026efbfbdefbfbd02",
		"0026efbfbdefbfbd30",
	}
	for _, src := range sources {
		t.Run(src, func(t *testing.T) {
			program, err := hex.DecodeString(src)
			require.NoError(t, err)
			cost, err := Check(program, defaultEvalParams(nil, nil))
			require.Error(t, err)
			isNotPanic(t, err)
			require.True(t, cost < 1000)
			sb := strings.Builder{}
			pass, err := Eval(program, defaultEvalParams(&sb, nil))
			if pass {
				t.Log(hex.EncodeToString(program))
				t.Log(sb.String())
			}
			require.False(t, pass)
			isNotPanic(t, err)
		})
	}
}

const panicString = "out of memory, buffer overrun, stack overflow, divide by zero, halt and catch fire"

func opPanic(cx *evalContext) {
	panic(panicString)
}
func checkPanic(cx *evalContext) int {
	panic(panicString)
}

func TestPanic(t *testing.T) {
	log := logging.TestingLog(t)
	program, err := AssembleString(`int 1`)
	require.NoError(t, err)
	var hackedOpcode int
	var oldSpec OpSpec
	var oldOz opSize
	for opcode, spec := range opsByOpcode {
		if spec.op == nil {
			hackedOpcode = opcode
			oldSpec = spec
			opsByOpcode[opcode].op = opPanic
			program = append(program, byte(opcode))
			oldOz = opSizeByOpcode[opcode]
			opSizeByOpcode[opcode].checkFunc = checkPanic
			break
		}
	}
	sb := strings.Builder{}
	params := defaultEvalParams(&sb, nil)
	params.Logger = log
	_, err = Check(program, params)
	require.Error(t, err)
	if pe, ok := err.(PanicError); ok {
		require.Equal(t, panicString, pe.PanicValue)
		pes := pe.Error()
		require.True(t, strings.Contains(pes, "panic"))
	} else {
		t.Errorf("expected PanicError object but got %T %#v", err, err)
	}
	sb = strings.Builder{}
	var txn transactions.SignedTxn
	txn.Lsig.Logic = program
	params = defaultEvalParams(&sb, &txn)
	params.Logger = log
	pass, err := Eval(program, params)
	if pass {
		t.Log(hex.EncodeToString(program))
		t.Log(sb.String())
	}
	require.False(t, pass)
	if pe, ok := err.(PanicError); ok {
		require.Equal(t, panicString, pe.PanicValue)
		pes := pe.Error()
		require.True(t, strings.Contains(pes, "panic"))
	} else {
		t.Errorf("expected PanicError object but got %T %#v", err, err)
	}
	opsByOpcode[hackedOpcode] = oldSpec
	opSizeByOpcode[hackedOpcode] = oldOz
}

func TestProgramTooNew(t *testing.T) {
	t.Parallel()
	var program [12]byte
	vlen := binary.PutUvarint(program[:], EvalMaxVersion+1)
	_, err := Check(program[:vlen], defaultEvalParams(nil, nil))
	require.Error(t, err)
	isNotPanic(t, err)
	pass, err := Eval(program[:vlen], defaultEvalParams(nil, nil))
	require.Error(t, err)
	require.False(t, pass)
	isNotPanic(t, err)
}

func TestInvalidVersion(t *testing.T) {
	t.Parallel()
	program, err := hex.DecodeString("ffffffffffffffffffffffff")
	require.NoError(t, err)
	_, err = Check(program, defaultEvalParams(nil, nil))
	require.Error(t, err)
	isNotPanic(t, err)
	pass, err := Eval(program, defaultEvalParams(nil, nil))
	require.Error(t, err)
	require.False(t, pass)
	isNotPanic(t, err)
}

func TestProgramProtoForbidden(t *testing.T) {
	t.Parallel()
	var program [12]byte
	vlen := binary.PutUvarint(program[:], EvalMaxVersion)
	proto := config.ConsensusParams{
		LogicSigVersion: EvalMaxVersion - 1,
	}
	_, err := Check(program[:vlen], EvalParams{Proto: &proto})
	require.Error(t, err)
	pass, err := Eval(program[:vlen], EvalParams{Proto: &proto})
	require.Error(t, err)
	require.False(t, pass)
	isNotPanic(t, err)
}

func TestMisalignedBranch(t *testing.T) {
	t.Parallel()
	program, err := AssembleString(`int 1
bnz done
bytecblock 0x01234576 0xababcdcd 0xf000baad
done:
int 1`)
	require.NoError(t, err)
	//t.Log(hex.EncodeToString(program))
	canonicalProgramBytes, err := hex.DecodeString("01200101224000112603040123457604ababcdcd04f000baad22")
	require.NoError(t, err)
	require.Equal(t, program, canonicalProgramBytes)
	program[7] = 3 // clobber the branch offset to be in the middle of the bytecblock
	_, err = Check(program, defaultEvalParams(nil, nil))
	require.Error(t, err)
	require.True(t, strings.Contains(err.Error(), "aligned"))
	pass, err := Eval(program, defaultEvalParams(nil, nil))
	require.Error(t, err)
	require.False(t, pass)
	isNotPanic(t, err)
}

func TestBranchTooFar(t *testing.T) {
	t.Parallel()
	program, err := AssembleString(`int 1
bnz done
bytecblock 0x01234576 0xababcdcd 0xf000baad
done:
int 1`)
	require.NoError(t, err)
	//t.Log(hex.EncodeToString(program))
	canonicalProgramBytes, err := hex.DecodeString("01200101224000112603040123457604ababcdcd04f000baad22")
	require.NoError(t, err)
	require.Equal(t, program, canonicalProgramBytes)
	program[7] = 200 // clobber the branch offset to be beyond the end of the program
	_, err = Check(program, defaultEvalParams(nil, nil))
	require.Error(t, err)
	require.True(t, strings.Contains(err.Error(), "beyond end of program"))
	pass, err := Eval(program, defaultEvalParams(nil, nil))
	require.Error(t, err)
	require.False(t, pass)
	isNotPanic(t, err)
}

func TestBranchTooLarge(t *testing.T) {
	t.Parallel()
	program, err := AssembleString(`int 1
bnz done
bytecblock 0x01234576 0xababcdcd 0xf000baad
done:
int 1`)
	require.NoError(t, err)
	//t.Log(hex.EncodeToString(program))
	canonicalProgramBytes, err := hex.DecodeString("01200101224000112603040123457604ababcdcd04f000baad22")
	require.NoError(t, err)
	require.Equal(t, program, canonicalProgramBytes)
	program[6] = 0xff // clobber the branch offset
	_, err = Check(program, defaultEvalParams(nil, nil))
	require.Error(t, err)
	require.True(t, strings.Contains(err.Error(), "too large"))
	pass, err := Eval(program, defaultEvalParams(nil, nil))
	require.Error(t, err)
	require.False(t, pass)
	isNotPanic(t, err)
}

/*
import random

def foo():
    for i in range(64):
        print('int {}'.format(random.randint(0,0x01ffffffffffffff)))
    for i in range(63):
        print('+')
*/
const addBenchmarkSource = `int 20472989571761113
int 80135167795737348
int 82174311944429262
int 18931946579653924
int 86155566607833591
int 1075021650573098
int 111652925954576936
int 135816594699663681
int 95344703885594586
int 122008589353955977
int 18682052868475822
int 6138676654186678
int 20318468210965565
int 41658258833442472
int 91731346037864488
int 122139121435492988
int 26527854151871033
int 97338225264319204
int 25225248073587158
int 26100029986766316
int 60361353774534329
int 122688610635077438
int 49726419125607815
int 26503250239309259
int 119040983139984526
int 12011745214067851
int 31103272093953594
int 19204804146789985
int 12319800308943462
int 35502003493132076
int 106417245469171849
int 129474471398607782
int 44744778376398162
int 88410275629377985
int 116489483148350180
int 102087738254976559
int 143005882611202070
int 57504305414978645
int 110445133719028573
int 24798855744653327
int 136537029232278114
int 96936727456694383
int 36951444151675279
int 1840647181459511
int 59139903823863499
int 28555970664661021
int 10770808248633273
int 4304440203913654
int 81225684287443549
int 51323495747459532
int 100914439082427354
int 91910226015228157
int 91438017996272107
int 24250386108370072
int 10016824859197666
int 61956446598005486
int 122571500041060621
int 15780818228280099
int 23540734418623763
int 30323254416524169
int 106160861143997231
int 58165567211420687
int 138605754086449805
int 28939890412103745
+
+
+
+
+
+
+
+
+
+
+
+
+
+
+
+
+
+
+
+
+
+
+
+
+
+
+
+
+
+
+
+
+
+
+
+
+
+
+
+
+
+
+
+
+
+
+
+
+
+
+
+
+
+
+
+
+
+
+
+
+
+
+
`

/*
import random

def foo():
    print('int {}'.format(random.randint(0,0x01ffffffffffffff)))
    for i in range(63):
        print('int {}'.format(random.randint(0,0x01ffffffffffffff)))
        print('+')
*/
const addBenchmark2Source = `int 8371863094338737
int 29595196041051360
+
int 139118528533666612
+
int 1421009403968912
+
int 907617584182604
+
int 8610485121810683
+
int 56818679638570570
+
int 22722200339071385
+
int 128025265808578871
+
int 30214594087062427
+
int 70941633792780019
+
int 68616285258830882
+
int 95617532397241262
+
int 137803932055116903
+
int 1240289092018042
+
int 114673410328755260
+
int 67006610117006306
+
int 108421978090249937
+
int 78170195495060544
+
int 109275909558212614
+
int 66046923927123871
+
int 85038805453063903
+
int 60775346571260341
+
int 22114958484139378
+
int 52262205171951711
+
int 33857856730782173
+
int 71141287912053397
+
int 119377806837197308
+
int 71417754584546836
+
int 122806020139022328
+
int 36646716042861244
+
int 99968579159521499
+
int 35488485222921935
+
int 16751897248756917
+
int 141620224053202253
+
int 13915744590935845
+
int 47411828952734632
+
int 94685514634950476
+
int 125511802479415110
+
int 34477253888878684
+
int 16061684214002734
+
int 58318330808434953
+
int 410385592781599
+
int 143008385493466625
+
int 103852750058221787
+
int 129643830537163971
+
int 100586050355894544
+
int 128489246083999182
+
int 84841243787957913
+
int 7286131447045084
+
int 36477256468337911
+
int 44619578152091966
+
int 53048951105105392
+
int 138234731403382207
+
int 54350808956391553
+
int 106338486498394095
+
int 111905698472755554
+
int 40677661094001844
+
int 20981945982205996
+
int 49847844071908901
+
int 39461620270393089
+
int 25635555040376697
+
int 37469742568207216
+
int 142791994204213819
+
`

func benchmarkBasicProgram(b *testing.B, source string) {
	program, err := AssembleString(source)
	require.NoError(b, err)
	cost, err := Check(program, defaultEvalParams(nil, nil))
	require.NoError(b, err)
	require.True(b, cost < 2000)
	//b.Logf("%d bytes of program", len(program))
	//b.Log(hex.EncodeToString(program))
	proto := defaultEvalProto()
	b.ResetTimer()
	sb := strings.Builder{} // Trace: &sb
	for i := 0; i < b.N; i++ {
		pass, err := Eval(program, EvalParams{Proto: &proto})
		if !pass {
			b.Log(sb.String())
		}
		// require is super slow but makes useful error messages, wrap it in a check that makes the benchmark run a bunch faster
		if err != nil {
			require.NoError(b, err)
		}
		if !pass {
			require.True(b, pass)
		}
	}
}

func benchmarkExpensiveProgram(b *testing.B, source string) {
	program, err := AssembleString(source)
	require.NoError(b, err)
	cost, err := Check(program, defaultEvalParams(nil, nil))
	require.NoError(b, err)
	require.True(b, cost > 1000)
	//b.Logf("%d bytes of program", len(program))
	//b.Log(hex.EncodeToString(program))
	b.ResetTimer()
	sb := strings.Builder{} // Trace: &sb
	for i := 0; i < b.N; i++ {
		pass, err := Eval(program, defaultEvalParams(&sb, nil))
		if !pass {
			b.Log(sb.String())
		}
		// require is super slow but makes useful error messages, wrap it in a check that makes the benchmark run a bunch faster
		if err != nil {
			require.NoError(b, err)
		}
		if !pass {
			require.True(b, pass)
		}
	}
}

func BenchmarkAddx64(b *testing.B) {
	progs := [][]string{
		[]string{"add long stack", addBenchmarkSource},
		[]string{"add small stack", addBenchmark2Source},
	}
	for _, pp := range progs {
		b.Run(pp[0], func(b *testing.B) {
			benchmarkBasicProgram(b, pp[1])
		})
	}
}

func BenchmarkNopPassx1(b *testing.B) {
	benchmarkBasicProgram(b, "int 1")
}

func BenchmarkSha256Raw(b *testing.B) {
	addr, _ := basics.UnmarshalChecksumAddress("OC6IROKUJ7YCU5NV76AZJEDKYQG33V2CJ7HAPVQ4ENTAGMLIOINSQ6EKGE")
	a := addr[:]
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		t := sha256.Sum256(a)
		a = t[:]
	}
}

func BenchmarkSha256x900(b *testing.B) {
	const firstline = "addr OC6IROKUJ7YCU5NV76AZJEDKYQG33V2CJ7HAPVQ4ENTAGMLIOINSQ6EKGE\n"
	sb := strings.Builder{}
	sb.WriteString(firstline)
	for i := 0; i < 900; i++ {
		sb.WriteString("sha256\n")
	}
	sb.WriteString("len\nint 0\n>\n")
	benchmarkExpensiveProgram(b, sb.String())
}

func BenchmarkKeccak256x900(b *testing.B) {
	const firstline = "addr OC6IROKUJ7YCU5NV76AZJEDKYQG33V2CJ7HAPVQ4ENTAGMLIOINSQ6EKGE\n"
	sb := strings.Builder{}
	sb.WriteString(firstline)
	for i := 0; i < 900; i++ {
		sb.WriteString("keccak256\n")
	}
	sb.WriteString("len\nint 0\n>\n")
	benchmarkExpensiveProgram(b, sb.String())
}

func BenchmarkSha512_256x900(b *testing.B) {
	const firstline = "addr OC6IROKUJ7YCU5NV76AZJEDKYQG33V2CJ7HAPVQ4ENTAGMLIOINSQ6EKGE\n"
	sb := strings.Builder{}
	sb.WriteString(firstline)
	for i := 0; i < 900; i++ {
		sb.WriteString("sha512_256\n")
	}
	sb.WriteString("len\nint 0\n>\n")
	benchmarkExpensiveProgram(b, sb.String())
}

func TestEd25519verify(t *testing.T) {
	t.Parallel()
	var s crypto.Seed
	crypto.RandBytes(s[:])
	c := crypto.GenerateSignatureSecrets(s)
	msg := "62fdfc072182654f163f5f0f9a621d729566c74d0aa413bf009c9800418c19cd"
	data, err := hex.DecodeString(msg)
	require.NoError(t, err)
	pk := basics.Address(c.SignatureVerifier)
	pkStr := pk.String()
	program, err := AssembleString(fmt.Sprintf(`arg 0
arg 1
addr %s
ed25519verify`, pkStr))
	require.NoError(t, err)
	sig := c.Sign(Msg{
		ProgramHash: crypto.HashObj(Program(program)),
		Data:        data[:],
	})
	var txn transactions.SignedTxn
	txn.Lsig.Logic = program
	txn.Lsig.Args = [][]byte{data[:], sig[:]}
	sb := strings.Builder{}
	pass, err := Eval(program, defaultEvalParams(&sb, &txn))
	if !pass {
		t.Log(hex.EncodeToString(program))
		t.Log(sb.String())
	}
	require.True(t, pass)
	require.NoError(t, err)

	// short sig will fail
	txn.Lsig.Args[1] = sig[1:]
	pass, err = Eval(program, defaultEvalParams(nil, &txn))
	require.False(t, pass)
	require.Error(t, err)
	isNotPanic(t, err)

	// flip a bit and it should not pass
	msg1 := "52fdfc072182654f163f5f0f9a621d729566c74d0aa413bf009c9800418c19cd"
	data1, err := hex.DecodeString(msg1)
	require.NoError(t, err)
	txn.Lsig.Args = [][]byte{data1, sig[:]}
	sb1 := strings.Builder{}
	pass1, err := Eval(program, defaultEvalParams(&sb1, &txn))
	require.False(t, pass1)
	require.NoError(t, err)
	isNotPanic(t, err)
}

func BenchmarkEd25519Verifyx1(b *testing.B) {
	//benchmark setup
	var data [][32]byte
	var programs [][]byte
	var signatures []crypto.Signature

	for i := 0; i < b.N; i++ {
		var buffer [32]byte //generate data to be signed
		crypto.RandBytes(buffer[:])
		data = append(data, buffer)

		var s crypto.Seed //generate programs and signatures
		crypto.RandBytes(s[:])
		secret := crypto.GenerateSignatureSecrets(s)
		pk := basics.Address(secret.SignatureVerifier)
		pkStr := pk.String()
		program, err := AssembleString(fmt.Sprintf(`arg 0
arg 1
addr %s
ed25519verify`, pkStr))
		require.NoError(b, err)
		programs = append(programs, program)
		sig := secret.SignBytes(buffer[:])
		signatures = append(signatures, sig)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		var txn transactions.SignedTxn
		txn.Lsig.Logic = programs[i]
		txn.Lsig.Args = [][]byte{data[i][:], signatures[i][:]}
		sb := strings.Builder{}
		proto := defaultEvalProto()
		ep := EvalParams{Proto: &proto, Txn: &txn, Trace: &sb}
		pass, err := Eval(programs[i], ep)
		if !pass {
			b.Log(hex.EncodeToString(programs[i]))
			b.Log(sb.String())
		}
		if err != nil {
			require.NoError(b, err)
		}
		if !pass {
			require.True(b, pass)
		}
	}
}

func BenchmarkCheckx5(b *testing.B) {
	sourcePrograms := []string{
		tlhcProgramText,
		testTxnProgramText,
		testCompareProgramText,
		addBenchmarkSource,
		addBenchmark2Source,
	}

	programs := make([][]byte, len(sourcePrograms))
	var err error
	for i, text := range sourcePrograms {
		programs[i], err = AssembleString(text)
		require.NoError(b, err)
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		for _, program := range programs {
			_, err = Check(program, defaultEvalParams(nil, nil))
			if err != nil {
				require.NoError(b, err)
			}
		}
	}
}
