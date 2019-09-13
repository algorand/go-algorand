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
)

func TestTrivialMath(t *testing.T) {
	t.Parallel()
	program, err := AssembleString(`int 2
int 3
+
int 5
==`)
	require.NoError(t, err)
	cost, err := Check(program, EvalParams{})
	require.NoError(t, err)
	require.True(t, cost < 1000)
	pass, err := Eval(program, EvalParams{})
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
	ep := EvalParams{Txn: &txn, Trace: &sb}
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
global Round
int 3000
>
&&
||`

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
	sb := strings.Builder{}
	block := bookkeeping.Block{}
	block.BlockHeader.Round = 999999
	ep := EvalParams{Txn: &txn, Trace: &sb, Block: &block}
	cost, err := Check(program, ep)
	if err != nil {
		t.Log(hex.EncodeToString(program))
		t.Log(sb.String())
	}
	require.NoError(t, err)
	require.True(t, cost < 1000)
	pass, _ := Eval(program, ep)
	if pass {
		t.Log(hex.EncodeToString(program))
		t.Log(sb.String())
	}
	require.False(t, pass)

	txn.Txn.Receiver = a2
	txn.Txn.CloseRemainderTo = a2
	sb = strings.Builder{}
	ep = EvalParams{Txn: &txn, Trace: &sb, Block: &block}
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
	block.BlockHeader.Round = 1
	ep = EvalParams{Txn: &txn, Trace: &sb, Block: &block}
	pass, _ = Eval(program, ep)
	if pass {
		t.Log(hex.EncodeToString(program))
		t.Log(sb.String())
	}
	require.False(t, pass)

	txn.Txn.Receiver = a1
	txn.Txn.CloseRemainderTo = a1
	sb = strings.Builder{}
	block.BlockHeader.Round = 999999
	ep = EvalParams{Txn: &txn, Trace: &sb, Block: &block}
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
	ep = EvalParams{Txn: &txn, Trace: &sb, Block: &block}
	pass, _ = Eval(program, ep)
	if pass {
		t.Log(hex.EncodeToString(program))
		t.Log(sb.String())
	}
	require.False(t, pass)
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
	pass, err := Eval(program, EvalParams{Trace: &sb})
	if !pass {
		t.Log(hex.EncodeToString(program))
		t.Log(sb.String())
	}
	require.True(t, pass)
	require.NoError(t, err)
}

func TestBtoi(t *testing.T) {
	t.Parallel()
	program, err := AssembleString(`int 0x1234567812345678
byte 0x1234567812345678
btoi
==`)
	require.NoError(t, err)
	sb := strings.Builder{}
	pass, err := Eval(program, EvalParams{Trace: &sb})
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
	pass, err := Eval(program, EvalParams{Trace: &sb})
	if pass {
		t.Log(hex.EncodeToString(program))
		t.Log(sb.String())
	}
	require.False(t, pass)
	require.Error(t, err)
}

func TestBnz(t *testing.T) {
	t.Parallel()
	program, err := AssembleString(`int 1
dup
bnz safe
err
safe:
`)
	require.NoError(t, err)
	sb := strings.Builder{}
	pass, err := Eval(program, EvalParams{Trace: &sb})
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
	cost, err := Check(program, EvalParams{})
	require.NoError(t, err)
	require.True(t, cost < 1000)
	sb := strings.Builder{}
	pass, err := Eval(program, EvalParams{Trace: &sb})
	if pass {
		t.Log(hex.EncodeToString(program))
		t.Log(sb.String())
	}
	require.False(t, pass)
	require.Error(t, err)
}

func TestAddOverflow(t *testing.T) {
	t.Parallel()
	program, err := AssembleString(`int 0xf000000000000000
int 0x1111111111111111
+
pop
int 1`)
	require.NoError(t, err)
	cost, err := Check(program, EvalParams{})
	require.NoError(t, err)
	require.True(t, cost < 1000)
	sb := strings.Builder{}
	pass, err := Eval(program, EvalParams{Trace: &sb})
	if pass {
		t.Log(hex.EncodeToString(program))
		t.Log(sb.String())
	}
	require.False(t, pass)
	require.Error(t, err)
}

func TestMulOverflow(t *testing.T) {
	t.Parallel()
	program, err := AssembleString(`int 0x111111111
int 0x222222222
*
pop
int 1`)
	require.NoError(t, err)
	cost, err := Check(program, EvalParams{})
	require.NoError(t, err)
	require.True(t, cost < 1000)
	sb := strings.Builder{}
	pass, err := Eval(program, EvalParams{Trace: &sb})
	if pass {
		t.Log(hex.EncodeToString(program))
		t.Log(sb.String())
	}
	require.False(t, pass)
	require.Error(t, err)
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
	cost, err := Check(program, EvalParams{Trace: &sb})
	if err != nil {
		t.Log(hex.EncodeToString(program))
		t.Log(sb.String())
	}
	require.NoError(t, err)
	require.True(t, cost < 1000)
	pass, err := Eval(program, EvalParams{Trace: &sb})
	if pass {
		t.Log(hex.EncodeToString(program))
		t.Log(sb.String())
	}
	require.False(t, pass)
	require.Error(t, err)
}

func TestModZero(t *testing.T) {
	t.Parallel()
	program, err := AssembleString(`int 0x111111111
int 0
%
pop
int 1`)
	require.NoError(t, err)
	cost, err := Check(program, EvalParams{})
	require.NoError(t, err)
	require.True(t, cost < 1000)
	sb := strings.Builder{}
	pass, err := Eval(program, EvalParams{Trace: &sb})
	if pass {
		t.Log(hex.EncodeToString(program))
		t.Log(sb.String())
	}
	require.False(t, pass)
	require.Error(t, err)
}

func TestErr(t *testing.T) {
	t.Parallel()
	program, err := AssembleString(`err
int 1`)
	require.NoError(t, err)
	cost, err := Check(program, EvalParams{})
	require.NoError(t, err)
	require.True(t, cost < 1000)
	sb := strings.Builder{}
	pass, err := Eval(program, EvalParams{Trace: &sb})
	if pass {
		t.Log(hex.EncodeToString(program))
		t.Log(sb.String())
	}
	require.False(t, pass)
	require.Error(t, err)
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
	cost, err := Check(program, EvalParams{})
	require.NoError(t, err)
	require.True(t, cost < 1000)
	sb := strings.Builder{}
	pass, err := Eval(program, EvalParams{Trace: &sb})
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
	cost, err := Check(program, EvalParams{})
	require.NoError(t, err)
	require.True(t, cost < 1000)
	sb := strings.Builder{}
	pass, err := Eval(program, EvalParams{Trace: &sb})
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
	cost, err := Check(program, EvalParams{})
	require.Error(t, err)
	require.True(t, cost < 1000)
	sb := strings.Builder{}
	pass, err := Eval(program, EvalParams{Trace: &sb})
	if pass {
		t.Log(hex.EncodeToString(program))
		t.Log(sb.String())
	}
	require.Error(t, err)
	require.False(t, pass)
}

func TestStackBytesLeftover(t *testing.T) {
	t.Parallel()
	program, err := AssembleString(`byte 0x10101010`)
	require.NoError(t, err)
	cost, err := Check(program, EvalParams{})
	require.Error(t, err)
	require.True(t, cost < 1000)
	sb := strings.Builder{}
	pass, err := Eval(program, EvalParams{Trace: &sb})
	if pass {
		t.Log(hex.EncodeToString(program))
		t.Log(sb.String())
	}
	require.Error(t, err)
	require.False(t, pass)
}

func TestStackEmpty(t *testing.T) {
	t.Parallel()
	program, err := AssembleString(`int 1
int 1
pop
pop`)
	require.NoError(t, err)
	cost, err := Check(program, EvalParams{})
	require.Error(t, err)
	require.True(t, cost < 1000)
	sb := strings.Builder{}
	pass, err := Eval(program, EvalParams{Trace: &sb})
	if pass {
		t.Log(hex.EncodeToString(program))
		t.Log(sb.String())
	}
	require.Error(t, err)
	require.False(t, pass)
}

func TestArgTooFar(t *testing.T) {
	t.Parallel()
	program, err := AssembleString(`arg_1
btoi`)
	require.NoError(t, err)
	cost, err := Check(program, EvalParams{})
	//require.Error(t, err)
	require.True(t, cost < 1000)
	sb := strings.Builder{}
	var txn transactions.SignedTxn
	txn.Lsig.Logic = program
	txn.Lsig.Args = nil
	pass, err := Eval(program, EvalParams{Trace: &sb, Txn: &txn})
	if pass {
		t.Log(hex.EncodeToString(program))
		t.Log(sb.String())
	}
	require.Error(t, err)
	require.False(t, pass)
}

func TestIntcTooFar(t *testing.T) {
	t.Parallel()
	program, err := AssembleString(`intc_1`)
	require.NoError(t, err)
	cost, err := Check(program, EvalParams{})
	//require.Error(t, err)
	require.True(t, cost < 1000)
	sb := strings.Builder{}
	var txn transactions.SignedTxn
	txn.Lsig.Logic = program
	txn.Lsig.Args = nil
	pass, err := Eval(program, EvalParams{Trace: &sb, Txn: &txn})
	if pass {
		t.Log(hex.EncodeToString(program))
		t.Log(sb.String())
	}
	require.Error(t, err)
	require.False(t, pass)
}

func TestBytecTooFar(t *testing.T) {
	t.Parallel()
	program, err := AssembleString(`bytec_1
btoi`)
	require.NoError(t, err)
	cost, err := Check(program, EvalParams{})
	//require.Error(t, err)
	require.True(t, cost < 1000)
	sb := strings.Builder{}
	var txn transactions.SignedTxn
	txn.Lsig.Logic = program
	txn.Lsig.Args = nil
	pass, err := Eval(program, EvalParams{Trace: &sb, Txn: &txn})
	if pass {
		t.Log(hex.EncodeToString(program))
		t.Log(sb.String())
	}
	require.Error(t, err)
	require.False(t, pass)
}

func TestTxnBadField(t *testing.T) {
	t.Parallel()
	program := []byte{0x01, 0x31, 0x7f}
	cost, err := Check(program, EvalParams{})
	//require.Error(t, err)
	require.True(t, cost < 1000)
	sb := strings.Builder{}
	var txn transactions.SignedTxn
	txn.Lsig.Logic = program
	txn.Lsig.Args = nil
	pass, err := Eval(program, EvalParams{Trace: &sb, Txn: &txn})
	if pass {
		t.Log(hex.EncodeToString(program))
		t.Log(sb.String())
	}
	require.Error(t, err)
	require.False(t, pass)
}

func TestGlobalBadField(t *testing.T) {
	t.Parallel()
	program := []byte{0x01, 0x32, 0x7f}
	cost, err := Check(program, EvalParams{})
	//require.Error(t, err)
	require.True(t, cost < 1000)
	sb := strings.Builder{}
	var txn transactions.SignedTxn
	txn.Lsig.Logic = program
	txn.Lsig.Args = nil
	pass, err := Eval(program, EvalParams{Trace: &sb, Txn: &txn})
	if pass {
		t.Log(hex.EncodeToString(program))
		t.Log(sb.String())
	}
	require.Error(t, err)
	require.False(t, pass)
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
	cost, err := Check(program, EvalParams{})
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
	pass, err := Eval(program, EvalParams{Trace: &sb, Txn: &txn})
	if !pass {
		t.Log(hex.EncodeToString(program))
		t.Log(sb.String())
	}
	require.NoError(t, err)
	require.True(t, pass)
}

func TestGlobal(t *testing.T) {
	t.Parallel()
	program, err := AssembleString(`global MinTxnFee
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
global TimeStamp
int 2069
==
&&`)
	require.NoError(t, err)
	cost, err := Check(program, EvalParams{})
	require.NoError(t, err)
	require.True(t, cost < 1000)
	var txn transactions.SignedTxn
	txn.Lsig.Logic = program
	sb := strings.Builder{}
	block := bookkeeping.Block{}
	block.BlockHeader.Round = 999999
	block.BlockHeader.TimeStamp = 2069
	proto := config.ConsensusParams{
		MinTxnFee:       123,
		MinBalance:      1000000,
		MaxTxnLife:      999,
		LogicSigVersion: 1,
	}
	ep := EvalParams{Trace: &sb, Txn: &txn, Block: &block, Proto: &proto}
	pass, err := Eval(program, ep)
	if !pass {
		t.Log(hex.EncodeToString(program))
		t.Log(sb.String())
	}
	require.NoError(t, err)
	require.True(t, pass)
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
&&`

func TestTxn(t *testing.T) {
	t.Parallel()
	program, err := AssembleString(testTxnProgramText)
	require.NoError(t, err)
	cost, err := Check(program, EvalParams{})
	require.NoError(t, err)
	require.True(t, cost < 1000)
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
	txn.Lsig.Logic = program
	txn.Lsig.Args = [][]byte{
		txn.Txn.Sender[:],
		txn.Txn.Receiver[:],
		txn.Txn.CloseRemainderTo[:],
		txn.Txn.VotePK[:],
		txn.Txn.SelectionPK[:],
		txn.Txn.Note,
	}
	sb := strings.Builder{}
	pass, err := Eval(program, EvalParams{Trace: &sb, Txn: &txn})
	if !pass {
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
	cost, err := Check(program, EvalParams{})
	require.NoError(t, err)
	require.True(t, cost < 1000)
	sb := strings.Builder{}
	pass, err := Eval(program, EvalParams{Trace: &sb})
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
	cost, err := Check(program, EvalParams{})
	require.NoError(t, err)
	require.True(t, cost < 1000)
	sb := strings.Builder{}
	pass, err := Eval(program, EvalParams{Trace: &sb})
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
	cost, err := Check(program, EvalParams{})
	require.NoError(t, err)
	require.True(t, cost < 1000)
	sb := strings.Builder{}
	pass, err := Eval(program, EvalParams{Trace: &sb})
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
	cost, err := Check(program, EvalParams{})
	require.NoError(t, err)
	require.True(t, cost < 1000)
	sb := strings.Builder{}
	pass, err := Eval(program, EvalParams{Trace: &sb})
	if !pass {
		t.Log(hex.EncodeToString(program))
		t.Log(sb.String())
	}
	require.NoError(t, err)
	require.True(t, pass)
}

func TestStackUnderflow(t *testing.T) {
	t.Parallel()
	program, err := AssembleString(`int 1`)
	program = append(program, 0x08) // +
	require.NoError(t, err)
	cost, err := Check(program, EvalParams{})
	require.Error(t, err) // Check should know the type stack was wrong
	require.True(t, cost < 1000)
	sb := strings.Builder{}
	pass, err := Eval(program, EvalParams{Trace: &sb})
	if pass {
		t.Log(hex.EncodeToString(program))
		t.Log(sb.String())
	}
	require.False(t, pass)
}

func TestWrongStackTypeRuntime(t *testing.T) {
	t.Parallel()
	program, err := AssembleString(`int 1`)
	require.NoError(t, err)
	program = append(program, 0x01, 0x15) // sha256, len
	cost, err := Check(program, EvalParams{})
	require.Error(t, err) // Check should know the type stack was wrong
	require.True(t, cost < 1000)
	sb := strings.Builder{}
	pass, err := Eval(program, EvalParams{Trace: &sb})
	if pass {
		t.Log(hex.EncodeToString(program))
		t.Log(sb.String())
	}
	require.False(t, pass)
}

func TestEqMismatch(t *testing.T) {
	t.Parallel()
	program, err := AssembleString(`byte 0x1234
int 1`)
	require.NoError(t, err)
	program = append(program, 0x12) // ==
	cost, err := Check(program, EvalParams{})
	//require.Error(t, err) // Check should know the type stack was wrong
	require.True(t, cost < 1000)
	sb := strings.Builder{}
	pass, err := Eval(program, EvalParams{Trace: &sb})
	if pass {
		t.Log(hex.EncodeToString(program))
		t.Log(sb.String())
	}
	require.False(t, pass)
}

func TestNeqMismatch(t *testing.T) {
	t.Parallel()
	program, err := AssembleString(`byte 0x1234
int 1`)
	require.NoError(t, err)
	program = append(program, 0x13) // !=
	cost, err := Check(program, EvalParams{})
	//require.Error(t, err) // Check should know the type stack was wrong
	require.True(t, cost < 1000)
	sb := strings.Builder{}
	pass, err := Eval(program, EvalParams{Trace: &sb})
	if pass {
		t.Log(hex.EncodeToString(program))
		t.Log(sb.String())
	}
	require.False(t, pass)
}

func TestWrongStackTypeRuntime2(t *testing.T) {
	t.Parallel()
	program, err := AssembleString(`byte 0x1234
int 1`)
	require.NoError(t, err)
	program = append(program, 0x08) // +
	cost, err := Check(program, EvalParams{})
	require.Error(t, err) // Check should know the type stack was wrong
	require.True(t, cost < 1000)
	sb := strings.Builder{}
	pass, _ := Eval(program, EvalParams{Trace: &sb})
	if pass {
		t.Log(hex.EncodeToString(program))
		t.Log(sb.String())
	}
	require.False(t, pass)
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
	cost, err := Check(program, EvalParams{})
	require.Error(t, err)
	require.True(t, cost < 1000)
	sb := strings.Builder{}
	pass, err := Eval(program, EvalParams{Trace: &sb})
	if pass {
		t.Log(hex.EncodeToString(program))
		t.Log(sb.String())
	}
	require.False(t, pass)
}

func TestProgramTooNew(t *testing.T) {
	t.Parallel()
	var program [12]byte
	vlen := binary.PutUvarint(program[:], EvalMaxVersion+1)
	_, err := Check(program[:vlen], EvalParams{})
	require.Error(t, err)
	pass, err := Eval(program[:vlen], EvalParams{})
	require.Error(t, err)
	require.False(t, pass)
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

func BenchmarkAddx64(b *testing.B) {
	program, err := AssembleString(addBenchmarkSource)
	require.NoError(b, err)
	cost, err := Check(program, EvalParams{})
	require.NoError(b, err)
	require.True(b, cost < 1000)
	//b.Logf("%d bytes of program", len(program))
	//b.Log(hex.EncodeToString(program))
	b.StopTimer()
	b.ResetTimer()
	b.StartTimer()
	sb := strings.Builder{} // Trace: &sb
	for i := 0; i < b.N; i++ {
		pass, err := Eval(program, EvalParams{})
		if !pass {
			b.Log(sb.String())
		}
		require.NoError(b, err)
		require.True(b, pass)
	}
}

func BenchmarkNopPassx1(b *testing.B) {
	program, err := AssembleString("int 1")
	require.NoError(b, err)
	cost, err := Check(program, EvalParams{})
	require.NoError(b, err)
	require.True(b, cost < 1000)
	//b.Logf("%d bytes of program", len(program))
	//b.Log(hex.EncodeToString(program))
	b.StopTimer()
	b.ResetTimer()
	b.StartTimer()
	sb := strings.Builder{} // Trace: &sb
	for i := 0; i < b.N; i++ {
		pass, err := Eval(program, EvalParams{})
		if !pass {
			b.Log(sb.String())
		}
		require.NoError(b, err)
		require.True(b, pass)
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
	program, err := AssembleString(sb.String())
	require.NoError(b, err)
	cost, err := Check(program, EvalParams{})
	require.NoError(b, err)
	require.True(b, cost > 1000)
	//b.Logf("%d bytes of program", len(program))
	//b.Log(hex.EncodeToString(program))
	b.StopTimer()
	b.ResetTimer()
	b.StartTimer()
	sb = strings.Builder{}
	for i := 0; i < b.N; i++ {
		pass, err := Eval(program, EvalParams{})
		if !pass {
			b.Log(sb.String())
		}
		require.NoError(b, err)
		require.True(b, pass)
	}
}

func BenchmarkKeccak256x900(b *testing.B) {
	const firstline = "addr OC6IROKUJ7YCU5NV76AZJEDKYQG33V2CJ7HAPVQ4ENTAGMLIOINSQ6EKGE\n"
	sb := strings.Builder{}
	sb.WriteString(firstline)
	for i := 0; i < 900; i++ {
		sb.WriteString("keccak256\n")
	}
	sb.WriteString("len\nint 0\n>\n")
	program, err := AssembleString(sb.String())
	require.NoError(b, err)
	cost, err := Check(program, EvalParams{})
	require.NoError(b, err)
	require.True(b, cost > 1000)
	//b.Logf("%d bytes of program", len(program))
	//b.Log(hex.EncodeToString(program))
	b.StopTimer()
	b.ResetTimer()
	b.StartTimer()
	sb = strings.Builder{}
	for i := 0; i < b.N; i++ {
		pass, err := Eval(program, EvalParams{})
		if !pass {
			b.Log(sb.String())
		}
		require.NoError(b, err)
		require.True(b, pass)
	}
}

func BenchmarkSha512_256x900(b *testing.B) {
	const firstline = "addr OC6IROKUJ7YCU5NV76AZJEDKYQG33V2CJ7HAPVQ4ENTAGMLIOINSQ6EKGE\n"
	sb := strings.Builder{}
	sb.WriteString(firstline)
	for i := 0; i < 900; i++ {
		sb.WriteString("sha512_256\n")
	}
	sb.WriteString("len\nint 0\n>\n")
	program, err := AssembleString(sb.String())
	require.NoError(b, err)
	cost, err := Check(program, EvalParams{})
	require.NoError(b, err)
	require.True(b, cost > 1000)
	//b.Logf("%d bytes of program", len(program))
	//b.Log(hex.EncodeToString(program))
	b.StopTimer()
	b.ResetTimer()
	b.StartTimer()
	sb = strings.Builder{}
	for i := 0; i < b.N; i++ {
		pass, err := Eval(program, EvalParams{})
		if !pass {
			b.Log(sb.String())
		}
		require.NoError(b, err)
		require.True(b, pass)
	}
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
	sig := c.SignBytes(data[:])
	var txn transactions.SignedTxn
	txn.Lsig.Logic = program
	txn.Lsig.Args = [][]byte{data[:], sig[:]}
	sb := strings.Builder{}
	ep := EvalParams{Txn: &txn, Trace: &sb}
	pass, err := Eval(program, ep)
	if !pass {
		t.Log(hex.EncodeToString(program))
		t.Log(sb.String())
	}
	require.True(t, pass)
	require.NoError(t, err)

	// flip a bit and it should not pass
	msg1 := "52fdfc072182654f163f5f0f9a621d729566c74d0aa413bf009c9800418c19cd"
	data1, err := hex.DecodeString(msg1)
	require.NoError(t, err)
	txn.Lsig.Args = [][]byte{data1, sig[:]}
	sb1 := strings.Builder{}
	ep1 := EvalParams{Txn: &txn, Trace: &sb1}
	pass1, err := Eval(program, ep1)
	require.False(t, pass1)
	require.NoError(t, err)
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
		ep := EvalParams{Txn: &txn, Trace: &sb}
		pass, err := Eval(programs[i], ep)
		if !pass {
			b.Log(hex.EncodeToString(programs[i]))
			b.Log(sb.String())
		}
		require.True(b, pass)
		require.NoError(b, err)
	}
}

func BenchmarkCheckx4(b *testing.B) {
	sourcePrograms := []string{
		tlhcProgramText,
		testTxnProgramText,
		testCompareProgramText,
		addBenchmarkSource,
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
			_, err = Check(program, EvalParams{})
			require.NoError(b, err)
		}
	}
}
