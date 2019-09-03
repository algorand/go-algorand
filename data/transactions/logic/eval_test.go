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
	"encoding/hex"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

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
	pass := Eval(program, EvalParams{})
	require.True(t, pass)
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
	pass := Eval(program, ep)
	require.True(t, pass)
	//t.Log(sb.String())
}

func TestTLHC(t *testing.T) {
	t.Parallel()
	a1, _ := basics.UnmarshalChecksumAddress("DFPKC2SJP3OTFVJFMCD356YB7BOT4SJZTGWLIPPFEWL3ZABUFLTOY6ILYE")
	a2, _ := basics.UnmarshalChecksumAddress("YYKRMERAFXMXCDWMBNR6BUUWQXDCUR53FPUGXLUYS7VNASRTJW2ENQ7BMQ")
	secret, _ := base64.StdEncoding.DecodeString("xPUB+DJir1wsH7g2iEY1QwYqHqYH1vUJtzZKW4RxXsY=")
	program, err := AssembleString(`txn CloseRemainderTo
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
||`)
	require.NoError(t, err)
	var txn transactions.SignedTxn
	txn.Lsig.Logic = program
	// right answer
	txn.Lsig.Args = [][]byte{secret}
	sb := strings.Builder{}
	block := bookkeeping.Block{}
	block.BlockHeader.Round = 999999
	ep := EvalParams{Txn: &txn, Trace: &sb, Block: &block}
	pass := Eval(program, ep)
	if pass {
		t.Log(hex.EncodeToString(program))
		t.Log(sb.String())
	}
	require.False(t, pass)

	txn.Txn.Receiver = a2
	txn.Txn.CloseRemainderTo = a2
	sb = strings.Builder{}
	ep = EvalParams{Txn: &txn, Trace: &sb, Block: &block}
	pass = Eval(program, ep)
	if !pass {
		t.Log(hex.EncodeToString(program))
		t.Log(sb.String())
	}
	require.True(t, pass)

	txn.Txn.Receiver = a2
	txn.Txn.CloseRemainderTo = a2
	sb = strings.Builder{}
	block.BlockHeader.Round = 1
	ep = EvalParams{Txn: &txn, Trace: &sb, Block: &block}
	pass = Eval(program, ep)
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
	pass = Eval(program, ep)
	if !pass {
		t.Log(hex.EncodeToString(program))
		t.Log(sb.String())
	}
	require.True(t, pass)

	// wrong answer
	txn.Lsig.Args = [][]byte{[]byte("=0\x97S\x85H\xe9\x91B\xfd\xdb;1\xf5Z\xaec?\xae\xf2I\x93\x08\x12\x94\xaa~\x06\x08\x849a")}
	sb = strings.Builder{}
	block.BlockHeader.Round = 1
	ep = EvalParams{Txn: &txn, Trace: &sb, Block: &block}
	pass = Eval(program, ep)
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
	pass := Eval(program, EvalParams{Trace: &sb})
	if !pass {
		t.Log(hex.EncodeToString(program))
		t.Log(sb.String())
	}
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
	pass := Eval(program, EvalParams{Trace: &sb})
	if !pass {
		t.Log(hex.EncodeToString(program))
		t.Log(sb.String())
	}
	require.True(t, pass)
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
	pass := Eval(program, EvalParams{Trace: &sb})
	if !pass {
		t.Log(hex.EncodeToString(program))
		t.Log(sb.String())
	}
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
	sb := strings.Builder{}
	pass := Eval(program, EvalParams{Trace: &sb})
	if pass {
		t.Log(hex.EncodeToString(program))
		t.Log(sb.String())
	}
	require.False(t, pass)
}

func TestAddOverflow(t *testing.T) {
	t.Parallel()
	program, err := AssembleString(`int 0xf000000000000000
int 0x1111111111111111
+
pop
int 1`)
	require.NoError(t, err)
	sb := strings.Builder{}
	pass := Eval(program, EvalParams{Trace: &sb})
	if pass {
		t.Log(hex.EncodeToString(program))
		t.Log(sb.String())
	}
	require.False(t, pass)
}

func TestMulOverflow(t *testing.T) {
	t.Parallel()
	program, err := AssembleString(`int 0x111111111
int 0x222222222
*
pop
int 1`)
	require.NoError(t, err)
	sb := strings.Builder{}
	pass := Eval(program, EvalParams{Trace: &sb})
	if pass {
		t.Log(hex.EncodeToString(program))
		t.Log(sb.String())
	}
	require.False(t, pass)
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
	pass := Eval(program, EvalParams{Trace: &sb})
	if pass {
		t.Log(hex.EncodeToString(program))
		t.Log(sb.String())
	}
	require.False(t, pass)
}

func TestModZero(t *testing.T) {
	t.Parallel()
	program, err := AssembleString(`int 0x111111111
int 0
%
pop
int 1`)
	require.NoError(t, err)
	sb := strings.Builder{}
	pass := Eval(program, EvalParams{Trace: &sb})
	if pass {
		t.Log(hex.EncodeToString(program))
		t.Log(sb.String())
	}
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

func BenchmarkAdd(b *testing.B) {
	program, err := AssembleString(addBenchmarkSource)
	require.NoError(b, err)
	//b.Logf("%d bytes of program", len(program))
	//b.Log(hex.EncodeToString(program))
	b.StopTimer()
	b.ResetTimer()
	b.StartTimer()
	sb := strings.Builder{} // Trace: &sb
	for i := 0; i < b.N; i++ {
		pass := Eval(program, EvalParams{})
		if !pass {
			b.Log(sb.String())
		}
		require.True(b, pass)
	}
}

func BenchmarkSha256(b *testing.B) {
	const firstline = "addr OC6IROKUJ7YCU5NV76AZJEDKYQG33V2CJ7HAPVQ4ENTAGMLIOINSQ6EKGE\n"
	sb := strings.Builder{}
	sb.WriteString(firstline)
	for i := 0; i < 900; i++ {
		sb.WriteString("sha256\n")
	}
	sb.WriteString("len\nint 0\n>\n")
	program, err := AssembleString(sb.String())
	require.NoError(b, err)
	//b.Logf("%d bytes of program", len(program))
	//b.Log(hex.EncodeToString(program))
	b.StopTimer()
	b.ResetTimer()
	b.StartTimer()
	sb = strings.Builder{}
	for i := 0; i < b.N; i++ {
		pass := Eval(program, EvalParams{})
		if !pass {
			b.Log(sb.String())
		}
		require.True(b, pass)
	}
}
