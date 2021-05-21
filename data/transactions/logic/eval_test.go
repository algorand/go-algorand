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
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strconv"
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

// Note that most of the tests use defaultEvalProto/defaultEvalParams as evaluator version so that
// we check that TEAL v1 and v2 programs are compatible with the latest evaluator
func defaultEvalProto() config.ConsensusParams {
	return defaultEvalProtoWithVersion(LogicVersion)
}

func defaultEvalProtoV1() config.ConsensusParams {
	return defaultEvalProtoWithVersion(1)
}

func defaultEvalProtoWithVersion(version uint64) config.ConsensusParams {
	return config.ConsensusParams{
		LogicSigVersion:     version,
		LogicSigMaxCost:     20000,
		MaxAppProgramCost:   700,
		MaxAppKeyLen:        64,
		MaxAppBytesValueLen: 64,
		// These must be identical to keep an old backward compat test working
		MinTxnFee:  1001,
		MinBalance: 1001,
		// Strange choices below so that we test against conflating them
		AppFlatParamsMinBalance:  1002,
		SchemaMinBalancePerEntry: 1003,
		SchemaUintMinBalance:     1004,
		SchemaBytesMinBalance:    1005,
	}
}

func defaultEvalParamsV1(sb *strings.Builder, txn *transactions.SignedTxn) EvalParams {
	return defaultEvalParamsWithVersion(sb, txn, 1)
}

func defaultEvalParams(sb *strings.Builder, txn *transactions.SignedTxn) EvalParams {
	return defaultEvalParamsWithVersion(sb, txn, LogicVersion)
}

func defaultEvalParamsWithVersion(sb *strings.Builder, txn *transactions.SignedTxn, version uint64) EvalParams {
	proto := defaultEvalProtoWithVersion(version)

	var pt *transactions.SignedTxn
	if txn != nil {
		pt = txn
	} else {
		var at transactions.SignedTxn
		pt = &at
	}

	ep := EvalParams{}
	ep.Proto = &proto
	ep.Txn = pt
	if sb != nil { // have to do this since go's nil semantics: https://golang.org/doc/faq#nil_error
		ep.Trace = sb
	}
	return ep
}

func TestTooManyArgs(t *testing.T) {
	t.Parallel()
	for v := uint64(1); v <= AssemblerMaxVersion; v++ {
		t.Run(fmt.Sprintf("v=%d", v), func(t *testing.T) {
			ops, err := AssembleStringWithVersion(`int 1`, v)
			require.NoError(t, err)
			var txn transactions.SignedTxn
			txn.Lsig.Logic = ops.Program
			args := [transactions.EvalMaxArgs + 1][]byte{}
			txn.Lsig.Args = args[:]
			sb := strings.Builder{}
			pass, err := Eval(ops.Program, defaultEvalParams(&sb, &txn))
			require.Error(t, err)
			require.False(t, pass)
		})
	}
}

func TestEmptyProgram(t *testing.T) {
	t.Parallel()
	pass, err := Eval(nil, defaultEvalParams(nil, nil))
	require.Error(t, err)
	require.Contains(t, err.Error(), "invalid program (empty)")
	require.False(t, pass)
}

// TestMinTealVersionParamEval tests eval/check reading the MinTealVersion from the param
func TestMinTealVersionParamEvalCheck(t *testing.T) {
	t.Parallel()
	params := defaultEvalParams(nil, nil)
	version2 := uint64(rekeyingEnabledVersion)
	params.MinTealVersion = &version2
	program := make([]byte, binary.MaxVarintLen64)
	// set the teal program version to 1
	binary.PutUvarint(program, 1)

	err := Check(program, params)
	require.Contains(t, err.Error(), fmt.Sprintf("program version must be >= %d", appsEnabledVersion))

	// If the param is read correctly, the eval should fail
	pass, err := Eval(program, params)
	require.Error(t, err)
	require.Contains(t, err.Error(), fmt.Sprintf("program version must be >= %d", appsEnabledVersion))
	require.False(t, pass)
}

func TestTxnFieldToTealValue(t *testing.T) {

	txn := transactions.Transaction{}
	groupIndex := 0
	field := FirstValid
	values := [6]uint64{0, 1, 2, 0xffffffff, 0xffffffffffffffff}

	for _, value := range values {
		txn.FirstValid = basics.Round(value)
		tealValue, err := TxnFieldToTealValue(&txn, groupIndex, field, 0)
		require.NoError(t, err)
		require.Equal(t, basics.TealUintType, tealValue.Type)
		require.Equal(t, value, tealValue.Uint)
	}

	// check arrayFieldIdx is ignored for non-arrays
	field = FirstValid
	value := uint64(1)
	txn.FirstValid = basics.Round(value)
	tealValue, err := TxnFieldToTealValue(&txn, groupIndex, field, 10)
	require.NoError(t, err)
	require.Equal(t, basics.TealUintType, tealValue.Type)
	require.Equal(t, value, tealValue.Uint)

	// check arrayFieldIdx is taken into account for arrays
	field = Accounts
	sender := basics.Address{}
	addr, _ := basics.UnmarshalChecksumAddress("DFPKC2SJP3OTFVJFMCD356YB7BOT4SJZTGWLIPPFEWL3ZABUFLTOY6ILYE")
	txn.Accounts = []basics.Address{addr}
	tealValue, err = TxnFieldToTealValue(&txn, groupIndex, field, 0)
	require.NoError(t, err)
	require.Equal(t, basics.TealBytesType, tealValue.Type)
	require.Equal(t, string(sender[:]), tealValue.Bytes)

	tealValue, err = TxnFieldToTealValue(&txn, groupIndex, field, 1)
	require.NoError(t, err)
	require.Equal(t, basics.TealBytesType, tealValue.Type)
	require.Equal(t, string(addr[:]), tealValue.Bytes)

	tealValue, err = TxnFieldToTealValue(&txn, groupIndex, field, 100)
	require.Error(t, err)
	require.Equal(t, basics.TealUintType, tealValue.Type)
	require.Equal(t, uint64(0), tealValue.Uint)
	require.Equal(t, "", tealValue.Bytes)
}

func TestWrongProtoVersion(t *testing.T) {
	t.Parallel()
	for v := uint64(1); v <= AssemblerMaxVersion; v++ {
		t.Run(fmt.Sprintf("v=%d", v), func(t *testing.T) {
			ops, err := AssembleStringWithVersion(`int 1`, v)
			require.NoError(t, err)
			var txn transactions.SignedTxn
			txn.Lsig.Logic = ops.Program
			sb := strings.Builder{}
			proto := defaultEvalProto()
			proto.LogicSigVersion = 0
			ep := defaultEvalParams(&sb, &txn)
			ep.Proto = &proto
			err = Check(ops.Program, ep)
			require.Error(t, err)
			require.Contains(t, err.Error(), "LogicSig not supported")
			pass, err := Eval(ops.Program, ep)
			require.Error(t, err)
			require.Contains(t, err.Error(), "LogicSig not supported")
			require.False(t, pass)
		})
	}
}

func TestSimpleMath(t *testing.T) {
	t.Parallel()
	testAccepts(t, "int  2; int 3; + ;int  5;==", 1)
	testAccepts(t, "int 22; int 3; - ;int 19;==", 1)
	testAccepts(t, "int  8; int 7; * ;int 56;==", 1)
	testAccepts(t, "int 21; int 7; / ;int  3;==", 1)

	testPanics(t, "int 1; int 2; - ;int 0; ==", 1)
}

func TestSha256EqArg(t *testing.T) {
	t.Parallel()
	for v := uint64(1); v <= AssemblerMaxVersion; v++ {
		t.Run(fmt.Sprintf("v=%d", v), func(t *testing.T) {
			ops, err := AssembleStringWithVersion(`arg 0
sha256
byte base64 5rZMNsevs5sULO+54aN+OvU6lQ503z2X+SSYUABIx7E=
==`, 1)
			require.NoError(t, err)
			var txn transactions.SignedTxn
			txn.Lsig.Logic = ops.Program
			txn.Lsig.Args = [][]byte{[]byte("=0\x97S\x85H\xe9\x91B\xfd\xdb;1\xf5Z\xaec?\xae\xf2I\x93\x08\x12\x94\xaa~\x06\x08\x849b")}
			sb := strings.Builder{}
			ep := defaultEvalParams(&sb, &txn)
			err = Check(ops.Program, ep)
			require.NoError(t, err)
			pass, err := Eval(ops.Program, ep)
			require.True(t, pass)
			require.NoError(t, err)
		})
	}
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
	for v := uint64(1); v <= AssemblerMaxVersion; v++ {
		t.Run(fmt.Sprintf("v=%d", v), func(t *testing.T) {

			a1, _ := basics.UnmarshalChecksumAddress("DFPKC2SJP3OTFVJFMCD356YB7BOT4SJZTGWLIPPFEWL3ZABUFLTOY6ILYE")
			a2, _ := basics.UnmarshalChecksumAddress("YYKRMERAFXMXCDWMBNR6BUUWQXDCUR53FPUGXLUYS7VNASRTJW2ENQ7BMQ")
			secret, _ := base64.StdEncoding.DecodeString("xPUB+DJir1wsH7g2iEY1QwYqHqYH1vUJtzZKW4RxXsY=")
			ops, err := AssembleStringWithVersion(tlhcProgramText, v)
			require.NoError(t, err)
			var txn transactions.SignedTxn
			txn.Lsig.Logic = ops.Program
			// right answer
			txn.Lsig.Args = [][]byte{secret}
			txn.Txn.FirstValid = 999999
			sb := strings.Builder{}
			block := bookkeeping.Block{}
			ep := defaultEvalParams(&sb, &txn)
			err = Check(ops.Program, ep)
			if err != nil {
				t.Log(hex.EncodeToString(ops.Program))
				t.Log(sb.String())
			}
			require.NoError(t, err)
			pass, err := Eval(ops.Program, ep)
			if pass {
				t.Log(hex.EncodeToString(ops.Program))
				t.Log(sb.String())
			}
			require.False(t, pass)
			isNotPanic(t, err)

			txn.Txn.Receiver = a2
			txn.Txn.CloseRemainderTo = a2
			sb = strings.Builder{}
			ep = defaultEvalParams(&sb, &txn)
			pass, err = Eval(ops.Program, ep)
			if !pass {
				t.Log(hex.EncodeToString(ops.Program))
				t.Log(sb.String())
			}
			require.True(t, pass)
			require.NoError(t, err)

			txn.Txn.Receiver = a2
			txn.Txn.CloseRemainderTo = a2
			sb = strings.Builder{}
			txn.Txn.FirstValid = 1
			ep = defaultEvalParams(&sb, &txn)
			pass, err = Eval(ops.Program, ep)
			if pass {
				t.Log(hex.EncodeToString(ops.Program))
				t.Log(sb.String())
			}
			require.False(t, pass)
			isNotPanic(t, err)

			txn.Txn.Receiver = a1
			txn.Txn.CloseRemainderTo = a1
			sb = strings.Builder{}
			txn.Txn.FirstValid = 999999
			ep = defaultEvalParams(&sb, &txn)
			pass, err = Eval(ops.Program, ep)
			if !pass {
				t.Log(hex.EncodeToString(ops.Program))
				t.Log(sb.String())
			}
			require.True(t, pass)
			require.NoError(t, err)

			// wrong answer
			txn.Lsig.Args = [][]byte{[]byte("=0\x97S\x85H\xe9\x91B\xfd\xdb;1\xf5Z\xaec?\xae\xf2I\x93\x08\x12\x94\xaa~\x06\x08\x849a")}
			sb = strings.Builder{}
			block.BlockHeader.Round = 1
			ep = defaultEvalParams(&sb, &txn)
			pass, err = Eval(ops.Program, ep)
			if pass {
				t.Log(hex.EncodeToString(ops.Program))
				t.Log(sb.String())
			}
			require.False(t, pass)
			isNotPanic(t, err)
		})
	}
}

func TestU64Math(t *testing.T) {
	t.Parallel()
	testAccepts(t, "int 0x1234567812345678; int 0x100000000; /; int 0x12345678; ==", 1)
}

func TestItob(t *testing.T) {
	t.Parallel()
	testAccepts(t, "byte 0x1234567812345678; int 0x1234567812345678; itob; ==", 1)
}

func TestBtoi(t *testing.T) {
	t.Parallel()
	testAccepts(t, "int 0x1234567812345678; byte 0x1234567812345678; btoi; ==", 1)
}

func TestBtoiTooLong(t *testing.T) {
	t.Parallel()
	testPanics(t, "int 0x1234567812345678; byte 0x1234567812345678aa; btoi; ==", 1)
}

func TestBnz(t *testing.T) {
	t.Parallel()
	testAccepts(t, `
int 1
dup
bnz safe
err
safe:
int 1
+
`, 1)

	testAccepts(t, `
int 1
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
`, 1)
}

func TestV2Branches(t *testing.T) {
	t.Parallel()
	testAccepts(t, `
int 0
dup
bz safe
err
safe:
int 1
+
`, 2)

	testAccepts(t, `
b safe
err
safe:
int 1
`, 2)
}

func TestReturn(t *testing.T) {
	t.Parallel()
	testAccepts(t, "int 1; return; err", 2)
	testRejects(t, "int 0; return; int 1", 2)
}

func TestSubUnderflow(t *testing.T) {
	t.Parallel()
	testPanics(t, "int 1; int 10; -; pop; int 1", 1)
}

func TestAddOverflow(t *testing.T) {
	t.Parallel()
	testPanics(t, "int 0xf000000000000000; int 0x1111111111111111; +; pop; int 1", 1)
}

func TestMulOverflow(t *testing.T) {
	t.Parallel()
	testPanics(t, "int 0x111111111; int 0x222222222; *; pop; int 1", 1)
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
	testAccepts(t, `
int 0x111111111
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
`, 1)
}

func TestAddwImpl(t *testing.T) {
	t.Parallel()
	carry, sum := opAddwImpl(1, 2)
	require.Equal(t, uint64(0), carry)
	require.Equal(t, uint64(3), sum)

	carry, sum = opAddwImpl(0xFFFFFFFFFFFFFFFD, 0x45)
	require.Equal(t, uint64(1), carry)
	require.Equal(t, uint64(0x42), sum)

	carry, sum = opAddwImpl(0, 0)
	require.Equal(t, uint64(0), carry)
	require.Equal(t, uint64(0), sum)

	carry, sum = opAddwImpl((1<<64)-1, (1<<64)-1)
	require.Equal(t, uint64(1), carry)
	require.Equal(t, uint64((1<<64)-2), sum)
}

func TestAddw(t *testing.T) {
	t.Parallel()
	testAccepts(t, `
int 0xFFFFFFFFFFFFFFFF
int 0x43
addw
int 0x42  // compare sum (top of the stack)
==
bnz continue
err
continue:
int 1                   // compare carry
==
bnz done
err
done:
int 1                   // ret 1
`, 2)
}

func TestUint128(t *testing.T) {
	x := uint128(0, 3)
	require.Equal(t, x.String(), "3")
	x = uint128(0, 0)
	require.Equal(t, x.String(), "0")
	x = uint128(1, 3)
	require.Equal(t, x.String(), "18446744073709551619")
	x = uint128(1, 5)
	require.Equal(t, x.String(), "18446744073709551621")
	x = uint128(^uint64(0), ^uint64(0)) // maximum uint128 = 2^64-1
	require.Equal(t, x.String(), "340282366920938463463374607431768211455")
}

func TestDivw(t *testing.T) {
	t.Parallel()
	// 2:0 / 1:0 == 2r0 == 0:2,0:0
	testAccepts(t, `int 2; int 0; int 1; int 0; divw;
                        int 0; ==; assert;
                        int 0; ==; assert;
                        int 2; ==; assert;
                        int 0; ==; assert; int 1`, 4)

	// 2:0 / 0:1 == 2:0r0 == 2:0,0:0
	testAccepts(t, `int 2; int 0; int 0; int 1; divw;
                        int 0; ==; assert;
                        int 0; ==; assert;
                        int 0; ==; assert;
                        int 2; ==; assert; int 1`, 4)

	// 0:0 / 0:7 == 0r0
	testAccepts(t, `int 0; int 0; int 0; int 7; divw;
                        int 0; ==; assert;
                        int 0; ==; assert;
                        int 0; ==; assert;
                        int 0; ==; assert; int 1`, 4)

	// maxu64:maxu64 / maxu64:maxu64 == 1r0
	testAccepts(t, `int 18446744073709551615; int 18446744073709551615; int 18446744073709551615; int 18446744073709551615;
                        divw;
                        int 0; ==; assert;
                        int 0; ==; assert;
                        int 1; ==; assert;
                        int 0; ==; assert; int 1`, 4)

	// 0:7777 / 1:0 == 0:0r7777 == 0:0,0:7777
	testAccepts(t, `int 0; int 7777; int 1; int 0; divw;
                        int 7777; ==; assert;
                        int 0; ==; assert;
                        int 0; ==; assert;
                        int 0; ==; assert; int 1`, 4)

	// 10:0 / 0:0 ==> panic
	testPanics(t, `int 10; int 0; int 0; int 0; divw;
	               pop; pop; pop; pop; int 1`, 4)
}

func TestDivZero(t *testing.T) {
	t.Parallel()
	testPanics(t, "int 0x11; int 0; /; pop; int 1", 1)
}

func TestModZero(t *testing.T) {
	t.Parallel()
	for v := uint64(1); v <= AssemblerMaxVersion; v++ {
		t.Run(fmt.Sprintf("v=%d", v), func(t *testing.T) {
			ops, err := AssembleStringWithVersion(`int 0x111111111
int 0
%
pop
int 1`, v)
			require.NoError(t, err)
			err = Check(ops.Program, defaultEvalParams(nil, nil))
			require.NoError(t, err)
			sb := strings.Builder{}
			pass, err := Eval(ops.Program, defaultEvalParams(&sb, nil))
			if pass {
				t.Log(hex.EncodeToString(ops.Program))
				t.Log(sb.String())
			}
			require.False(t, pass)
			require.Error(t, err)
			isNotPanic(t, err)
		})
	}
}

func TestErr(t *testing.T) {
	t.Parallel()
	for v := uint64(1); v <= AssemblerMaxVersion; v++ {
		t.Run(fmt.Sprintf("v=%d", v), func(t *testing.T) {
			ops, err := AssembleStringWithVersion(`err
int 1`, v)
			require.NoError(t, err)
			err = Check(ops.Program, defaultEvalParams(nil, nil))
			require.NoError(t, err)
			sb := strings.Builder{}
			pass, err := Eval(ops.Program, defaultEvalParams(&sb, nil))
			if pass {
				t.Log(hex.EncodeToString(ops.Program))
				t.Log(sb.String())
			}
			require.False(t, pass)
			require.Error(t, err)
			isNotPanic(t, err)
		})
	}
}

func TestModSubMulOk(t *testing.T) {
	t.Parallel()
	for v := uint64(1); v <= AssemblerMaxVersion; v++ {
		t.Run(fmt.Sprintf("v=%d", v), func(t *testing.T) {
			ops, err := AssembleStringWithVersion(`int 35
int 16
%
int 1
-
int 2
*
int 4
==`, v)
			require.NoError(t, err)
			err = Check(ops.Program, defaultEvalParams(nil, nil))
			require.NoError(t, err)
			sb := strings.Builder{}
			pass, err := Eval(ops.Program, defaultEvalParams(&sb, nil))
			if !pass {
				t.Log(hex.EncodeToString(ops.Program))
				t.Log(sb.String())
			}
			require.NoError(t, err)
			require.True(t, pass)
		})
	}
}

func TestPop(t *testing.T) {
	t.Parallel()
	for v := uint64(1); v <= AssemblerMaxVersion; v++ {
		t.Run(fmt.Sprintf("v=%d", v), func(t *testing.T) {
			ops, err := AssembleStringWithVersion(`int 1
int 0
pop`, v)
			require.NoError(t, err)
			sb := strings.Builder{}
			err = Check(ops.Program, defaultEvalParams(&sb, nil))
			require.NoError(t, err)
			sb = strings.Builder{}
			pass, err := Eval(ops.Program, defaultEvalParams(&sb, nil))
			if !pass {
				t.Log(hex.EncodeToString(ops.Program))
				t.Log(sb.String())
			}
			require.NoError(t, err)
			require.True(t, pass)
		})
	}
}

func TestStackLeftover(t *testing.T) {
	t.Parallel()
	for v := uint64(1); v <= AssemblerMaxVersion; v++ {
		t.Run(fmt.Sprintf("v=%d", v), func(t *testing.T) {
			ops, err := AssembleStringWithVersion(`int 1
int 1`, v)
			require.NoError(t, err)
			sb := strings.Builder{}
			err = Check(ops.Program, defaultEvalParams(&sb, nil))
			require.NoError(t, err)
			sb = strings.Builder{}
			pass, err := Eval(ops.Program, defaultEvalParams(&sb, nil))
			if pass {
				t.Log(hex.EncodeToString(ops.Program))
				t.Log(sb.String())
			}
			require.Error(t, err)
			require.False(t, pass)
			isNotPanic(t, err)
		})
	}
}

func TestStackBytesLeftover(t *testing.T) {
	t.Parallel()
	for v := uint64(1); v <= AssemblerMaxVersion; v++ {
		t.Run(fmt.Sprintf("v=%d", v), func(t *testing.T) {
			ops, err := AssembleStringWithVersion(`byte 0x10101010`, v)
			require.NoError(t, err)
			sb := strings.Builder{}
			err = Check(ops.Program, defaultEvalParams(&sb, nil))
			require.NoError(t, err)
			sb = strings.Builder{}
			pass, err := Eval(ops.Program, defaultEvalParams(&sb, nil))
			if pass {
				t.Log(hex.EncodeToString(ops.Program))
				t.Log(sb.String())
			}
			require.Error(t, err)
			require.False(t, pass)
			isNotPanic(t, err)
		})
	}
}

func TestStackEmpty(t *testing.T) {
	t.Parallel()
	for v := uint64(1); v <= AssemblerMaxVersion; v++ {
		t.Run(fmt.Sprintf("v=%d", v), func(t *testing.T) {
			ops, err := AssembleStringWithVersion(`int 1
int 1
pop
pop`, v)
			require.NoError(t, err)
			err = Check(ops.Program, defaultEvalParams(nil, nil))
			require.NoError(t, err)
			sb := strings.Builder{}
			pass, err := Eval(ops.Program, defaultEvalParams(&sb, nil))
			if pass {
				t.Log(hex.EncodeToString(ops.Program))
				t.Log(sb.String())
			}
			require.Error(t, err)
			require.False(t, pass)
			isNotPanic(t, err)
		})
	}
}

func TestArgTooFar(t *testing.T) {
	t.Parallel()
	for v := uint64(1); v <= AssemblerMaxVersion; v++ {
		t.Run(fmt.Sprintf("v=%d", v), func(t *testing.T) {
			ops, err := AssembleStringWithVersion(`arg_1
btoi`, v)
			require.NoError(t, err)
			err = Check(ops.Program, defaultEvalParams(nil, nil))
			require.NoError(t, err) // TODO: Check should know the type stack was wrong
			sb := strings.Builder{}
			var txn transactions.SignedTxn
			txn.Lsig.Logic = ops.Program
			txn.Lsig.Args = nil
			pass, err := Eval(ops.Program, defaultEvalParams(&sb, &txn))
			if pass {
				t.Log(hex.EncodeToString(ops.Program))
				t.Log(sb.String())
			}
			require.Error(t, err)
			require.False(t, pass)
			isNotPanic(t, err)
		})
	}
}

func TestIntcTooFar(t *testing.T) {
	t.Parallel()
	for v := uint64(1); v <= AssemblerMaxVersion; v++ {
		t.Run(fmt.Sprintf("v=%d", v), func(t *testing.T) {
			ops, err := AssembleStringWithVersion(`intc_1`, v)
			require.NoError(t, err)
			err = Check(ops.Program, defaultEvalParams(nil, nil))
			require.NoError(t, err) // TODO: Check should know the type stack was wrong
			sb := strings.Builder{}
			var txn transactions.SignedTxn
			txn.Lsig.Logic = ops.Program
			txn.Lsig.Args = nil
			pass, err := Eval(ops.Program, defaultEvalParams(&sb, &txn))
			if pass {
				t.Log(hex.EncodeToString(ops.Program))
				t.Log(sb.String())
			}
			require.Error(t, err)
			require.False(t, pass)
			isNotPanic(t, err)
		})
	}
}

func TestBytecTooFar(t *testing.T) {
	t.Parallel()
	for v := uint64(1); v <= AssemblerMaxVersion; v++ {
		t.Run(fmt.Sprintf("v=%d", v), func(t *testing.T) {
			ops, err := AssembleStringWithVersion(`bytec_1
btoi`, v)
			require.NoError(t, err)
			err = Check(ops.Program, defaultEvalParams(nil, nil))
			require.NoError(t, err) // TODO: Check should know the type stack was wrong
			sb := strings.Builder{}
			var txn transactions.SignedTxn
			txn.Lsig.Logic = ops.Program
			txn.Lsig.Args = nil
			pass, err := Eval(ops.Program, defaultEvalParams(&sb, &txn))
			if pass {
				t.Log(hex.EncodeToString(ops.Program))
				t.Log(sb.String())
			}
			require.Error(t, err)
			require.False(t, pass)
			isNotPanic(t, err)
		})
	}
}

func TestTxnBadField(t *testing.T) {
	t.Parallel()
	program := []byte{0x01, 0x31, 0x7f}
	err := Check(program, defaultEvalParams(nil, nil))
	require.NoError(t, err) // TODO: Check should know the type stack was wrong
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

	// test txn does not accept ApplicationArgs and Accounts
	txnOpcode := OpsByName[LogicVersion]["txn"].Opcode
	txnaOpcode := OpsByName[LogicVersion]["txna"].Opcode

	fields := []TxnField{ApplicationArgs, Accounts}
	for _, field := range fields {
		source := fmt.Sprintf("txn %s 0", field.String())
		ops, err := AssembleStringWithVersion(source, AssemblerMaxVersion)
		require.NoError(t, err)
		require.Equal(t, txnaOpcode, ops.Program[1])
		ops.Program[1] = txnOpcode
		pass, err = Eval(ops.Program, defaultEvalParams(&sb, &txn))
		require.Error(t, err)
		require.Contains(t, err.Error(), fmt.Sprintf("invalid txn field %d", field))
		require.False(t, pass)
	}
}

func TestGtxnBadIndex(t *testing.T) {
	t.Parallel()
	program := []byte{0x01, 0x33, 0x1, 0x01}
	err := Check(program, defaultEvalParams(nil, nil))
	require.NoError(t, err) // TODO: Check should know the type stack was wrong
	sb := strings.Builder{}
	var txn transactions.SignedTxn
	txn.Lsig.Logic = program
	txn.Lsig.Args = nil
	txgroup := make([]transactions.SignedTxn, 1)
	txgroup[0] = txn
	ep := defaultEvalParams(&sb, &txn)
	ep.TxnGroup = txgroup
	pass, err := Eval(program, ep)
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
	err := Check(program, defaultEvalParams(nil, nil))
	require.NoError(t, err) // TODO: Check should know the type stack was wrong
	sb := strings.Builder{}
	var txn transactions.SignedTxn
	txn.Lsig.Logic = program
	txn.Lsig.Args = nil
	txgroup := make([]transactions.SignedTxn, 1)
	txgroup[0] = txn
	ep := defaultEvalParams(&sb, &txn)
	ep.TxnGroup = txgroup
	pass, err := Eval(program, ep)
	if pass {
		t.Log(hex.EncodeToString(program))
		t.Log(sb.String())
	}
	require.Error(t, err)
	require.False(t, pass)
	isNotPanic(t, err)

	// test gtxn does not accept ApplicationArgs and Accounts
	txnOpcode := OpsByName[LogicVersion]["txn"].Opcode
	txnaOpcode := OpsByName[LogicVersion]["txna"].Opcode

	fields := []TxnField{ApplicationArgs, Accounts}
	for _, field := range fields {
		source := fmt.Sprintf("txn %s 0", field.String())
		ops, err := AssembleStringWithVersion(source, AssemblerMaxVersion)
		require.NoError(t, err)
		require.Equal(t, txnaOpcode, ops.Program[1])
		ops.Program[1] = txnOpcode
		pass, err = Eval(ops.Program, defaultEvalParams(&sb, &txn))
		require.Error(t, err)
		require.Contains(t, err.Error(), fmt.Sprintf("invalid txn field %d", field))
		require.False(t, pass)
	}
}

func TestGlobalBadField(t *testing.T) {
	t.Parallel()
	program := []byte{0x01, 0x32, 0x7f}
	err := Check(program, defaultEvalParams(nil, nil))
	require.NoError(t, err) // Check does not validates opcode args
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
	for v := uint64(1); v <= AssemblerMaxVersion; v++ {
		t.Run(fmt.Sprintf("v=%d", v), func(t *testing.T) {
			ops, err := AssembleStringWithVersion(`arg 0
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
&&`, v)
			require.NoError(t, err)
			err = Check(ops.Program, defaultEvalParams(nil, nil))
			require.NoError(t, err)
			var txn transactions.SignedTxn
			txn.Lsig.Logic = ops.Program
			txn.Lsig.Args = [][]byte{
				[]byte("aoeu"),
				[]byte("aoeu"),
				[]byte("aoeu2"),
				[]byte("aoeu3"),
				[]byte("aoeu4"),
			}
			sb := strings.Builder{}
			pass, err := Eval(ops.Program, defaultEvalParams(&sb, &txn))
			if !pass {
				t.Log(hex.EncodeToString(ops.Program))
				t.Log(sb.String())
			}
			require.NoError(t, err)
			require.True(t, pass)
		})
	}
}

const globalV1TestProgram = `
global MinTxnFee
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
&&
global GroupSize
int 1
==
&&
`

const testAddr = "47YPQTIGQEO7T4Y4RWDYWEKV6RTR2UNBQXBABEEGM72ESWDQNCQ52OPASU"

const globalV2TestProgram = globalV1TestProgram + `
global LogicSigVersion
int 1
>
&&
global Round
int 0
>
&&
global LatestTimestamp
int 0
>
&&
global CurrentApplicationID
int 42
==
&&
`
const globalV3TestProgram = globalV2TestProgram + `
global CreatorAddress
addr ` + testAddr + `
==
&&
`

const globalV4TestProgram = globalV3TestProgram + `
// No new globals in v4
`

func TestGlobal(t *testing.T) {
	t.Parallel()
	type desc struct {
		lastField GlobalField
		program   string
		eval      func([]byte, EvalParams) (bool, error)
		check     func([]byte, EvalParams) error
	}
	tests := map[uint64]desc{
		0: {GroupSize, globalV1TestProgram, Eval, Check},
		1: {GroupSize, globalV1TestProgram, Eval, Check},
		2: {
			CurrentApplicationID, globalV2TestProgram,
			EvalStateful, CheckStateful,
		},
		3: {
			CreatorAddress, globalV3TestProgram,
			EvalStateful, CheckStateful,
		},
		4: {
			CreatorAddress, globalV4TestProgram,
			EvalStateful, CheckStateful,
		},
	}
	ledger := makeTestLedger(nil)
	ledger.appID = 42
	addr, err := basics.UnmarshalChecksumAddress(testAddr)
	require.NoError(t, err)
	ledger.creatorAddr = addr
	for v := uint64(0); v <= AssemblerMaxVersion; v++ {
		t.Run(fmt.Sprintf("v=%d", v), func(t *testing.T) {
			last := tests[v].lastField
			testProgram := tests[v].program
			check := tests[v].check
			eval := tests[v].eval
			for _, globalField := range GlobalFieldNames[:last] {
				if !strings.Contains(testProgram, globalField) {
					t.Errorf("TestGlobal missing field %v", globalField)
				}
			}
			ops := testProg(t, testProgram, v)
			err := check(ops.Program, defaultEvalParams(nil, nil))
			require.NoError(t, err)
			var txn transactions.SignedTxn
			txn.Lsig.Logic = ops.Program
			txgroup := make([]transactions.SignedTxn, 1)
			txgroup[0] = txn
			sb := strings.Builder{}
			block := bookkeeping.Block{}
			block.BlockHeader.Round = 999999
			block.BlockHeader.TimeStamp = 2069
			proto := config.ConsensusParams{
				MinTxnFee:         123,
				MinBalance:        1000000,
				MaxTxnLife:        999,
				LogicSigVersion:   LogicVersion,
				LogicSigMaxCost:   20000,
				MaxAppProgramCost: 700,
			}
			ep := defaultEvalParams(&sb, &txn)
			ep.TxnGroup = txgroup
			ep.Proto = &proto
			ep.Ledger = ledger
			pass, err := eval(ops.Program, ep)
			if !pass {
				t.Log(hex.EncodeToString(ops.Program))
				t.Log(sb.String())
			}
			require.NoError(t, err)
			require.True(t, pass)
		})
	}
}

func TestTypeEnum(t *testing.T) {
	t.Parallel()
	for v := uint64(1); v <= AssemblerMaxVersion; v++ {
		t.Run(fmt.Sprintf("v=%d", v), func(t *testing.T) {
			ttypes := []protocol.TxType{
				protocol.PaymentTx,
				protocol.KeyRegistrationTx,
				protocol.AssetConfigTx,
				protocol.AssetTransferTx,
				protocol.AssetFreezeTx,
				protocol.ApplicationCallTx,
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
				"ApplicationCall",
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
					ops, err := AssembleStringWithVersion(text, v)
					require.NoError(t, err)
					err = Check(ops.Program, defaultEvalParams(nil, nil))
					require.NoError(t, err)
					var txn transactions.SignedTxn
					txn.Txn.Type = tt
					sb := strings.Builder{}
					ep := defaultEvalParams(&sb, &txn)
					ep.GroupIndex = 3
					pass, err := Eval(ops.Program, ep)
					if !pass {
						t.Log(hex.EncodeToString(ops.Program))
						t.Log(sb.String())
					}
					require.NoError(t, err)
					require.True(t, pass)
				})
			}
		})
	}
}

func TestOnCompletionConstants(t *testing.T) {
	t.Parallel()

	// ensure all the OnCompetion values are in OnCompletionValues list
	var max int = 100
	var last int = max
	for i := 0; i < max; i++ {
		oc := transactions.OnCompletion(i)
		unknownStringer := "OnCompletion(" + strconv.FormatInt(int64(i), 10) + ")"
		if oc.String() == unknownStringer {
			last = i
			break
		}
	}
	require.Less(t, last, max, "too many OnCompletion constants, adjust max limit")
	require.Equal(t, int(invalidOnCompletionConst), last)
	require.Equal(t, len(onCompletionConstToUint64), len(onCompletionDescriptions))
	require.Equal(t, len(OnCompletionNames), last)
	for v := NoOp; v < invalidOnCompletionConst; v++ {
		require.Equal(t, v.String(), OnCompletionNames[int(v)])
	}

	// check constants matching to their values
	ep := defaultEvalParams(nil, nil)
	for v := uint64(1); v <= AssemblerMaxVersion; v++ {
		t.Run(fmt.Sprintf("v=%d", v), func(t *testing.T) {
			for i := 0; i < last; i++ {
				oc := OnCompletionConstType(i)
				symbol := oc.String()
				require.Contains(t, onCompletionConstToUint64, symbol)
				require.Equal(t, uint64(i), onCompletionConstToUint64[symbol])
				t.Run(symbol, func(t *testing.T) {
					text := fmt.Sprintf(`int %s
int %s
==
`, symbol, oc)
					ops, err := AssembleStringWithVersion(text, v)
					require.NoError(t, err)
					pass, err := Eval(ops.Program, ep)
					require.NoError(t, err)
					require.True(t, pass)
				})
			}
		})
	}
}

const testTxnProgramTextV1 = `txn Sender
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
&&
`

const testTxnProgramTextV2 = testTxnProgramTextV1 + `txn ApplicationID
int 123
==
&&
txn OnCompletion
int 0
==
&&
txna ApplicationArgs 0
byte 0x706179
==
&&
txn NumAppArgs
int 8
==
&&
txna Accounts 0
arg 0
==
&&
txn NumAccounts
int 1
==
&&
byte b64 UHJvZ3JhbQ==  // Program
txn ApprovalProgram
concat
sha512_256
arg 9
==
&&
byte b64 UHJvZ3JhbQ==  // Program
txn ClearStateProgram
concat
sha512_256
arg 10
==
&&
txn RekeyTo
txna ApplicationArgs 1
==
&&
txn ConfigAsset
int 33
==
&&
txn ConfigAssetTotal
int 100
==
&&
txn ConfigAssetDecimals
int 2
==
&&
txn ConfigAssetDefaultFrozen
int 1
==
&&
txn ConfigAssetUnitName
byte "tok"
==
&&
txn ConfigAssetName
byte "a_super_coin"
==
&&
txn ConfigAssetURL
byte "http://algorand.com"
==
&&
txn ConfigAssetMetadataHash
txna ApplicationArgs 2
==
&&
txn ConfigAssetManager
txna ApplicationArgs 3
==
&&
txn ConfigAssetReserve
txna ApplicationArgs 4
==
&&
txn ConfigAssetFreeze
txna ApplicationArgs 5
==
&&
txn ConfigAssetClawback
txna ApplicationArgs 6
==
&&
txn FreezeAsset
int 34
==
&&
txn FreezeAssetAccount
txna ApplicationArgs 7
==
&&
txn FreezeAssetFrozen
int 1
==
&&
`

const testTxnProgramTextV3 = testTxnProgramTextV2 + `
assert
txn NumAssets
int 2
==
assert
txna Assets 0
int 55
==
assert
txn NumApplications
int 3
==
assert
txn Applications 3			// Assembler will use 'txna'
int 111
==
assert

txn GlobalNumUint
int 3
==
assert
txn GlobalNumByteSlice
int 0
==
assert
txn LocalNumUint
int 1
==
assert
txn LocalNumByteSlice
int 2
==
assert


int 1
`

const testTxnProgramTextV4 = testTxnProgramTextV3 + `
assert
txn AppProgramExtraPages
int 2
==
assert


int 1
`

func makeSampleTxn() transactions.SignedTxn {
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
	txn.Txn.ApplicationID = basics.AppIndex(123)
	txn.Txn.Accounts = make([]basics.Address, 1)
	txn.Txn.Accounts[0] = txn.Txn.Receiver
	rekeyToAddr := []byte("aoeuiaoeuiaoeuiaoeuiaoeuiaoeui05")
	metadata := []byte("aoeuiaoeuiaoeuiaoeuiaoeuiaoeuiHH")
	managerAddr := []byte("aoeuiaoeuiaoeuiaoeuiaoeuiaoeui06")
	reserveAddr := []byte("aoeuiaoeuiaoeuiaoeuiaoeuiaoeui07")
	freezeAddr := []byte("aoeuiaoeuiaoeuiaoeuiaoeuiaoeui08")
	clawbackAddr := []byte("aoeuiaoeuiaoeuiaoeuiaoeuiaoeui09")
	freezeAccAddr := []byte("aoeuiaoeuiaoeuiaoeuiaoeuiaoeui10")
	txn.Txn.ApplicationArgs = [][]byte{
		[]byte(protocol.PaymentTx),
		rekeyToAddr,
		metadata,
		managerAddr,
		reserveAddr,
		freezeAddr,
		clawbackAddr,
		freezeAccAddr,
	}
	copy(txn.Txn.RekeyTo[:], rekeyToAddr)
	txn.Txn.ConfigAsset = 33
	txn.Txn.AssetParams.Total = 100
	txn.Txn.AssetParams.Decimals = 2
	txn.Txn.AssetParams.DefaultFrozen = true
	txn.Txn.AssetParams.UnitName = "tok"
	txn.Txn.AssetParams.AssetName = "a_super_coin"
	txn.Txn.AssetParams.URL = "http://algorand.com"
	txn.Txn.AssetParams.UnitName = "tok"
	copy(txn.Txn.AssetParams.MetadataHash[:], metadata)
	copy(txn.Txn.AssetParams.Manager[:], managerAddr)
	copy(txn.Txn.AssetParams.Reserve[:], reserveAddr)
	copy(txn.Txn.AssetParams.Freeze[:], freezeAddr)
	copy(txn.Txn.AssetParams.Clawback[:], clawbackAddr)
	txn.Txn.FreezeAsset = 34
	copy(txn.Txn.FreezeAccount[:], freezeAccAddr)
	txn.Txn.AssetFrozen = true
	txn.Txn.ForeignAssets = []basics.AssetIndex{55, 77}
	txn.Txn.ForeignApps = []basics.AppIndex{56, 78, 111}
	txn.Txn.GlobalStateSchema = basics.StateSchema{NumUint: 3, NumByteSlice: 0}
	txn.Txn.LocalStateSchema = basics.StateSchema{NumUint: 1, NumByteSlice: 2}
	return txn
}

func makeSampleTxnGroup(txn transactions.SignedTxn) []transactions.SignedTxn {
	txgroup := make([]transactions.SignedTxn, 2)
	txgroup[0] = txn
	txgroup[1].Txn.Amount.Raw = 42
	txgroup[1].Txn.Fee.Raw = 1066
	txgroup[1].Txn.FirstValid = 42
	txgroup[1].Txn.LastValid = 1066
	txgroup[1].Txn.Sender = txn.Txn.Receiver
	txgroup[1].Txn.Receiver = txn.Txn.Sender
	return txgroup
}

func TestTxn(t *testing.T) {
	t.Parallel()
	for _, txnField := range TxnFieldNames {
		if !strings.Contains(testTxnProgramTextV4, txnField) {
			if txnField != FirstValidTime.String() {
				t.Errorf("TestTxn missing field %v", txnField)
			}
		}
	}

	tests := map[uint64]string{
		1: testTxnProgramTextV1,
		2: testTxnProgramTextV2,
		3: testTxnProgramTextV3,
		4: testTxnProgramTextV4,
	}

	clearOps, err := AssembleStringWithVersion("int 1", 1)
	require.NoError(t, err)

	for v, source := range tests {
		t.Run(fmt.Sprintf("v=%d", v), func(t *testing.T) {
			ops := testProg(t, source, v)
			err := Check(ops.Program, defaultEvalParams(nil, nil))
			require.NoError(t, err)
			txn := makeSampleTxn()
			txn.Txn.ApprovalProgram = ops.Program
			txn.Txn.ClearStateProgram = clearOps.Program
			txn.Lsig.Logic = ops.Program
			txn.Txn.ExtraProgramPages = 2
			// RekeyTo not allowed in TEAL v1
			if v < rekeyingEnabledVersion {
				txn.Txn.RekeyTo = basics.Address{}
			}
			txid := txn.Txn.ID()
			programHash := HashProgram(ops.Program)
			clearProgramHash := HashProgram(clearOps.Program)
			txn.Lsig.Args = [][]byte{
				txn.Txn.Sender[:],
				txn.Txn.Receiver[:],
				txn.Txn.CloseRemainderTo[:],
				txn.Txn.VotePK[:],
				txn.Txn.SelectionPK[:],
				txn.Txn.Note,
				{0, 0, 0, 0, 0, 0, 0, 1},
				txid[:],
				txn.Txn.Lease[:],
				programHash[:],
				clearProgramHash[:],
			}
			sb := strings.Builder{}
			ep := defaultEvalParams(&sb, &txn)
			ep.GroupIndex = 3
			pass, err := Eval(ops.Program, ep)
			if !pass {
				t.Log(hex.EncodeToString(ops.Program))
				t.Log(sb.String())
			}
			require.NoError(t, err)
			require.True(t, pass)
		})
	}
}

func TestCachedTxIDs(t *testing.T) {
	t.Parallel()
	cachedTxnProg := `
gtxn 0 TxID
arg 0
==
bz fail

gtxn 0 TxID
arg 0
==
bz fail

txn TxID
arg 0
==
bz fail

txn TxID
arg 0
==
bz fail

gtxn 1 TxID
arg 1
==
bz fail

gtxn 1 TxID
arg 1
==
bz fail

success:
int 1
return

fail:
int 0
return
`
	ops, err := AssembleStringWithVersion(cachedTxnProg, 2)
	require.NoError(t, err)
	sb := strings.Builder{}
	err = Check(ops.Program, defaultEvalParams(&sb, nil))
	if err != nil {
		t.Log(hex.EncodeToString(ops.Program))
		t.Log(sb.String())
	}
	require.NoError(t, err)
	txn := makeSampleTxn()
	txgroup := makeSampleTxnGroup(txn)
	txn.Lsig.Logic = ops.Program
	txid0 := txgroup[0].ID()
	txid1 := txgroup[1].ID()
	txn.Lsig.Args = [][]byte{
		txid0[:],
		txid1[:],
	}
	sb = strings.Builder{}
	ep := defaultEvalParams(&sb, &txn)
	ep.TxnGroup = txgroup
	pass, err := Eval(ops.Program, ep)
	if !pass || err != nil {
		t.Log(hex.EncodeToString(ops.Program))
		t.Log(sb.String())
	}
	require.NoError(t, err)
	require.True(t, pass)
}

func TestGtxn(t *testing.T) {
	t.Parallel()
	gtxnTextV1 := `gtxn 1 Amount
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
&&
`

	gtxnText := gtxnTextV1 + `gtxna 0 ApplicationArgs 0
byte 0x706179
==
&&
gtxn 0 NumAppArgs
int 8
==
&&
gtxna 0 Accounts 0
gtxn 0 Sender
==
&&
gtxn 0 NumAccounts
int 1
==
&&
`

	tests := map[uint64]string{
		1: gtxnTextV1,
		2: gtxnText,
	}

	for v, source := range tests {
		t.Run(fmt.Sprintf("v=%d", v), func(t *testing.T) {
			txn := makeSampleTxn()
			// RekeyTo not allowed in TEAL v1
			if v < rekeyingEnabledVersion {
				txn.Txn.RekeyTo = basics.Address{}
			}
			txn.Lsig.Args = [][]byte{
				txn.Txn.Sender[:],
				txn.Txn.Receiver[:],
				txn.Txn.CloseRemainderTo[:],
				txn.Txn.VotePK[:],
				txn.Txn.SelectionPK[:],
				txn.Txn.Note,
			}
			ep := defaultEvalParams(nil, &txn)
			ep.TxnGroup = makeSampleTxnGroup(txn)
			testLogic(t, source, v, ep)
			if v >= 3 {
				gtxnsProg := strings.ReplaceAll(source, "gtxn 0", "int 0; gtxns")
				gtxnsProg = strings.ReplaceAll(gtxnsProg, "gtxn 1", "int 1; gtxns")
				gtxnsProg = strings.ReplaceAll(gtxnsProg, "gtxna 0", "int 0; gtxnsa")
				gtxnsProg = strings.ReplaceAll(gtxnsProg, "gtxna 1", "int 1; gtxnsa")
				require.False(t, strings.Contains(gtxnsProg, "gtxn "))  // Got 'em all
				require.False(t, strings.Contains(gtxnsProg, "gtxna ")) // Got 'em all
				testLogic(t, gtxnsProg, v, ep)
			}
		})
	}
}

func testLogic(t *testing.T, program string, v uint64, ep EvalParams, problems ...string) {
	ops := testProg(t, program, v)
	sb := &strings.Builder{}
	ep.Trace = sb
	ep.Txn.Lsig.Logic = ops.Program
	err := Check(ops.Program, ep)
	if err != nil {
		t.Log(hex.EncodeToString(ops.Program))
		t.Log(sb.String())
	}
	require.NoError(t, err)

	pass, err := Eval(ops.Program, ep)
	if len(problems) == 0 {
		require.NoError(t, err, sb.String())
		require.True(t, pass, sb.String())
	} else {
		require.Error(t, err, sb.String())
		for _, problem := range problems {
			require.Contains(t, err.Error(), problem)
		}
	}
}

func TestTxna(t *testing.T) {
	t.Parallel()
	source := `txna Accounts 1
txna ApplicationArgs 0
==
`
	ops, err := AssembleStringWithVersion(source, AssemblerMaxVersion)
	require.NoError(t, err)
	var txn transactions.SignedTxn
	txn.Txn.Accounts = make([]basics.Address, 1)
	txn.Txn.Accounts[0] = txn.Txn.Sender
	txn.Txn.ApplicationArgs = make([][]byte, 1)
	txn.Txn.ApplicationArgs[0] = []byte(protocol.PaymentTx)
	txgroup := make([]transactions.SignedTxn, 1)
	txgroup[0] = txn
	ep := defaultEvalParams(nil, &txn)
	ep.TxnGroup = txgroup
	_, err = Eval(ops.Program, ep)
	require.NoError(t, err)

	// modify txn field
	saved := ops.Program[2]
	ops.Program[2] = 0x01
	_, err = Eval(ops.Program, ep)
	require.Error(t, err)
	require.Contains(t, err.Error(), "txna unsupported field")

	// modify txn field to unknown one
	ops.Program[2] = 99
	_, err = Eval(ops.Program, ep)
	require.Error(t, err)
	require.Contains(t, err.Error(), "invalid txn field 99")

	// modify txn array index
	ops.Program[2] = saved
	saved = ops.Program[3]
	ops.Program[3] = 0x02
	_, err = Eval(ops.Program, ep)
	require.Error(t, err)
	require.Contains(t, err.Error(), "invalid Accounts index")

	// modify txn array index in the second opcode
	ops.Program[3] = saved
	saved = ops.Program[6]
	ops.Program[6] = 0x01
	_, err = Eval(ops.Program, ep)
	require.Error(t, err)
	require.Contains(t, err.Error(), "invalid ApplicationArgs index")
	ops.Program[6] = saved

	// check special case: Account 0 == Sender
	// even without any additional context
	source = `txna Accounts 0
txn Sender
==
`
	ops2, err := AssembleStringWithVersion(source, AssemblerMaxVersion)
	require.NoError(t, err)
	var txn2 transactions.SignedTxn
	copy(txn2.Txn.Sender[:], []byte("aoeuiaoeuiaoeuiaoeuiaoeuiaoeui00"))
	ep2 := defaultEvalParams(nil, &txn2)
	pass, err := Eval(ops2.Program, ep2)
	require.NoError(t, err)
	require.True(t, pass)

	// check gtxna
	source = `gtxna 0 Accounts 1
txna ApplicationArgs 0
==`
	ops, err = AssembleStringWithVersion(source, AssemblerMaxVersion)
	require.NoError(t, err)
	_, err = Eval(ops.Program, ep)
	require.NoError(t, err)

	// modify gtxn index
	saved = ops.Program[2]
	ops.Program[2] = 0x01
	_, err = Eval(ops.Program, ep)
	require.Error(t, err)
	require.Contains(t, err.Error(), "gtxna lookup TxnGroup[1] but it only has 1")

	// modify gtxn field
	ops.Program[2] = saved
	saved = ops.Program[3]
	ops.Program[3] = 0x01
	_, err = Eval(ops.Program, ep)
	require.Error(t, err)
	require.Contains(t, err.Error(), "gtxna unsupported field")

	// modify gtxn field to unknown one
	ops.Program[3] = 99
	_, err = Eval(ops.Program, ep)
	require.Error(t, err)
	require.Contains(t, err.Error(), "invalid txn field 99")

	// modify gtxn array index
	ops.Program[3] = saved
	saved = ops.Program[4]
	ops.Program[4] = 0x02
	_, err = Eval(ops.Program, ep)
	require.Error(t, err)
	require.Contains(t, err.Error(), "invalid Accounts index")
	ops.Program[4] = saved

	// check special case: Account 0 == Sender
	// even without any additional context
	source = `gtxna 0 Accounts 0
txn Sender
==
`
	ops3, err := AssembleStringWithVersion(source, AssemblerMaxVersion)
	require.NoError(t, err)
	var txn3 transactions.SignedTxn
	copy(txn2.Txn.Sender[:], []byte("aoeuiaoeuiaoeuiaoeuiaoeuiaoeui00"))
	txgroup3 := make([]transactions.SignedTxn, 1)
	txgroup3[0] = txn3
	ep3 := defaultEvalParams(nil, &txn3)
	ep3.TxnGroup = txgroup3
	pass, err = Eval(ops3.Program, ep3)
	require.NoError(t, err)
	require.True(t, pass)
}

// check empty values in ApplicationArgs and Account
func TestTxnaEmptyValues(t *testing.T) {
	t.Parallel()
	source := `txna ApplicationArgs 0
btoi
int 0
==
`
	ops, err := AssembleStringWithVersion(source, AssemblerMaxVersion)
	require.NoError(t, err)

	var txn transactions.SignedTxn
	txn.Txn.ApplicationArgs = make([][]byte, 1)
	txn.Txn.ApplicationArgs[0] = []byte("")
	txgroup := make([]transactions.SignedTxn, 1)
	txgroup[0] = txn
	ep := defaultEvalParams(nil, &txn)
	ep.TxnGroup = txgroup
	pass, err := Eval(ops.Program, ep)
	require.NoError(t, err)
	require.True(t, pass)
	txn.Txn.ApplicationArgs[0] = nil
	txgroup[0] = txn
	ep.TxnGroup = txgroup
	pass, err = Eval(ops.Program, ep)
	require.NoError(t, err)
	require.True(t, pass)

	source2 := `txna Accounts 1
global ZeroAddress
==
`
	ops2, err := AssembleStringWithVersion(source2, AssemblerMaxVersion)
	require.NoError(t, err)

	var txn2 transactions.SignedTxn
	txn2.Txn.Accounts = make([]basics.Address, 1)
	txn2.Txn.Accounts[0] = basics.Address{}
	txgroup2 := make([]transactions.SignedTxn, 1)
	txgroup2[0] = txn2
	ep2 := defaultEvalParams(nil, &txn2)
	ep2.TxnGroup = txgroup2
	pass, err = Eval(ops2.Program, ep2)
	require.NoError(t, err)
	require.True(t, pass)
	txn2.Txn.Accounts = make([]basics.Address, 1)
	txgroup2[0] = txn
	ep2.TxnGroup = txgroup2
	pass, err = Eval(ops2.Program, ep2)
	require.NoError(t, err)
	require.True(t, pass)
}

func TestBitOps(t *testing.T) {
	t.Parallel()
	for v := uint64(1); v <= AssemblerMaxVersion; v++ {
		t.Run(fmt.Sprintf("v=%d", v), func(t *testing.T) {
			ops, err := AssembleStringWithVersion(`int 0x17
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
==`, v)
			require.NoError(t, err)
			err = Check(ops.Program, defaultEvalParams(nil, nil))
			require.NoError(t, err)
			sb := strings.Builder{}
			pass, err := Eval(ops.Program, defaultEvalParams(&sb, nil))
			if !pass {
				t.Log(hex.EncodeToString(ops.Program))
				t.Log(sb.String())
			}
			require.NoError(t, err)
			require.True(t, pass)
		})
	}
}

func TestStringOps(t *testing.T) {
	t.Parallel()
	ops := testProg(t, `byte 0x123456789abc
substring 1 3
byte 0x3456
==
byte 0x12
byte 0x3456
byte 0x789abc
concat
concat
byte 0x123456789abc
==
&&
byte 0x123456789abc
int 1
int 3
substring3
byte 0x3456
==
&&
byte 0x123456789abc
int 3
int 3
substring3
len
int 0
==
&&`, 2)
	err := Check(ops.Program, defaultEvalParams(nil, nil))
	require.NoError(t, err)
	sb := strings.Builder{}
	pass, err := Eval(ops.Program, defaultEvalParams(&sb, nil))
	if !pass {
		t.Log(hex.EncodeToString(ops.Program))
		t.Log(sb.String())
	}
	require.NoError(t, err)
	require.True(t, pass)
}

func TestConsOverflow(t *testing.T) {
	t.Parallel()
	ops := testProg(t, `byte 0xf000000000000000
dup
concat
dup
concat
dup
concat
dup
concat
dup
concat
dup
concat
dup
concat
dup
concat
dup
concat
dup
concat
dup
concat
dup
concat
dup
concat
dup
concat
dup
concat
dup
concat
dup
concat
dup
concat
len`, 2)
	err := Check(ops.Program, defaultEvalParams(nil, nil))
	require.NoError(t, err)
	sb := strings.Builder{}
	pass, err := Eval(ops.Program, defaultEvalParams(&sb, nil))
	if pass {
		t.Log(hex.EncodeToString(ops.Program))
		t.Log(sb.String())
	}
	require.False(t, pass)
	require.Error(t, err)
	isNotPanic(t, err)
}

func TestSubstringFlop(t *testing.T) {
	t.Parallel()
	// fails in compiler
	ops := testProg(t, `byte 0xf000000000000000
substring 4 2
len`, 2, expect{2, "substring end is before start"})

	// fails at runtime
	ops = testProg(t, `byte 0xf000000000000000
int 4
int 2
substring3
len`, 2)
	err := Check(ops.Program, defaultEvalParams(nil, nil))
	require.NoError(t, err)
	sb := strings.Builder{}
	pass, err := Eval(ops.Program, defaultEvalParams(&sb, nil))
	if pass {
		t.Log(hex.EncodeToString(ops.Program))
		t.Log(sb.String())
	}
	require.False(t, pass)
	require.Error(t, err)
	isNotPanic(t, err)

	// fails at runtime
	ops = testProg(t, `byte 0xf000000000000000
int 4
int 0xFFFFFFFFFFFFFFFE
substring3
len`, 2)
	err = Check(ops.Program, defaultEvalParams(nil, nil))
	require.NoError(t, err)
	pass, err = Eval(ops.Program, defaultEvalParams(nil, nil))
	require.False(t, pass)
	require.Error(t, err)
	require.Contains(t, err.Error(), "substring range beyond length of string")
}

func TestSubstringRange(t *testing.T) {
	t.Parallel()
	ops := testProg(t, `byte 0xf000000000000000
substring 2 99
len`, 2)
	err := Check(ops.Program, defaultEvalParams(nil, nil))
	require.NoError(t, err)
	sb := strings.Builder{}
	pass, err := Eval(ops.Program, defaultEvalParams(&sb, nil))
	if pass {
		t.Log(hex.EncodeToString(ops.Program))
		t.Log(sb.String())
	}
	require.False(t, pass)
	require.Error(t, err)
	isNotPanic(t, err)
}

func TestLoadStore(t *testing.T) {
	t.Parallel()
	for v := uint64(1); v <= AssemblerMaxVersion; v++ {
		t.Run(fmt.Sprintf("v=%d", v), func(t *testing.T) {
			ops := testProg(t, `int 37
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
&&`, v)
			err := Check(ops.Program, defaultEvalParams(nil, nil))
			require.NoError(t, err)
			sb := strings.Builder{}
			pass, err := Eval(ops.Program, defaultEvalParams(&sb, nil))
			if !pass {
				t.Log(hex.EncodeToString(ops.Program))
				t.Log(sb.String())
			}
			require.NoError(t, err)
			require.True(t, pass)
		})
	}
}

func TestLoadStore2(t *testing.T) {
	t.Parallel()
	progText := `int 2
int 3
byte 0xaa
store 44
store 43
store 42
load 43
load 42
+
int 5
==`
	for v := uint64(1); v <= AssemblerMaxVersion; v++ {
		t.Run(fmt.Sprintf("v=%d", v), func(t *testing.T) {
			ops := testProg(t, progText, v)
			err := Check(ops.Program, defaultEvalParams(nil, nil))
			require.NoError(t, err)
			sb := strings.Builder{}
			pass, err := Eval(ops.Program, defaultEvalParams(&sb, nil))
			if !pass {
				t.Log(hex.EncodeToString(ops.Program))
				t.Log(sb.String())
			}
			require.NoError(t, err)
			require.True(t, pass)
		})
	}
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
	for v := uint64(1); v <= AssemblerMaxVersion; v++ {
		t.Run(fmt.Sprintf("v=%d", v), func(t *testing.T) {
			ops, err := AssembleStringWithVersion(testCompareProgramText, v)
			require.NoError(t, err)
			err = Check(ops.Program, defaultEvalParams(nil, nil))
			require.NoError(t, err)
			sb := strings.Builder{}
			pass, err := Eval(ops.Program, defaultEvalParams(nil, nil))
			if !pass {
				t.Log(hex.EncodeToString(ops.Program))
				t.Log(sb.String())
			}
			require.NoError(t, err)
			require.True(t, pass)
		})
	}
}

func TestKeccak256(t *testing.T) {
	t.Parallel()
	/*
		pip install sha3
		import sha3
		blob=b'fnord'
		sha3.keccak_256(blob).hexdigest()
	*/
	progText := `byte 0x666E6F7264
keccak256
byte 0xc195eca25a6f4c82bfba0287082ddb0d602ae9230f9cf1f1a40b68f8e2c41567
==`
	for v := uint64(1); v <= AssemblerMaxVersion; v++ {
		t.Run(fmt.Sprintf("v=%d", v), func(t *testing.T) {
			ops, err := AssembleStringWithVersion(progText, v)
			require.NoError(t, err)
			err = Check(ops.Program, defaultEvalParams(nil, nil))
			require.NoError(t, err)
			sb := strings.Builder{}
			pass, err := Eval(ops.Program, defaultEvalParams(nil, nil))
			if !pass {
				t.Log(hex.EncodeToString(ops.Program))
				t.Log(sb.String())
			}
			require.NoError(t, err)
			require.True(t, pass)
		})
	}
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
	progText := `byte 0x666E6F7264
sha512_256

byte 0x98D2C31612EA500279B6753E5F6E780CA63EBA8274049664DAD66A2565ED1D2A
==`
	for v := uint64(1); v <= AssemblerMaxVersion; v++ {
		t.Run(fmt.Sprintf("v=%d", v), func(t *testing.T) {
			ops, err := AssembleStringWithVersion(progText, v)
			require.NoError(t, err)
			err = Check(ops.Program, defaultEvalParams(nil, nil))
			require.NoError(t, err)
			sb := strings.Builder{}
			pass, err := Eval(ops.Program, defaultEvalParams(&sb, nil))
			if !pass {
				t.Log(hex.EncodeToString(ops.Program))
				t.Log(sb.String())
			}
			require.NoError(t, err)
			require.True(t, pass)
		})
	}
}

func TestSlowLogic(t *testing.T) {
	t.Parallel()
	fragment := `byte 0x666E6F7264; keccak256
                     byte 0xc195eca25a6f4c82bfba0287082ddb0d602ae9230f9cf1f1a40b68f8e2c41567; ==;`

	// Sanity check. Running a short sequence of these fragments passes in all versions.
	source := fragment + strings.Repeat(fragment+"&&;", 5)
	testAccepts(t, source, 1)

	// in v1, each repeat costs 30
	v1overspend := fragment + strings.Repeat(fragment+"&&;", 20000/30)
	// in v2,v3 each repeat costs 134
	v2overspend := fragment + strings.Repeat(fragment+"&&;", 20000/134)

	// v1overspend fails (on v1)
	ops := testProg(t, v1overspend, 1)
	err := Check(ops.Program, defaultEvalParamsWithVersion(nil, nil, 1))
	require.Error(t, err)
	require.Contains(t, err.Error(), "static cost")
	// v2overspend passes Check, even on v2 proto, because cost is "grandfathered"
	ops = testProg(t, v2overspend, 1)
	err = Check(ops.Program, defaultEvalParamsWithVersion(nil, nil, 2))
	require.NoError(t, err)

	// even the shorter, v2overspend, fails when compiled as v2 code
	ops = testProg(t, v2overspend, 2)
	err = Check(ops.Program, defaultEvalParamsWithVersion(nil, nil, 2))
	require.Error(t, err)
	require.Contains(t, err.Error(), "static cost")

	// in v4 cost is still 134, but only matters in Eval, not Check, so both fail there
	ep4 := defaultEvalParamsWithVersion(nil, nil, 4)
	ops = testProg(t, v1overspend, 4)
	err = Check(ops.Program, ep4)
	require.NoError(t, err)
	_, err = Eval(ops.Program, ep4)
	require.Error(t, err)
	require.Contains(t, err.Error(), "dynamic cost")

	ops = testProg(t, v2overspend, 4)
	err = Check(ops.Program, ep4)
	require.NoError(t, err)
	_, err = Eval(ops.Program, ep4)
	require.Error(t, err)
	require.Contains(t, err.Error(), "dynamic cost")
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
	for v := uint64(1); v <= AssemblerMaxVersion; v++ {
		t.Run(fmt.Sprintf("v=%d", v), func(t *testing.T) {
			ops, err := AssembleStringWithVersion(`int 1`, v)
			ops.Program = append(ops.Program, 0x08) // +
			require.NoError(t, err)
			err = Check(ops.Program, defaultEvalParams(nil, nil))
			require.NoError(t, err)
			sb := strings.Builder{}
			pass, err := Eval(ops.Program, defaultEvalParams(&sb, nil))
			if pass {
				t.Log(hex.EncodeToString(ops.Program))
				t.Log(sb.String())
			}
			require.False(t, pass)
			isNotPanic(t, err)
		})
	}
}

func TestWrongStackTypeRuntime(t *testing.T) {
	t.Parallel()
	for v := uint64(1); v <= AssemblerMaxVersion; v++ {
		t.Run(fmt.Sprintf("v=%d", v), func(t *testing.T) {
			ops, err := AssembleStringWithVersion(`int 1`, v)
			require.NoError(t, err)
			ops.Program = append(ops.Program, 0x01, 0x15) // sha256, len
			err = Check(ops.Program, defaultEvalParams(nil, nil))
			require.NoError(t, err)
			sb := strings.Builder{}
			pass, err := Eval(ops.Program, defaultEvalParams(&sb, nil))
			if pass {
				t.Log(hex.EncodeToString(ops.Program))
				t.Log(sb.String())
			}
			require.False(t, pass)
			isNotPanic(t, err)
		})
	}
}

func TestEqMismatch(t *testing.T) {
	t.Parallel()
	for v := uint64(1); v <= AssemblerMaxVersion; v++ {
		t.Run(fmt.Sprintf("v=%d", v), func(t *testing.T) {
			ops, err := AssembleStringWithVersion(`byte 0x1234
int 1`, v)
			require.NoError(t, err)
			ops.Program = append(ops.Program, 0x12) // ==
			err = Check(ops.Program, defaultEvalParams(nil, nil))
			require.NoError(t, err) // TODO: Check should know the type stack was wrong
			sb := strings.Builder{}
			pass, err := Eval(ops.Program, defaultEvalParams(&sb, nil))
			if pass {
				t.Log(hex.EncodeToString(ops.Program))
				t.Log(sb.String())
			}
			require.False(t, pass)
			isNotPanic(t, err)
		})
	}
}

func TestNeqMismatch(t *testing.T) {
	t.Parallel()
	for v := uint64(1); v <= AssemblerMaxVersion; v++ {
		t.Run(fmt.Sprintf("v=%d", v), func(t *testing.T) {
			ops, err := AssembleStringWithVersion(`byte 0x1234
int 1`, v)
			require.NoError(t, err)
			ops.Program = append(ops.Program, 0x13) // !=
			err = Check(ops.Program, defaultEvalParams(nil, nil))
			require.NoError(t, err) // TODO: Check should know the type stack was wrong
			sb := strings.Builder{}
			pass, err := Eval(ops.Program, defaultEvalParams(&sb, nil))
			if pass {
				t.Log(hex.EncodeToString(ops.Program))
				t.Log(sb.String())
			}
			require.False(t, pass)
			isNotPanic(t, err)
		})
	}
}

func TestWrongStackTypeRuntime2(t *testing.T) {
	t.Parallel()
	for v := uint64(1); v <= AssemblerMaxVersion; v++ {
		t.Run(fmt.Sprintf("v=%d", v), func(t *testing.T) {
			ops, err := AssembleStringWithVersion(`byte 0x1234
int 1`, v)
			require.NoError(t, err)
			ops.Program = append(ops.Program, 0x08) // +
			err = Check(ops.Program, defaultEvalParams(nil, nil))
			require.NoError(t, err)
			sb := strings.Builder{}
			pass, _ := Eval(ops.Program, defaultEvalParams(&sb, nil))
			if pass {
				t.Log(hex.EncodeToString(ops.Program))
				t.Log(sb.String())
			}
			require.False(t, pass)
			isNotPanic(t, err)
		})
	}
}

func TestIllegalOp(t *testing.T) {
	t.Parallel()
	for v := uint64(1); v <= AssemblerMaxVersion; v++ {
		t.Run(fmt.Sprintf("v=%d", v), func(t *testing.T) {
			ops, err := AssembleStringWithVersion(`int 1`, v)
			require.NoError(t, err)
			for opcode, spec := range opsByOpcode[v] {
				if spec.op == nil {
					ops.Program = append(ops.Program, byte(opcode))
					break
				}
			}
			err = Check(ops.Program, defaultEvalParams(nil, nil))
			require.Error(t, err)
			sb := strings.Builder{}
			pass, err := Eval(ops.Program, defaultEvalParams(&sb, nil))
			if pass {
				t.Log(hex.EncodeToString(ops.Program))
				t.Log(sb.String())
			}
			require.False(t, pass)
			isNotPanic(t, err)
		})
	}
}

func TestShortProgram(t *testing.T) {
	t.Parallel()
	for v := uint64(1); v <= AssemblerMaxVersion; v++ {
		t.Run(fmt.Sprintf("v=%d", v), func(t *testing.T) {
			ops, err := AssembleStringWithVersion(`int 1
bnz done
done:
int 1
`, v)
			require.NoError(t, err)
			// cut two last bytes - intc_1 and last byte of bnz
			ops.Program = ops.Program[:len(ops.Program)-2]
			err = Check(ops.Program, defaultEvalParams(nil, nil))
			require.Error(t, err)
			sb := strings.Builder{}
			pass, err := Eval(ops.Program, defaultEvalParams(&sb, nil))
			if pass {
				t.Log(hex.EncodeToString(ops.Program))
				t.Log(sb.String())
			}
			require.False(t, pass)
			isNotPanic(t, err)
		})
	}
}

func TestShortProgramTrue(t *testing.T) {
	t.Parallel()
	ops := testProg(t, `intcblock 1
intc 0
intc 0
bnz done
done:`, 2)
	err := Check(ops.Program, defaultEvalParams(nil, nil))
	require.NoError(t, err)
	sb := strings.Builder{}
	pass, err := Eval(ops.Program, defaultEvalParams(&sb, nil))
	require.NoError(t, err)
	require.True(t, pass)
}
func TestShortBytecblock(t *testing.T) {
	t.Parallel()
	for v := uint64(1); v <= AssemblerMaxVersion; v++ {
		t.Run(fmt.Sprintf("v=%d", v), func(t *testing.T) {
			fullops, err := AssembleStringWithVersion(`bytecblock 0x123456 0xababcdcd "test"`, v)
			require.NoError(t, err)
			fullops.Program[2] = 50 // fake 50 elements
			for i := 2; i < len(fullops.Program); i++ {
				program := fullops.Program[:i]
				t.Run(hex.EncodeToString(program), func(t *testing.T) {
					err := Check(program, defaultEvalParams(nil, nil))
					require.Error(t, err)
					isNotPanic(t, err)
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
		})
	}
}

func TestShortBytecblock2(t *testing.T) {
	t.Parallel()
	sources := []string{
		"02260180fe83f88fe0bf80ff01aa",
		"01260180fe83f88fe0bf80ff01aa",
		"0026efbfbdefbfbd02",
		"0026efbfbdefbfbd30",
	}
	for _, src := range sources {
		t.Run(src, func(t *testing.T) {
			program, err := hex.DecodeString(src)
			require.NoError(t, err)
			err = Check(program, defaultEvalParams(nil, nil))
			require.Error(t, err)
			isNotPanic(t, err)
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
func checkPanic(cx *evalContext) error {
	panic(panicString)
}

func TestPanic(t *testing.T) {
	log := logging.TestingLog(t)
	for v := uint64(1); v <= AssemblerMaxVersion; v++ {
		t.Run(fmt.Sprintf("v=%d", v), func(t *testing.T) {
			ops, err := AssembleStringWithVersion(`int 1`, v)
			require.NoError(t, err)
			var hackedOpcode int
			var oldSpec OpSpec
			for opcode, spec := range opsByOpcode[v] {
				if spec.op == nil {
					hackedOpcode = opcode
					oldSpec = spec
					opsByOpcode[v][opcode].op = opPanic
					opsByOpcode[v][opcode].Modes = modeAny
					opsByOpcode[v][opcode].Details.checkFunc = checkPanic
					ops.Program = append(ops.Program, byte(opcode))
					break
				}
			}
			sb := strings.Builder{}
			params := defaultEvalParams(&sb, nil)
			params.Logger = log
			err = Check(ops.Program, params)
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
			txn.Lsig.Logic = ops.Program
			params = defaultEvalParams(&sb, &txn)
			params.Logger = log
			pass, err := Eval(ops.Program, params)
			if pass {
				t.Log(hex.EncodeToString(ops.Program))
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
			opsByOpcode[v][hackedOpcode] = oldSpec
		})
	}
}

func TestProgramTooNew(t *testing.T) {
	t.Parallel()
	var program [12]byte
	vlen := binary.PutUvarint(program[:], EvalMaxVersion+1)
	err := Check(program[:vlen], defaultEvalParams(nil, nil))
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
	err = Check(program, defaultEvalParams(nil, nil))
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
	ep := EvalParams{}
	ep.Proto = &proto
	err := Check(program[:vlen], ep)
	require.Error(t, err)
	ep.Txn = &transactions.SignedTxn{}
	pass, err := Eval(program[:vlen], ep)
	require.Error(t, err)
	require.False(t, pass)
	isNotPanic(t, err)
}

func TestMisalignedBranch(t *testing.T) {
	t.Parallel()
	for v := uint64(1); v <= AssemblerMaxVersion; v++ {
		t.Run(fmt.Sprintf("v=%d", v), func(t *testing.T) {
			ops, err := AssembleStringWithVersion(`int 1
bnz done
bytecblock 0x01234576 0xababcdcd 0xf000baad
done:
int 1`, v)
			require.NoError(t, err)
			//t.Log(hex.EncodeToString(program))
			canonicalProgramString := mutateProgVersion(v, "01200101224000112603040123457604ababcdcd04f000baad22")
			canonicalProgramBytes, err := hex.DecodeString(canonicalProgramString)
			require.NoError(t, err)
			require.Equal(t, ops.Program, canonicalProgramBytes)
			ops.Program[7] = 3 // clobber the branch offset to be in the middle of the bytecblock
			err = Check(ops.Program, defaultEvalParams(nil, nil))
			require.Error(t, err)
			require.Contains(t, err.Error(), "aligned")
			pass, err := Eval(ops.Program, defaultEvalParams(nil, nil))
			require.Error(t, err)
			require.False(t, pass)
			isNotPanic(t, err)

			// back branches are checked differently, so test misaligned back branch
			ops.Program[6] = 0xff // Clobber the two bytes of offset with 0xff 0xff = -1
			ops.Program[7] = 0xff // That jumps into the offset itself (pc + 3 -1)
			err = Check(ops.Program, defaultEvalParams(nil, nil))
			require.Error(t, err)
			if v < backBranchEnabledVersion {
				require.Contains(t, err.Error(), "negative branch")
			} else {
				require.Contains(t, err.Error(), "back branch")
				require.Contains(t, err.Error(), "aligned")
			}
			pass, err = Eval(ops.Program, defaultEvalParams(nil, nil))
			require.Error(t, err)
			require.False(t, pass)
			isNotPanic(t, err)
		})
	}
}

func TestBranchTooFar(t *testing.T) {
	t.Parallel()
	for v := uint64(1); v <= AssemblerMaxVersion; v++ {
		t.Run(fmt.Sprintf("v=%d", v), func(t *testing.T) {
			ops, err := AssembleStringWithVersion(`int 1
bnz done
bytecblock 0x01234576 0xababcdcd 0xf000baad
done:
int 1`, v)
			require.NoError(t, err)
			//t.Log(hex.EncodeToString(ops.Program))
			canonicalProgramString := mutateProgVersion(v, "01200101224000112603040123457604ababcdcd04f000baad22")
			canonicalProgramBytes, err := hex.DecodeString(canonicalProgramString)
			require.NoError(t, err)
			require.Equal(t, ops.Program, canonicalProgramBytes)
			ops.Program[7] = 200 // clobber the branch offset to be beyond the end of the program
			err = Check(ops.Program, defaultEvalParams(nil, nil))
			require.Error(t, err)
			require.True(t, strings.Contains(err.Error(), "beyond end of program"))
			pass, err := Eval(ops.Program, defaultEvalParams(nil, nil))
			require.Error(t, err)
			require.False(t, pass)
			isNotPanic(t, err)
		})
	}
}

func TestBranchTooLarge(t *testing.T) {
	t.Parallel()
	for v := uint64(1); v <= AssemblerMaxVersion; v++ {
		t.Run(fmt.Sprintf("v=%d", v), func(t *testing.T) {
			ops, err := AssembleStringWithVersion(`int 1
bnz done
bytecblock 0x01234576 0xababcdcd 0xf000baad
done:
int 1`, v)
			require.NoError(t, err)
			//t.Log(hex.EncodeToString(ops.Program))
			// (br)anch byte, (hi)gh byte of offset,  (lo)w byte:     brhilo
			canonicalProgramString := mutateProgVersion(v, "01200101224000112603040123457604ababcdcd04f000baad22")
			canonicalProgramBytes, err := hex.DecodeString(canonicalProgramString)
			require.NoError(t, err)
			require.Equal(t, ops.Program, canonicalProgramBytes)
			ops.Program[6] = 0x70 // clobber hi byte of branch offset
			err = Check(ops.Program, defaultEvalParams(nil, nil))
			require.Error(t, err)
			require.Contains(t, err.Error(), "beyond")
			pass, err := Eval(ops.Program, defaultEvalParams(nil, nil))
			require.Error(t, err)
			require.Contains(t, err.Error(), "beyond")
			require.False(t, pass)
			isNotPanic(t, err)
		})
	}
	branches := []string{
		"bz done",
		"b done",
	}
	template := `int 0
%s
done:
int 1
`
	ep := defaultEvalParams(nil, nil)
	for _, line := range branches {
		t.Run(fmt.Sprintf("branch=%s", line), func(t *testing.T) {
			source := fmt.Sprintf(template, line)
			ops, err := AssembleStringWithVersion(source, AssemblerMaxVersion)
			require.NoError(t, err)
			ops.Program[7] = 0xf0 // clobber the branch offset - highly negative
			ops.Program[8] = 0xff // clobber the branch offset
			err = Check(ops.Program, ep)
			require.Error(t, err)
			require.Contains(t, err.Error(), "beyond")
			pass, err := Eval(ops.Program, ep)
			require.Error(t, err)
			require.Contains(t, err.Error(), "beyond")
			require.False(t, pass)
		})
	}
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
	ops, err := AssembleStringWithVersion(source, AssemblerMaxVersion)
	require.NoError(b, err)
	err = Check(ops.Program, defaultEvalParams(nil, nil))
	require.NoError(b, err)
	//b.Logf("%d bytes of program", len(ops.Program))
	//b.Log(hex.EncodeToString(ops.Program))
	b.ResetTimer()
	sb := strings.Builder{} // Trace: &sb
	for i := 0; i < b.N; i++ {
		pass, err := Eval(ops.Program, defaultEvalParams(nil, nil))
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
	ops, err := AssembleStringWithVersion(source, AssemblerMaxVersion)
	require.NoError(b, err)
	ep := defaultEvalParams(nil, nil)
	err = Check(ops.Program, ep)
	require.Error(b, err) // excessive cost
	//b.Logf("%d bytes of program", len(ops.Program))
	//b.Log(hex.EncodeToString(ops.Program))
	b.ResetTimer()
	sb := strings.Builder{} // Trace: &sb
	for i := 0; i < b.N; i++ {
		pass, err := Eval(ops.Program, defaultEvalParams(&sb, nil))
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
		{"add long stack", addBenchmarkSource},
		{"add small stack", addBenchmark2Source},
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

	for v := uint64(1); v <= AssemblerMaxVersion; v++ {
		t.Run(fmt.Sprintf("v=%d", v), func(t *testing.T) {
			ops, err := AssembleStringWithVersion(fmt.Sprintf(`arg 0
arg 1
addr %s
ed25519verify`, pkStr), v)
			require.NoError(t, err)
			sig := c.Sign(Msg{
				ProgramHash: crypto.HashObj(Program(ops.Program)),
				Data:        data[:],
			})
			var txn transactions.SignedTxn
			txn.Lsig.Logic = ops.Program
			txn.Lsig.Args = [][]byte{data[:], sig[:]}
			sb := strings.Builder{}
			pass, err := Eval(ops.Program, defaultEvalParams(&sb, &txn))
			if !pass {
				t.Log(hex.EncodeToString(ops.Program))
				t.Log(sb.String())
			}
			require.True(t, pass)
			require.NoError(t, err)

			// short sig will fail
			txn.Lsig.Args[1] = sig[1:]
			pass, err = Eval(ops.Program, defaultEvalParams(nil, &txn))
			require.False(t, pass)
			require.Error(t, err)
			isNotPanic(t, err)

			// flip a bit and it should not pass
			msg1 := "52fdfc072182654f163f5f0f9a621d729566c74d0aa413bf009c9800418c19cd"
			data1, err := hex.DecodeString(msg1)
			require.NoError(t, err)
			txn.Lsig.Args = [][]byte{data1, sig[:]}
			sb1 := strings.Builder{}
			pass1, err := Eval(ops.Program, defaultEvalParams(&sb1, &txn))
			require.False(t, pass1)
			require.NoError(t, err)
			isNotPanic(t, err)
		})
	}
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
		ops, err := AssembleStringWithVersion(fmt.Sprintf(`arg 0
arg 1
addr %s
ed25519verify`, pkStr), AssemblerMaxVersion)
		require.NoError(b, err)
		programs = append(programs, ops.Program)
		sig := secret.SignBytes(buffer[:])
		signatures = append(signatures, sig)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		var txn transactions.SignedTxn
		txn.Lsig.Logic = programs[i]
		txn.Lsig.Args = [][]byte{data[i][:], signatures[i][:]}
		sb := strings.Builder{}
		ep := defaultEvalParams(&sb, &txn)
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
		testTxnProgramTextV3,
		testCompareProgramText,
		addBenchmarkSource,
		addBenchmark2Source,
	}

	programs := make([]*OpStream, len(sourcePrograms))
	var err error
	for i, text := range sourcePrograms {
		programs[i], err = AssembleStringWithVersion(text, AssemblerMaxVersion)
		require.NoError(b, err)
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		for _, program := range programs {
			err = Check(program.Program, defaultEvalParams(nil, nil))
			if err != nil {
				require.NoError(b, err)
			}
		}
	}
}

func TestStackValues(t *testing.T) {
	t.Parallel()

	actual := oneInt.plus(oneInt)
	require.Equal(t, twoInts, actual)

	actual = oneInt.plus(oneAny)
	require.Equal(t, StackTypes{StackUint64, StackAny}, actual)

	actual = twoInts.plus(oneBytes)
	require.Equal(t, StackTypes{StackUint64, StackUint64, StackBytes}, actual)

	actual = oneInt.plus(oneBytes).plus(oneAny)
	require.Equal(t, StackTypes{StackUint64, StackBytes, StackAny}, actual)
}

func TestEvalVersions(t *testing.T) {
	t.Parallel()

	text := `int 1
txna ApplicationArgs 0
pop
`
	ops, err := AssembleStringWithVersion(text, AssemblerMaxVersion)
	require.NoError(t, err)

	ep := defaultEvalParams(nil, nil)
	ep.Txn = &transactions.SignedTxn{}
	ep.Txn.Txn.ApplicationArgs = [][]byte{[]byte("test")}
	_, err = Eval(ops.Program, ep)
	require.NoError(t, err)

	ep = defaultEvalParamsV1(nil, nil)
	_, err = Eval(ops.Program, ep)
	require.Error(t, err)
	require.Contains(t, err.Error(), "greater than protocol supported version 1")

	// hack the version and fail on illegal opcode
	ops.Program[0] = 0x1
	ep = defaultEvalParamsV1(nil, nil)
	_, err = Eval(ops.Program, ep)
	require.Error(t, err)
	require.Contains(t, err.Error(), "illegal opcode 0x36") // txna
}

func TestStepErrors(t *testing.T) {
	// This test modifies opsByName table, do not run in parallel

	source := `intcblock 0
intc_0
intc_0
+
`
	ops, err := AssembleStringWithVersion(source, AssemblerMaxVersion)
	require.NoError(t, err)

	ep := defaultEvalParams(nil, nil)

	origSpec := OpsByName[LogicVersion]["+"]
	spec := origSpec
	defer func() {
		// restore, opsByOpcode is global
		opsByOpcode[LogicVersion][spec.Opcode] = origSpec
	}()

	spec.op = func(cx *evalContext) {
		// overflow
		cx.stack = make([]stackValue, 2000)
	}
	opsByOpcode[LogicVersion][spec.Opcode] = spec
	_, err = Eval(ops.Program, ep)
	require.Error(t, err)
	require.Contains(t, err.Error(), "stack overflow")
}

func TestDup(t *testing.T) {
	t.Parallel()

	text := `int 1
dup
==
bnz dup_ok
err
dup_ok:
int 1
int 2
dup2 // expected 1, 2, 1, 2
int 2
==
bz error
int 1
==
bz error
int 2
==
bz error
int 1
==
bz error
b exit
error:
err
exit:
int 1
`
	ep := defaultEvalParams(nil, nil)

	ops := testProg(t, text, AssemblerMaxVersion)
	pass, err := Eval(ops.Program, ep)
	require.NoError(t, err)
	require.True(t, pass)

	text = `int 1; int 2; dup2; pop; pop; pop`
	ops = testProg(t, text, AssemblerMaxVersion)
	pass, err = Eval(ops.Program, ep)
	require.NoError(t, err)
	require.True(t, pass)

	text = `int 1; int 2; dup2; pop; pop`
	ops = testProg(t, text, AssemblerMaxVersion)
	pass, err = Eval(ops.Program, ep)
	require.Error(t, err)
	require.False(t, pass)
}

func TestStringLiteral(t *testing.T) {
	t.Parallel()

	text := `byte "foo bar"
byte b64(Zm9vIGJhcg==)
==
`
	ep := defaultEvalParams(nil, nil)

	ops, err := AssembleStringWithVersion(text, AssemblerMaxVersion)
	require.NoError(t, err)
	pass, err := Eval(ops.Program, ep)
	require.NoError(t, err)
	require.True(t, pass)

	text = `byte "foo bar // not a comment"
byte b64(Zm9vIGJhciAvLyBub3QgYSBjb21tZW50)
==
`
	ops, err = AssembleStringWithVersion(text, AssemblerMaxVersion)
	require.NoError(t, err)
	pass, err = Eval(ops.Program, ep)
	require.NoError(t, err)
	require.True(t, pass)

	text = `byte ""
byte 0x
==
`
	ops, err = AssembleStringWithVersion(text, AssemblerMaxVersion)
	require.NoError(t, err)
	pass, err = Eval(ops.Program, ep)
	require.NoError(t, err)
	require.True(t, pass)

	text = `byte "" // empty string literal
byte 0x // empty byte constant
==
`
	ops, err = AssembleStringWithVersion(text, AssemblerMaxVersion)
	require.NoError(t, err)
	pass, err = Eval(ops.Program, ep)
	require.NoError(t, err)
	require.True(t, pass)
}

func TestArgType(t *testing.T) {
	t.Parallel()

	var sv stackValue
	require.Equal(t, StackUint64, sv.argType())
	sv.Bytes = []byte("")
	require.Equal(t, StackBytes, sv.argType())
	sv.Uint = 1
	require.Equal(t, StackBytes, sv.argType())
	sv.Bytes = nil
	require.Equal(t, StackUint64, sv.argType())
}

func TestApplicationsDisallowOldTeal(t *testing.T) {
	const source = "int 1"
	ep := defaultEvalParams(nil, nil)

	txn := makeSampleTxn()
	txn.Txn.Type = protocol.ApplicationCallTx
	txn.Txn.RekeyTo = basics.Address{}
	txngroup := []transactions.SignedTxn{txn}
	ep.TxnGroup = txngroup

	for v := uint64(0); v < appsEnabledVersion; v++ {
		ops, err := AssembleStringWithVersion(source, v)
		require.NoError(t, err)

		err = CheckStateful(ops.Program, ep)
		require.Error(t, err)
		require.Contains(t, err.Error(), fmt.Sprintf("program version must be >= %d", appsEnabledVersion))

		_, err = EvalStateful(ops.Program, ep)
		require.Error(t, err)
		require.Contains(t, err.Error(), fmt.Sprintf("program version must be >= %d", appsEnabledVersion))
	}

	ops, err := AssembleStringWithVersion(source, appsEnabledVersion)
	require.NoError(t, err)

	err = CheckStateful(ops.Program, ep)
	require.NoError(t, err)

	_, err = EvalStateful(ops.Program, ep)
	require.NoError(t, err)
}

func TestAnyRekeyToOrApplicationRaisesMinTealVersion(t *testing.T) {
	const source = "int 1"

	// Construct a group of two payments, no rekeying
	txn0 := makeSampleTxn()
	txn0.Txn.Type = protocol.PaymentTx
	txn0.Txn.RekeyTo = basics.Address{}
	txn1 := txn0
	txngroup0 := []transactions.SignedTxn{txn0, txn1}

	// Construct a group of one payment, one ApplicationCall, no rekeying
	txn2 := makeSampleTxn()
	txn2.Txn.Type = protocol.PaymentTx
	txn2.Txn.RekeyTo = basics.Address{}
	txn3 := txn2
	txn3.Txn.Type = protocol.ApplicationCallTx
	txngroup1 := []transactions.SignedTxn{txn2, txn3}

	// Construct a group of one payment, one rekeying payment
	txn4 := makeSampleTxn()
	txn4.Txn.Type = protocol.PaymentTx
	txn5 := txn4
	txn4.Txn.RekeyTo = basics.Address{}
	txn5.Txn.RekeyTo = basics.Address{1}
	txngroup2 := []transactions.SignedTxn{txn4, txn5}

	type testcase struct {
		group            []transactions.SignedTxn
		validFromVersion uint64
	}

	cases := []testcase{
		{txngroup0, 0},
		{txngroup1, appsEnabledVersion},
		{txngroup2, rekeyingEnabledVersion},
	}

	for ci, cse := range cases {
		t.Run(fmt.Sprintf("ci=%d", ci), func(t *testing.T) {
			ep := defaultEvalParams(nil, nil)
			ep.TxnGroup = cse.group
			ep.Txn = &cse.group[0]

			// Computed MinTealVersion should be == validFromVersion
			calc := ComputeMinTealVersion(cse.group)
			require.Equal(t, calc, cse.validFromVersion)

			// Should fail for all versions < validFromVersion
			expected := fmt.Sprintf("program version must be >= %d", cse.validFromVersion)
			for v := uint64(0); v < cse.validFromVersion; v++ {
				ops, err := AssembleStringWithVersion(source, v)
				require.NoError(t, err)

				err = CheckStateful(ops.Program, ep)
				require.Error(t, err)
				require.Contains(t, err.Error(), expected)

				_, err = EvalStateful(ops.Program, ep)
				require.Error(t, err)
				require.Contains(t, err.Error(), expected)

				err = Check(ops.Program, ep)
				require.Error(t, err)
				require.Contains(t, err.Error(), expected)

				_, err = Eval(ops.Program, ep)
				require.Error(t, err)
				require.Contains(t, err.Error(), expected)
			}

			// Should succeed for all versions >= validFromVersion
			for v := cse.validFromVersion; v <= AssemblerMaxVersion; v++ {
				ops, err := AssembleStringWithVersion(source, v)
				require.NoError(t, err)

				err = CheckStateful(ops.Program, ep)
				require.NoError(t, err)

				_, err = EvalStateful(ops.Program, ep)
				require.NoError(t, err)

				err = Check(ops.Program, ep)
				require.NoError(t, err)

				_, err = Eval(ops.Program, ep)
				require.NoError(t, err)
			}
		})
	}
}

// check all v2 opcodes: allowed in v2 and not allowed in v1 and v0
func TestAllowedOpcodesV2(t *testing.T) {
	t.Parallel()

	tests := map[string]string{
		"txna":              "txna Accounts 0",
		"gtxna":             "gtxna 0 ApplicationArgs 0",
		"bz":                "int 0; bz l; l:",
		"b":                 "b l; l:",
		"return":            "int 1; return",
		"addw":              "int 0; int 1; addw",
		"dup2":              "int 1; int 2; dup2",
		"concat":            "byte 0x41; dup; concat",
		"substring":         "byte 0x41; substring 0 1",
		"substring3":        "byte 0x41; dup; dup; substring3",
		"balance":           "int 1; balance",
		"app_opted_in":      "int 0; dup; app_opted_in",
		"app_local_get":     "int 0; byte 0x41; app_local_get",
		"app_local_get_ex":  "int 0; dup; byte 0x41; app_local_get_ex",
		"app_global_get":    "int 0; byte 0x41; app_global_get",
		"app_global_get_ex": "int 0; byte 0x41; app_global_get_ex",
		"app_local_put":     "int 0; dup; byte 0x41; app_local_put",
		"app_global_put":    "byte 0x41; dup; app_global_put",
		"app_local_del":     "int 0; byte 0x41; app_local_del",
		"app_global_del":    "byte 0x41; app_global_del",
		"asset_holding_get": "int 1; int 1; asset_holding_get AssetBalance",
		"asset_params_get":  "int 1; asset_params_get AssetTotal",
	}

	excluded := map[string]bool{
		"sha256":     true,
		"keccak256":  true,
		"sha512_256": true,
		"txn":        true,
		"gtxn":       true,
	}

	ep := defaultEvalParams(nil, nil)

	cnt := 0
	for _, spec := range OpSpecs {
		if spec.Version == 2 && !excluded[spec.Name] {
			source, ok := tests[spec.Name]
			require.True(t, ok, "Missed opcode in the test: %s", spec.Name)
			require.Contains(t, source, spec.Name)
			ops := testProg(t, source, AssemblerMaxVersion)
			// all opcodes allowed in stateful mode so use CheckStateful/EvalStateful
			err := CheckStateful(ops.Program, ep)
			require.NoError(t, err, source)
			_, err = EvalStateful(ops.Program, ep)
			if spec.Name != "return" {
				// "return" opcode always succeeds so ignore it
				require.Error(t, err, source)
				require.NotContains(t, err.Error(), "illegal opcode")
			}

			for v := byte(0); v <= 1; v++ {
				ops.Program[0] = v
				err = Check(ops.Program, ep)
				require.Error(t, err, source)
				require.Contains(t, err.Error(), "illegal opcode")
				err = CheckStateful(ops.Program, ep)
				require.Error(t, err, source)
				require.Contains(t, err.Error(), "illegal opcode")
				_, err = Eval(ops.Program, ep)
				require.Error(t, err, source)
				require.Contains(t, err.Error(), "illegal opcode")
				_, err = EvalStateful(ops.Program, ep)
				require.Error(t, err, source)
				require.Contains(t, err.Error(), "illegal opcode")
			}
			cnt++
		}
	}
	require.Equal(t, len(tests), cnt)
}

// check all v3 opcodes: allowed in v3 and not allowed before
func TestAllowedOpcodesV3(t *testing.T) {
	t.Parallel()

	// all tests are expected to fail in evaluation
	tests := map[string]string{
		"assert":      "int 1; assert",
		"min_balance": "int 1; min_balance",
		"getbit":      "int 15; int 64; getbit",
		"setbit":      "int 15; int 64; int 0; setbit",
		"getbyte":     "byte \"john\"; int 5; getbyte",
		"setbyte":     "byte \"john\"; int 5; int 66; setbyte",
		"swap":        "int 1; byte \"x\"; swap",
		"select":      "int 1; byte \"x\"; int 1; select",
		"dig":         "int 1; int 1; dig 1",
		"gtxns":       "int 0; gtxns FirstValid",
		"gtxnsa":      "int 0; gtxnsa Accounts 0",
		"pushint":     "pushint 7; pushint 4",
		"pushbytes":   `pushbytes "stringsfail?"`,
	}

	excluded := map[string]bool{}

	ep := defaultEvalParams(nil, nil)

	cnt := 0
	for _, spec := range OpSpecs {
		if spec.Version == 3 && !excluded[spec.Name] {
			source, ok := tests[spec.Name]
			require.True(t, ok, "Missed opcode in the test: %s", spec.Name)
			require.Contains(t, source, spec.Name)
			ops := testProg(t, source, AssemblerMaxVersion)
			// all opcodes allowed in stateful mode so use CheckStateful/EvalStateful
			err := CheckStateful(ops.Program, ep)
			require.NoError(t, err, source)
			_, err = EvalStateful(ops.Program, ep)
			require.Error(t, err, source)
			require.NotContains(t, err.Error(), "illegal opcode")

			for v := byte(0); v <= 1; v++ {
				ops.Program[0] = v
				err = Check(ops.Program, ep)
				require.Error(t, err, source)
				require.Contains(t, err.Error(), "illegal opcode")
				err = CheckStateful(ops.Program, ep)
				require.Error(t, err, source)
				require.Contains(t, err.Error(), "illegal opcode")
				_, err = Eval(ops.Program, ep)
				require.Error(t, err, source)
				require.Contains(t, err.Error(), "illegal opcode")
				_, err = EvalStateful(ops.Program, ep)
				require.Error(t, err, source)
				require.Contains(t, err.Error(), "illegal opcode")
			}
			cnt++
		}
	}
	require.Equal(t, len(tests), cnt)
}

func TestRekeyFailsOnOldVersion(t *testing.T) {
	t.Parallel()
	for v := uint64(0); v < rekeyingEnabledVersion; v++ {
		t.Run(fmt.Sprintf("v=%d", v), func(t *testing.T) {
			ops, err := AssembleStringWithVersion(`int 1`, v)
			require.NoError(t, err)
			var txn transactions.SignedTxn
			txn.Lsig.Logic = ops.Program
			txn.Txn.RekeyTo = basics.Address{1, 2, 3, 4}
			sb := strings.Builder{}
			proto := defaultEvalProto()
			ep := defaultEvalParams(&sb, &txn)
			ep.TxnGroup = []transactions.SignedTxn{txn}
			ep.Proto = &proto
			err = Check(ops.Program, ep)
			require.Error(t, err)
			require.Contains(t, err.Error(), fmt.Sprintf("program version must be >= %d", rekeyingEnabledVersion))
			pass, err := Eval(ops.Program, ep)
			require.Error(t, err)
			require.Contains(t, err.Error(), fmt.Sprintf("program version must be >= %d", rekeyingEnabledVersion))
			require.False(t, pass)
		})
	}
}

func obfuscate(program string) string {
	// Put a prefix on the program that does nothing interesting,
	// but prevents assembly from detecting type errors.  Allows
	// evaluation testing of a program that would be rejected by
	// assembler.
	if strings.Contains(program, "obfuscate") {
		return program // Already done.  Tests sometimes use at multiple levels
	}
	return "int 0;bnz obfuscate;obfuscate:;" + program
}

type evalTester func(pass bool, err error) bool

func testEvaluation(t *testing.T, program string, introduced uint64, tester evalTester) {
	for v := uint64(1); v <= AssemblerMaxVersion; v++ {
		t.Run(fmt.Sprintf("v=%d", v), func(t *testing.T) {
			if v < introduced {
				testProg(t, obfuscate(program), v, expect{0, "...was introduced..."})
				return
			}
			ops := testProg(t, program, v)
			// Programs created with a previous assembler
			// should still operate properly with future
			// EvalParams, so try all forward versions.
			for lv := v; lv <= AssemblerMaxVersion; lv++ {
				t.Run(fmt.Sprintf("lv=%d", lv), func(t *testing.T) {
					sb := strings.Builder{}
					err := Check(ops.Program, defaultEvalParamsWithVersion(&sb, nil, lv))
					if err != nil {
						t.Log(hex.EncodeToString(ops.Program))
						t.Log(sb.String())
					}
					require.NoError(t, err)
					var txn transactions.SignedTxn
					txn.Lsig.Logic = ops.Program
					sb = strings.Builder{}
					pass, err := Eval(ops.Program, defaultEvalParamsWithVersion(&sb, &txn, lv))
					ok := tester(pass, err)
					if !ok {
						t.Log(hex.EncodeToString(ops.Program))
						t.Log(sb.String())
						t.Log(err)
					}
					require.True(t, ok)
					isNotPanic(t, err) // Never want a Go level panic.
				})
			}
		})
	}
}

func testAccepts(t *testing.T, program string, introduced uint64) {
	testEvaluation(t, program, introduced, func(pass bool, err error) bool {
		return pass && err == nil
	})
}
func testRejects(t *testing.T, program string, introduced uint64) {
	testEvaluation(t, program, introduced, func(pass bool, err error) bool {
		// Returned False, but didn't panic
		return !pass && err == nil
	})
}
func testPanics(t *testing.T, program string, introduced uint64) {
	testEvaluation(t, program, introduced, func(pass bool, err error) bool {
		// TEAL panic! not just reject at exit
		return !pass && err != nil
	})
}

func TestAssert(t *testing.T) {
	t.Parallel()
	testAccepts(t, "int 1;assert;int 1", 3)
	testRejects(t, "int 1;assert;int 0", 3)
	testPanics(t, "int 0;assert;int 1", 3)
	testPanics(t, obfuscate("assert;int 1"), 3)
	testPanics(t, obfuscate(`byte "john";assert;int 1`), 3)
}

func TestBits(t *testing.T) {
	t.Parallel()
	testAccepts(t, "int 1; int 0; getbit; int 1; ==", 3)
	testAccepts(t, "int 1; int 1; getbit; int 0; ==", 3)

	testAccepts(t, "int 1; int 63; getbit; int 0; ==", 3)
	testPanics(t, "int 1; int 64; getbit; int 0; ==", 3)

	testAccepts(t, "int 0; int 3; int 1; setbit; int 8; ==", 3)
	testAccepts(t, "int 8; int 3; getbit; int 1; ==", 3)

	testAccepts(t, "int 15; int 3; int 0; setbit; int 7; ==", 3)

	// bit 10 is the 3rd bit (from the high end) in the second byte
	testAccepts(t, "byte 0xfff0; int 10; getbit; int 1; ==", 3)
	testAccepts(t, "byte 0xfff0; int 12; getbit; int 0; ==", 3)
	testPanics(t, "byte 0xfff0; int 16; getbit; int 0; ==", 3)

	testAccepts(t, "byte 0xfffff0; int 21; int 1; setbit; byte 0xfffff4; ==", 3)
	testAccepts(t, "byte 0xfffff4; int 1; int 0; setbit; byte 0xbffff4; ==", 3)
	testPanics(t, "byte 0xfffff4; int 24; int 0; setbit; byte 0xbf; ==", 3)

	testAccepts(t, "byte 0x0000; int 3; int 1; setbit; byte 0x1000; ==", 3)
	testAccepts(t, "byte 0x0000; int 15; int 1; setbit; byte 0x0001; ==", 3)
	testAccepts(t, "int 0x0000; int 3; int 1; setbit; int 0x0008; ==", 3)
	testAccepts(t, "int 0x0000; int 12; int 1; setbit; int 0x1000; ==", 3)

	// These test that setbyte is not modifying a shared value.
	// Since neither bytec nor dup copies, the first test is
	// insufficient, the setbit changes the original constant (if
	// it fails to copy).
	testAccepts(t, "byte 0xfffff0; dup; int 21; int 1; setbit; byte 0xfffff4; ==; pop; byte 0xfffff0; ==", 3)
	testAccepts(t, "byte 0xffff; byte 0xf0; concat; dup; int 21; int 1; setbit; byte 0xfffff4; ==; pop; byte 0xfffff0; ==", 3)

}

func TestBytes(t *testing.T) {
	t.Parallel()
	testAccepts(t, "byte 0x12345678; int 2; getbyte; int 0x56; ==", 3)
	testPanics(t, "byte 0x12345678; int 4; getbyte; int 0x56; ==", 3)

	testAccepts(t, `byte "john"; int 0; getbyte; int 106; ==`, 3) // ascii j
	testAccepts(t, `byte "john"; int 1; getbyte; int 111; ==`, 3) // ascii o
	testAccepts(t, `byte "john"; int 2; getbyte; int 104; ==`, 3) // ascii h
	testAccepts(t, `byte "john"; int 3; getbyte; int 110; ==`, 3) // ascii n
	testPanics(t, `byte "john"; int 4; getbyte; int 1; ==`, 3)    // past end

	testAccepts(t, `byte "john"; int 2; int 105; setbyte; byte "join"; ==`, 3)

	// These test that setbyte is not modifying a shared value.
	// Since neither bytec nor dup copies, the first test is
	// insufficient, the setbyte changes the original constant (if
	// it fails to copy).
	testAccepts(t, `byte "john"; dup; int 2; int 105; setbyte; pop; byte "john"; ==`, 3)
	testAccepts(t, `byte "jo"; byte "hn"; concat; dup; int 2; int 105; setbyte; pop; byte "john"; ==`, 3)
}

func TestSwap(t *testing.T) {
	t.Parallel()
	testAccepts(t, "int 1; byte 0x1234; swap; int 1; ==; assert; byte 0x1234; ==", 3)
}

func TestSelect(t *testing.T) {
	t.Parallel()

	testAccepts(t, "int 1; byte 0x1231; int 0; select", 3) // selects the 1
	testRejects(t, "int 0; byte 0x1232; int 0; select", 3) // selects the 0

	testAccepts(t, "int 0; int 1; int 1; select", 3)      // selects the 1
	testPanics(t, "int 1; byte 0x1233; int 1; select", 3) // selects the bytes
}

func TestDig(t *testing.T) {
	t.Parallel()
	testAccepts(t, "int 3; int 2; int 1; dig 1; int 2; ==; return", 3)
	testPanics(t, "int 3; int 2; int 1; dig 11; int 2; ==; return", 3)
}

func TestPush(t *testing.T) {
	t.Parallel()
	testAccepts(t, "int 2; pushint 2; ==", 3)
	testAccepts(t, "pushbytes 0x1234; byte 0x1234; ==", 3)

	// There's a savings to be had if the intcblock is entirely avoided
	ops1 := testProg(t, "int 1", 3)
	ops2 := testProg(t, "pushint 1", 3)
	require.Less(t, len(ops2.Program), len(ops1.Program))

	// There's no savings to be had if the pushint replaces a
	// reference to one of the arg{0-3} opcodes, since they only
	// use one byte. And the intcblock only grows by the varuint
	// encoding size of the pushedint. Which is the same either
	// way.

	ops1 = testProg(t, "int 2; int 1", 3)
	ops2 = testProg(t, "int 2; pushint 1", 3)
	require.Equal(t, len(ops2.Program), len(ops1.Program))

	// There's a savings to be had when intcblock > 4 elements,
	// because references beyong arg 3 require two byte.
	ops1 = testProg(t, "int 2; int 3; int 5; int 6; int 1", 3)
	ops2 = testProg(t, "int 2; int 3; int 5; int 6; pushint 1", 3)
	require.Less(t, len(ops2.Program), len(ops1.Program))
}

func TestLoop(t *testing.T) {
	t.Parallel()
	// Double until > 10. Should be 16
	testAccepts(t, "int 1; loop: int 2; *; dup; int 10; <; bnz loop; int 16; ==", 4)

	// Why does this label on line with instruction cause trouble?
	testAccepts(t, "int 1; loop: int 2; *; dup; int 10; <; bnz loop; int 16; ==", 4)

	// Infinite loop because multiply by one instead of two
	testPanics(t, "int 1; loop:; int 1; *; dup; int 10; <; bnz loop; int 16; ==", 4)
}

func TestSubroutine(t *testing.T) {
	t.Parallel()
	testAccepts(t, "int 1; callsub double; int 2; ==; return; double: dup; +; retsub;", 4)
	testAccepts(t, `
b main;
fact:
  dup
  int 2
  <
  bz recur
  retsub
recur:
  dup
  int 1
  -
  callsub fact
  *
  retsub

main:
  int 5
  callsub fact
  int 120
  ==
`, 4)

	// Mutually recursive odd/even.  Each is intentionally done in a slightly different way.
	testAccepts(t, `
b main
odd:				// If 0, return false, else return !even
  dup
  bz retfalse
  callsub even
  !
  retsub

retfalse:
  pop
  int 0
  retsub


even:				// If 0, return true, else decrement and return even
  dup
  bz rettrue
  int 1
  -
  callsub odd
  retsub

rettrue:
  pop
  int 1
  retsub


main:
  int 1
  callsub odd
  assert

  int 0
  callsub even
  assert

  int 10
  callsub even
  assert

  int 10
  callsub odd
  !
  assert

  int 1
`, 4)

	testPanics(t, "int 1; retsub", 4)

	testPanics(t, "int 1; recur: callsub recur; int 1", 4)
}
