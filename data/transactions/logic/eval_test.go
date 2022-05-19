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
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/bookkeeping"
	"github.com/algorand/go-algorand/data/transactions"
	"github.com/algorand/go-algorand/logging"
	"github.com/algorand/go-algorand/protocol"
	"github.com/algorand/go-algorand/test/partitiontest"
)

// Note that most of the tests use makeTestProto/defaultEvalParams as evaluator version so that
// we check that TEAL v1 and v2 programs are compatible with the latest evaluator
func makeTestProto() *config.ConsensusParams {
	return makeTestProtoV(LogicVersion)
}

func makeTestProtoV(version uint64) *config.ConsensusParams {
	return &config.ConsensusParams{
		LogicSigVersion:     version,
		LogicSigMaxCost:     20000,
		Application:         version >= appsEnabledVersion,
		MaxAppProgramCost:   700,
		MaxAppKeyLen:        64,
		MaxAppBytesValueLen: 64,
		// These must be identical to keep an old backward compat test working
		MinTxnFee:  1001,
		MinBalance: 1001,
		// Our sample txn is 42-1066 (and that's used as default in itxn_begin)
		MaxTxnLife: 1500,
		// Strange choices below so that we test against conflating them
		AppFlatParamsMinBalance:  1002,
		SchemaMinBalancePerEntry: 1003,
		SchemaUintMinBalance:     1004,
		SchemaBytesMinBalance:    1005,
		AppFlatOptInMinBalance:   1006,

		MaxInnerTransactions: 4,
		MaxTxGroupSize:       8,

		// With the addition of itxn_field, itxn_submit, which rely on
		// machinery outside logic package for validity checking, we
		// need a more realistic set of consensus paramaters.
		Asset:                 true,
		MaxAssetNameBytes:     12,
		MaxAssetUnitNameBytes: 6,
		MaxAssetURLBytes:      32,
		MaxAssetDecimals:      4,
		SupportRekeying:       true,
		MaxTxnNoteBytes:       500,
		EnableFeePooling:      true,

		// Chosen to be different from one another and from normal proto
		MaxAppTxnAccounts:        3,
		MaxAppTxnForeignApps:     5,
		MaxAppTxnForeignAssets:   6,
		MaxAppTotalTxnReferences: 7,

		MaxAppArgs:        12,
		MaxAppTotalArgLen: 800,

		MaxAppProgramLen:        900,
		MaxAppTotalProgramLen:   1200, // Weird, but better tests
		MaxExtraAppProgramPages: 2,

		MaxGlobalSchemaEntries: 30,
		MaxLocalSchemaEntries:  13,

		EnableAppCostPooling:          true,
		EnableInnerTransactionPooling: true,

		MinInnerApplVersion: 4,

		SupportBecomeNonParticipatingTransactions: true,

		UnifyInnerTxIDs: true,
	}
}

func defaultEvalParams(txns ...transactions.SignedTxn) *EvalParams {
	return defaultEvalParamsWithVersion(LogicVersion, txns...)
}

func benchmarkEvalParams(txn transactions.SignedTxn) *EvalParams {
	ep := defaultEvalParams(txn)
	ep.Trace = nil // Tracing would slow down benchmarks
	clone := *ep.Proto
	bigBudget := 1000 * 1000 // Allow long run times
	clone.LogicSigMaxCost = uint64(bigBudget)
	clone.MaxAppProgramCost = bigBudget
	ep.Proto = &clone
	ep.PooledApplicationBudget = &bigBudget
	return ep
}

func defaultEvalParamsWithVersion(version uint64, txns ...transactions.SignedTxn) *EvalParams {
	empty := false
	if len(txns) == 0 {
		empty = true
		txns = []transactions.SignedTxn{{Txn: transactions.Transaction{Type: protocol.ApplicationCallTx}}}
	}
	ep := NewEvalParams(transactions.WrapSignedTxnsWithAD(txns), makeTestProtoV(version), &transactions.SpecialAddresses{})
	if empty {
		// We made an app type in order to get a full ep, but that sets MinTealVersion=2
		ep.TxnGroup[0].Txn.Type = "" // set it back
		ep.MinTealVersion = nil      // will recalculate in eval()
	}
	return ep
}

// reset puts an ep back into its original state.  This is in *_test.go because
// no real code should ever need this. EvalParams should be created to evaluate
// a group, and then thrown away.
func (ep *EvalParams) reset() {
	if ep.Proto.EnableAppCostPooling {
		budget := ep.Proto.MaxAppProgramCost
		ep.PooledApplicationBudget = &budget
	}
	if ep.Proto.EnableInnerTransactionPooling {
		inners := ep.Proto.MaxTxGroupSize * ep.Proto.MaxInnerTransactions
		ep.pooledAllowedInners = &inners
	}
	ep.pastScratch = make([]*scratchSpace, ep.Proto.MaxTxGroupSize)
	for i := range ep.TxnGroup {
		ep.TxnGroup[i].ApplyData = transactions.ApplyData{}
	}
	if ep.available != nil {
		ep.available.apps = nil
		ep.available.asas = nil
		// leave ep.available.boxes alone, as it is not affected by evaluations
	}
	ep.appAddrCache = make(map[basics.AppIndex]basics.Address)
	if ep.Trace != nil {
		ep.Trace = &strings.Builder{}
	}
}

func TestTooManyArgs(t *testing.T) {
	partitiontest.PartitionTest(t)

	t.Parallel()
	for v := uint64(1); v <= AssemblerMaxVersion; v++ {
		t.Run(fmt.Sprintf("v=%d", v), func(t *testing.T) {
			ops := testProg(t, "int 1", v)
			var txn transactions.SignedTxn
			txn.Lsig.Logic = ops.Program
			args := [transactions.EvalMaxArgs + 1][]byte{}
			txn.Lsig.Args = args[:]
			pass, err := EvalSignature(0, defaultEvalParams(txn))
			require.Error(t, err)
			require.False(t, pass)
		})
	}
}

func TestEmptyProgram(t *testing.T) {
	partitiontest.PartitionTest(t)

	t.Parallel()
	testLogicBytes(t, nil, defaultEvalParams(), "invalid", "invalid program (empty)")
}

// TestMinTealVersionParamEval tests eval/check reading the MinTealVersion from the param
func TestMinTealVersionParamEvalCheckSignature(t *testing.T) {
	partitiontest.PartitionTest(t)

	t.Parallel()
	params := defaultEvalParams()
	version2 := uint64(rekeyingEnabledVersion)
	params.MinTealVersion = &version2
	program := make([]byte, binary.MaxVarintLen64)
	// set the teal program version to 1
	binary.PutUvarint(program, 1)

	verErr := fmt.Sprintf("program version must be >= %d", appsEnabledVersion)
	testAppBytes(t, program, params, verErr, verErr)
}

func TestTxnFieldToTealValue(t *testing.T) {
	partitiontest.PartitionTest(t)

	txn := transactions.Transaction{}
	groupIndex := 0
	field := FirstValid
	values := [6]uint64{0, 1, 2, 0xffffffff, 0xffffffffffffffff}

	for _, value := range values {
		txn.FirstValid = basics.Round(value)
		tealValue, err := TxnFieldToTealValue(&txn, groupIndex, field, 0, false)
		require.NoError(t, err)
		require.Equal(t, basics.TealUintType, tealValue.Type)
		require.Equal(t, value, tealValue.Uint)
	}

	// check arrayFieldIdx is ignored for non-arrays
	field = FirstValid
	value := uint64(1)
	txn.FirstValid = basics.Round(value)
	tealValue, err := TxnFieldToTealValue(&txn, groupIndex, field, 10, false)
	require.NoError(t, err)
	require.Equal(t, basics.TealUintType, tealValue.Type)
	require.Equal(t, value, tealValue.Uint)

	// check arrayFieldIdx is taken into account for arrays
	field = Accounts
	sender := basics.Address{}
	addr, _ := basics.UnmarshalChecksumAddress("DFPKC2SJP3OTFVJFMCD356YB7BOT4SJZTGWLIPPFEWL3ZABUFLTOY6ILYE")
	txn.Accounts = []basics.Address{addr}
	tealValue, err = TxnFieldToTealValue(&txn, groupIndex, field, 0, false)
	require.NoError(t, err)
	require.Equal(t, basics.TealBytesType, tealValue.Type)
	require.Equal(t, string(sender[:]), tealValue.Bytes)

	tealValue, err = TxnFieldToTealValue(&txn, groupIndex, field, 1, false)
	require.NoError(t, err)
	require.Equal(t, basics.TealBytesType, tealValue.Type)
	require.Equal(t, string(addr[:]), tealValue.Bytes)

	tealValue, err = TxnFieldToTealValue(&txn, groupIndex, field, 100, false)
	require.Error(t, err)
	require.Equal(t, basics.TealUintType, tealValue.Type)
	require.Equal(t, uint64(0), tealValue.Uint)
	require.Equal(t, "", tealValue.Bytes)
}

func TestWrongProtoVersion(t *testing.T) {
	partitiontest.PartitionTest(t)

	t.Parallel()
	for v := uint64(1); v <= AssemblerMaxVersion; v++ {
		t.Run(fmt.Sprintf("v=%d", v), func(t *testing.T) {
			ops := testProg(t, "int 1", v)
			ep := defaultEvalParamsWithVersion(0)
			testAppBytes(t, ops.Program, ep, "LogicSig not supported", "LogicSig not supported")
		})
	}
}

func TestSimpleMath(t *testing.T) {
	partitiontest.PartitionTest(t)

	t.Parallel()
	testAccepts(t, "int  2; int 3; + ;int  5;==", 1)
	testAccepts(t, "int 22; int 3; - ;int 19;==", 1)
	testAccepts(t, "int  8; int 7; * ;int 56;==", 1)
	testAccepts(t, "int 21; int 7; / ;int  3;==", 1)

	testPanics(t, "int 1; int 2; - ;int 0; ==", 1)
}

func TestSha256EqArg(t *testing.T) {
	partitiontest.PartitionTest(t)

	t.Parallel()
	for v := uint64(1); v <= AssemblerMaxVersion; v++ {
		t.Run(fmt.Sprintf("v=%d", v), func(t *testing.T) {
			ops := testProg(t, `arg 0
sha256
byte base64 5rZMNsevs5sULO+54aN+OvU6lQ503z2X+SSYUABIx7E=
==`, v)
			var txn transactions.SignedTxn
			txn.Lsig.Logic = ops.Program
			txn.Lsig.Args = [][]byte{[]byte("=0\x97S\x85H\xe9\x91B\xfd\xdb;1\xf5Z\xaec?\xae\xf2I\x93\x08\x12\x94\xaa~\x06\x08\x849b")}
			ep := defaultEvalParams(txn)
			err := CheckSignature(0, ep)
			require.NoError(t, err)
			pass, err := EvalSignature(0, ep)
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
	partitiontest.PartitionTest(t)

	t.Parallel()
	for v := uint64(1); v <= AssemblerMaxVersion; v++ {
		t.Run(fmt.Sprintf("v=%d", v), func(t *testing.T) {

			a1, _ := basics.UnmarshalChecksumAddress("DFPKC2SJP3OTFVJFMCD356YB7BOT4SJZTGWLIPPFEWL3ZABUFLTOY6ILYE")
			a2, _ := basics.UnmarshalChecksumAddress("YYKRMERAFXMXCDWMBNR6BUUWQXDCUR53FPUGXLUYS7VNASRTJW2ENQ7BMQ")
			secret, _ := base64.StdEncoding.DecodeString("xPUB+DJir1wsH7g2iEY1QwYqHqYH1vUJtzZKW4RxXsY=")
			ops := testProg(t, tlhcProgramText, v)
			var txn transactions.SignedTxn
			txn.Lsig.Logic = ops.Program
			// right answer
			txn.Lsig.Args = [][]byte{secret}
			txn.Txn.FirstValid = 999999
			block := bookkeeping.Block{}
			ep := defaultEvalParams(txn)
			err := CheckSignature(0, ep)
			if err != nil {
				t.Log(hex.EncodeToString(ops.Program))
				t.Log(ep.Trace.String())
			}
			require.NoError(t, err)
			pass, err := EvalSignature(0, ep)
			if pass {
				t.Log(hex.EncodeToString(ops.Program))
				t.Log(ep.Trace.String())
			}
			require.False(t, pass)
			isNotPanic(t, err)

			txn.Txn.Receiver = a2
			txn.Txn.CloseRemainderTo = a2
			ep = defaultEvalParams(txn)
			pass, err = EvalSignature(0, ep)
			if !pass {
				t.Log(hex.EncodeToString(ops.Program))
				t.Log(ep.Trace.String())
			}
			require.True(t, pass)
			require.NoError(t, err)

			txn.Txn.Receiver = a2
			txn.Txn.CloseRemainderTo = a2
			txn.Txn.FirstValid = 1
			ep = defaultEvalParams(txn)
			pass, err = EvalSignature(0, ep)
			if pass {
				t.Log(hex.EncodeToString(ops.Program))
				t.Log(ep.Trace.String())
			}
			require.False(t, pass)
			isNotPanic(t, err)

			txn.Txn.Receiver = a1
			txn.Txn.CloseRemainderTo = a1
			txn.Txn.FirstValid = 999999
			ep = defaultEvalParams(txn)
			pass, err = EvalSignature(0, ep)
			if !pass {
				t.Log(hex.EncodeToString(ops.Program))
				t.Log(ep.Trace.String())
			}
			require.True(t, pass)
			require.NoError(t, err)

			// wrong answer
			txn.Lsig.Args = [][]byte{[]byte("=0\x97S\x85H\xe9\x91B\xfd\xdb;1\xf5Z\xaec?\xae\xf2I\x93\x08\x12\x94\xaa~\x06\x08\x849a")}
			block.BlockHeader.Round = 1
			ep = defaultEvalParams(txn)
			pass, err = EvalSignature(0, ep)
			if pass {
				t.Log(hex.EncodeToString(ops.Program))
				t.Log(ep.Trace.String())
			}
			require.False(t, pass)
			isNotPanic(t, err)
		})
	}
}

func TestU64Math(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	testAccepts(t, "int 0x1234567812345678; int 0x100000000; /; int 0x12345678; ==", 1)
}

func TestItob(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	testAccepts(t, "byte 0x1234567812345678; int 0x1234567812345678; itob; ==", 1)
}

func TestBtoi(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	testAccepts(t, "int 0x1234567812345678; byte 0x1234567812345678; btoi; ==", 1)
	testAccepts(t, "int 0x34567812345678; byte 0x34567812345678; btoi; ==", 1)
	testAccepts(t, "int 0x567812345678; byte 0x567812345678; btoi; ==", 1)
	testAccepts(t, "int 0x7812345678; byte 0x7812345678; btoi; ==", 1)
	testAccepts(t, "int 0x12345678; byte 0x12345678; btoi; ==", 1)
	testAccepts(t, "int 0x345678; byte 0x345678; btoi; ==", 1)
	testAccepts(t, "int 0; byte b64(); btoi; ==", 1)
}

func TestBtoiTooLong(t *testing.T) {
	partitiontest.PartitionTest(t)

	t.Parallel()
	testPanics(t, "int 0x1234567812345678; byte 0x1234567812345678aa; btoi; ==", 1)
}

func TestBnz(t *testing.T) {
	partitiontest.PartitionTest(t)

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

	// This code accepts if run, but the assembler will complain because the
	// "straightline" path has a typing error.  That path is not taken because
	// of the specific values used, so there is no runtime error. You could
	// assemble this with "#pragma typetrack false", and it would accept.
	code := `
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
`
	testProg(t, code, LogicVersion, Expect{12, "+ expects 2 stack arguments..."})
	testAccepts(t, notrack(code), 1)
}

func TestV2Branches(t *testing.T) {
	partitiontest.PartitionTest(t)

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
	partitiontest.PartitionTest(t)

	t.Parallel()
	testAccepts(t, "int 1; return; err", 2)
	testRejects(t, "int 0; return; int 1", 2)
}

func TestSubUnderflow(t *testing.T) {
	partitiontest.PartitionTest(t)

	t.Parallel()
	testPanics(t, "int 1; int 10; -; pop; int 1", 1)
}

func TestAddOverflow(t *testing.T) {
	partitiontest.PartitionTest(t)

	t.Parallel()
	testPanics(t, "int 0xf000000000000000; int 0x1111111111111111; +; pop; int 1", 1)
}

func TestMulOverflow(t *testing.T) {
	partitiontest.PartitionTest(t)

	t.Parallel()
	testPanics(t, "int 0x111111111; int 0x222222222; *; pop; int 1", 1)
}

func TestMulw(t *testing.T) {
	partitiontest.PartitionTest(t)

	t.Parallel()
	testAccepts(t, "int 1; int 2; mulw; int 2; ==; assert; int 0; ==", 3)
	testAccepts(t, "int 0x111111111; int 0x222222222; mulw; int 0x468acf130eca8642; ==; assert; int 2; ==", 3)
	testAccepts(t, "int 1; int 0; mulw; int 0; ==; assert; int 0; ==", 3)
	testAccepts(t, "int 0xFFFFFFFFFFFFFFFF; int 0xFFFFFFFFFFFFFFFF; mulw; int 1; ==; assert; int 0xFFFFFFFFFFFFFFFe; ==", 3)
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

func TestAddw(t *testing.T) {
	partitiontest.PartitionTest(t)

	t.Parallel()
	testAccepts(t, "int 1; int 2; addw; int 3; ==; assert; int 0; ==", 3)
	testAccepts(t, "int 0xFFFFFFFFFFFFFFFD; int 0x45; addw; int 0x42; ==; assert; int 1; ==", 3)
	testAccepts(t, "int 0; int 0; addw; int 0; ==; assert; int 0; ==", 3)
	testAccepts(t, "int 0xFFFFFFFFFFFFFFFF; dup; addw; int 0xFFFFFFFFFFFFFFFe; ==; assert; int 1; ==", 3)

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

func TestDivw(t *testing.T) {
	partitiontest.PartitionTest(t)

	t.Parallel()
	testPanics(t, "int 1; int 2; int 0; divw; assert;", 6)
	testPanics(t, "int 2; int 1; int 1; divw; assert;", 6)
	testPanics(t, "int 2; int 0; int 2; divw; assert", 6)
	testAccepts(t, "int 1; int 2; int 2; divw;", 6)

	testAccepts(t, "int 1; int 0; int 2; divw; int 0x8000000000000000; ==", 6)
	testAccepts(t, "int 0; int 90; int 30; divw; int 3; ==", 6)
}

func TestUint128(t *testing.T) {
	partitiontest.PartitionTest(t)

	t.Parallel()
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

func TestDivModw(t *testing.T) {
	partitiontest.PartitionTest(t)

	t.Parallel()
	// 2:0 / 1:0 == 2r0 == 0:2,0:0
	testAccepts(t, `int 2; int 0; int 1; int 0; divmodw;
                        int 0; ==; assert;
                        int 0; ==; assert;
                        int 2; ==; assert;
                        int 0; ==; assert; int 1`, 4)

	// 2:0 / 0:1 == 2:0r0 == 2:0,0:0
	testAccepts(t, `int 2; int 0; int 0; int 1; divmodw;
                        int 0; ==; assert;
                        int 0; ==; assert;
                        int 0; ==; assert;
                        int 2; ==; assert; int 1`, 4)

	// 0:0 / 0:7 == 0r0
	testAccepts(t, `int 0; int 0; int 0; int 7; divmodw;
                        int 0; ==; assert;
                        int 0; ==; assert;
                        int 0; ==; assert;
                        int 0; ==; assert; int 1`, 4)

	// maxu64:maxu64 / maxu64:maxu64 == 1r0
	testAccepts(t, `int 18446744073709551615; int 18446744073709551615; int 18446744073709551615; int 18446744073709551615;
                        divmodw;
                        int 0; ==; assert;
                        int 0; ==; assert;
                        int 1; ==; assert;
                        int 0; ==; assert; int 1`, 4)

	// 0:7777 / 1:0 == 0:0r7777 == 0:0,0:7777
	testAccepts(t, `int 0; int 7777; int 1; int 0; divmodw;
                        int 7777; ==; assert;
                        int 0; ==; assert;
                        int 0; ==; assert;
                        int 0; ==; assert; int 1`, 4)

	// 10:0 / 0:0 ==> panic
	testPanics(t, `int 10; int 0; int 0; int 0; divmodw;
	               pop; pop; pop; pop; int 1`, 4)
}

func TestWideMath(t *testing.T) {
	partitiontest.PartitionTest(t)

	t.Parallel()
	// 2^64 = 18446744073709551616, we use a bunch of numbers close to that below
	pattern := `
int %d
dup
store 0
int %d
dup
store 1
mulw
// add one less than the first number
load 0
int 1
-
addw
// stack is now [high word, carry bit, low word]
store 2
+				// combine carry and high
load 2
// now divmodw by the 1st given number (widened)
int 0
load 0
divmodw
// remainder should be one less that first number
load 0; int 1; -;  ==; assert
int 0; ==; assert		// (upper word)
// then the 2nd given number is left (widened)
load 1; ==; assert
int 0; ==; assert
// succeed
int 1
`

	testAccepts(t, fmt.Sprintf(pattern, 1000, 8192378), 4)
	testAccepts(t, fmt.Sprintf(pattern, 1082734200, 8192378), 4)
	testAccepts(t, fmt.Sprintf(pattern, 1000, 8129387292378), 4)
	testAccepts(t, fmt.Sprintf(pattern, 10278362800, 8192378), 4)
	for i := 1; i < 100; i++ {
		for j := 1; i < 100; i++ {
			testAccepts(t, fmt.Sprintf(pattern, i+j<<40, (i*j)<<40+j), 4)
		}
	}
}

func TestMulDiv(t *testing.T) {
	partitiontest.PartitionTest(t)

	// Demonstrate a "function" that expects three u64s on stack,
	// and calculates B*C/A. (Following opcode documentation
	// convention, C is top-of-stack, B is below it, and A is
	// below B.

	t.Parallel()
	muldiv := `
muldiv:
mulw				// multiply B*C. puts TWO u64s on stack
int 0				// high word of C as a double-word
dig 3				// pull C to TOS
divmodw
pop				// pop unneeded remainder low word
pop                             // pop unneeded remainder high word
swap
int 0
==
assert				// ensure high word of quotient was 0
swap				// bring C to surface
pop				// in order to get rid of it
retsub
`
	testAccepts(t, "int 5; int 8; int 10; callsub muldiv; int 16; ==; return;"+muldiv, 4)

	testRejects(t, "int 5; int 8; int 10; callsub muldiv; int 15; ==; return;"+muldiv, 4)

	testAccepts(t, "int 500000000000; int 80000000000; int 100000000000; callsub muldiv; int 16000000000; ==; return;"+muldiv, 4)
}

func TestDivZero(t *testing.T) {
	partitiontest.PartitionTest(t)

	t.Parallel()
	testPanics(t, "int 0x11; int 0; /; pop; int 1", 1)
}

func TestModZero(t *testing.T) {
	partitiontest.PartitionTest(t)

	t.Parallel()
	testPanics(t, "int 0x111111111; int 0; %; pop; int 1", 1)
}

func TestErr(t *testing.T) {
	partitiontest.PartitionTest(t)

	t.Parallel()
	testPanics(t, "err; int 1", 1)
}

func TestModSubMulOk(t *testing.T) {
	partitiontest.PartitionTest(t)

	t.Parallel()
	testAccepts(t, "int 35; int 16; %; int 1; -; int 2; *; int 4; ==", 1)
}

func TestPop(t *testing.T) {
	partitiontest.PartitionTest(t)

	t.Parallel()
	testAccepts(t, "int 1; int 0; pop", 1)
}

func TestStackLeftover(t *testing.T) {
	partitiontest.PartitionTest(t)

	t.Parallel()
	testPanics(t, "int 1; int 1", 1)
}

func TestStackBytesLeftover(t *testing.T) {
	partitiontest.PartitionTest(t)

	t.Parallel()
	testPanics(t, "byte 0x10101010", 1)
}

func TestStackEmpty(t *testing.T) {
	partitiontest.PartitionTest(t)

	t.Parallel()
	testPanics(t, "int 1; int 1; pop; pop", 1)
}

func TestArgTooFar(t *testing.T) {
	partitiontest.PartitionTest(t)

	t.Parallel()
	testPanics(t, "arg_1; btoi", 1)
}

func TestIntcTooFar(t *testing.T) {
	partitiontest.PartitionTest(t)

	t.Parallel()
	// Want to be super clear that intc_1 fails, whether an intcblock exists (but small) or not
	testPanics(t, "intc_1", 1)
	testPanics(t, "int 1; intc_1; pop", 1)
}

func TestBytecTooFar(t *testing.T) {
	partitiontest.PartitionTest(t)

	t.Parallel()
	testPanics(t, "bytec_1; btoi", 1)
	testPanics(t, "byte 0x23; bytec_1; btoi", 1)
}

func TestTxnBadField(t *testing.T) {
	partitiontest.PartitionTest(t)

	t.Parallel()
	program := []byte{0x01, 0x31, 0x7f}
	testLogicBytes(t, program, defaultEvalParams(), "invalid txn field")
	// TODO: Check should know the type stack was wrong

	// test txn does not accept ApplicationArgs and Accounts
	txnOpcode := OpsByName[LogicVersion]["txn"].Opcode
	txnaOpcode := OpsByName[LogicVersion]["txna"].Opcode

	fields := []TxnField{ApplicationArgs, Accounts}
	for _, field := range fields {
		source := fmt.Sprintf("txn %s 0", field.String())
		ops := testProg(t, source, AssemblerMaxVersion)
		require.Equal(t, txnaOpcode, ops.Program[1])
		ops.Program[1] = txnOpcode
		testLogicBytes(t, ops.Program, defaultEvalParams(), fmt.Sprintf("invalid txn field %d", field))
	}
}

func TestGtxnBadIndex(t *testing.T) {
	partitiontest.PartitionTest(t)

	t.Parallel()
	program := []byte{0x01, 0x33, 0x1, 0x01}
	testLogicBytes(t, program, defaultEvalParams(), "txn index 1")
}

func TestGtxnBadField(t *testing.T) {
	partitiontest.PartitionTest(t)

	t.Parallel()
	program := []byte{0x01, 0x33, 0x0, 127}
	// TODO: Check should know the type stack was wrong
	testLogicBytes(t, program, defaultEvalParams(), "invalid txn field 127")

	// test gtxn does not accept ApplicationArgs and Accounts
	txnOpcode := OpsByName[LogicVersion]["txn"].Opcode
	txnaOpcode := OpsByName[LogicVersion]["txna"].Opcode

	fields := []TxnField{ApplicationArgs, Accounts}
	for _, field := range fields {
		source := fmt.Sprintf("txn %s 0", field.String())
		ops := testProg(t, source, AssemblerMaxVersion)
		require.Equal(t, txnaOpcode, ops.Program[1])
		ops.Program[1] = txnOpcode
		testLogicBytes(t, ops.Program, defaultEvalParams(), fmt.Sprintf("invalid txn field %d", field))
	}
}

func TestGlobalBadField(t *testing.T) {
	partitiontest.PartitionTest(t)

	t.Parallel()
	program := []byte{0x01, 0x32, 127}
	testLogicBytes(t, program, defaultEvalParams(), "invalid global field")
}

func TestArg(t *testing.T) {
	partitiontest.PartitionTest(t)

	t.Parallel()
	for v := uint64(1); v <= AssemblerMaxVersion; v++ {
		t.Run(fmt.Sprintf("v=%d", v), func(t *testing.T) {
			source := "arg 0; arg 1; ==; arg 2; arg 3; !=; &&; arg 4; len; int 9; <; &&;"
			if v >= 5 {
				source += "int 0; args; int 1; args; ==; assert; int 2; args; int 3; args; !=; assert"
			}

			var txn transactions.SignedTxn
			txn.Lsig.Args = [][]byte{
				[]byte("aoeu"),
				[]byte("aoeu"),
				[]byte("aoeu2"),
				[]byte("aoeu3"),
				[]byte("aoeu4"),
			}
			ops := testProg(t, source, v)
			testLogicBytes(t, ops.Program, defaultEvalParams(txn))
		})
	}
}

const globalV1TestProgram = `
global MinTxnFee
int 1001
==
global MinBalance
int 1001
==
&&
global MaxTxnLife
int 1500
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
int 888
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

const globalV5TestProgram = globalV4TestProgram + `
global CurrentApplicationAddress
len
int 32
==
&&
global GroupID
byte 0x0706000000000000000000000000000000000000000000000000000000000000
==
&&
`

const globalV6TestProgram = globalV5TestProgram + `
global OpcodeBudget
int 0
>
&&
global CallerApplicationAddress
global ZeroAddress
==
&&
global CallerApplicationID
!
&&
`

const globalV7TestProgram = globalV6TestProgram + `
// No new globals in v7
`

func TestGlobal(t *testing.T) {
	partitiontest.PartitionTest(t)

	t.Parallel()
	type desc struct {
		lastField GlobalField
		program   string
	}
	// Associate the highest allowed global constant with each version's test program
	tests := map[uint64]desc{
		0: {GroupSize, globalV1TestProgram},
		1: {GroupSize, globalV1TestProgram},
		2: {CurrentApplicationID, globalV2TestProgram},
		3: {CreatorAddress, globalV3TestProgram},
		4: {CreatorAddress, globalV4TestProgram},
		5: {GroupID, globalV5TestProgram},
		6: {CallerApplicationAddress, globalV6TestProgram},
		7: {CallerApplicationAddress, globalV7TestProgram},
	}
	// tests keys are versions so they must be in a range 1..AssemblerMaxVersion plus zero version
	require.LessOrEqual(t, len(tests), AssemblerMaxVersion+1)
	require.Len(t, globalFieldSpecs, int(invalidGlobalField))

	ledger := NewLedger(nil)
	addr, err := basics.UnmarshalChecksumAddress(testAddr)
	require.NoError(t, err)
	ledger.NewApp(addr, 888, basics.AppParams{})
	for v := uint64(1); v <= AssemblerMaxVersion; v++ {
		_, ok := tests[v]
		require.True(t, ok)
		t.Run(fmt.Sprintf("v=%d", v), func(t *testing.T) {
			last := tests[v].lastField
			testProgram := tests[v].program
			for _, globalField := range GlobalFieldNames[:last+1] {
				if !strings.Contains(testProgram, globalField) {
					t.Errorf("TestGlobal missing field %v", globalField)
				}
			}

			txn := transactions.SignedTxn{}
			txn.Txn.Group = crypto.Digest{0x07, 0x06}

			ep := defaultEvalParams(txn)
			ep.Ledger = ledger
			testApp(t, tests[v].program, ep)
		})
	}
}
func TestTypeEnum(t *testing.T) {
	partitiontest.PartitionTest(t)

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
					ops := testProg(t, text, v)
					txn := transactions.SignedTxn{}
					txn.Txn.Type = tt
					if v < appsEnabledVersion && tt == protocol.ApplicationCallTx {
						testLogicBytes(t, ops.Program, defaultEvalParams(txn),
							"program version must be", "program version must be")
						return
					}
					testLogicBytes(t, ops.Program, defaultEvalParams(txn))
				})
			}
		})
	}
}

func TestOnCompletionConstants(t *testing.T) {
	partitiontest.PartitionTest(t)

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
	require.Equal(t, len(onCompletionMap), len(onCompletionDescriptions))
	require.Equal(t, len(OnCompletionNames), last)
	for v := NoOp; v < invalidOnCompletionConst; v++ {
		require.Equal(t, v.String(), OnCompletionNames[int(v)])
	}

	// check constants matching to their values
	for i := 0; i < last; i++ {
		oc := OnCompletionConstType(i)
		symbol := oc.String()
		require.Contains(t, onCompletionMap, symbol)
		require.Equal(t, uint64(i), onCompletionMap[symbol])
		t.Run(symbol, func(t *testing.T) {
			testAccepts(t, fmt.Sprintf("int %s; int %s; ==;", symbol, oc), 1)
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
byte "pay"
==
txn Type
byte "appl"
==
||

&&

txn TypeEnum
int 1
==
txn TypeEnum
int 6
==
||

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
int 888
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
txn ExtraProgramPages
int 2
==
assert

int 1
`

const testTxnProgramTextV5 = testTxnProgramTextV4 + `
txn Nonparticipation
pop
int 1
==
assert
txn ConfigAssetMetadataHash
int 2
txnas ApplicationArgs
==
assert
txn Sender
int 0
args
==
assert

int 1
`

// The additions in v6 were all "effects" so they must look behind.  They use gtxn 2.
const testTxnProgramTextV6 = testTxnProgramTextV5 + `
assert
txn StateProofPK
len
int 64
==
assert

gtxn 2 CreatedAssetID
int 0
==
assert

gtxn 2 CreatedApplicationID
int 0
==
assert

gtxn 2 NumLogs
int 2
==
assert

gtxn 2 Logs 1
byte "prefilled"
==
assert

gtxn 2 LastLog
byte "prefilled"
==
assert

gtxn 2 CreatedAssetID
int 0
==
assert

gtxn 2 CreatedApplicationID
int 0
==
assert

gtxn 2 NumLogs
int 2
==
assert

gtxn 2 Logs 1
byte "prefilled"
==
assert

gtxn 2 LastLog
byte "prefilled"
==
assert

int 1
`

const testTxnProgramTextV7 = testTxnProgramTextV6

func makeSampleTxn() transactions.SignedTxn {
	var txn transactions.SignedTxn
	copy(txn.Txn.Sender[:], []byte("aoeuiaoeuiaoeuiaoeuiaoeuiaoeui00"))
	copy(txn.Txn.Receiver[:], []byte("aoeuiaoeuiaoeuiaoeuiaoeuiaoeui01"))
	copy(txn.Txn.CloseRemainderTo[:], []byte("aoeuiaoeuiaoeuiaoeuiaoeuiaoeui02"))
	copy(txn.Txn.VotePK[:], []byte("aoeuiaoeuiaoeuiaoeuiaoeuiaoeui03"))
	copy(txn.Txn.SelectionPK[:], []byte("aoeuiaoeuiaoeuiaoeuiaoeuiaoeui04"))
	copy(txn.Txn.StateProofPK[:], []byte("aoeuiaoeuiaoeuiaoeuiaoeuiaoeuiaoeuiaoeuiaoeuiaoeuiaoeuiaoeuiao05"))
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
	txn.Txn.Nonparticipation = false
	txn.Txn.Type = protocol.PaymentTx
	txn.Txn.AssetAmount = 1234
	txn.Txn.AssetSender = txn.Txn.Receiver
	txn.Txn.AssetReceiver = txn.Txn.CloseRemainderTo
	txn.Txn.AssetCloseTo = txn.Txn.Sender
	txn.Txn.ApplicationID = basics.AppIndex(888)
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
	txn.Txn.ForeignApps = []basics.AppIndex{56, 100, 111} // 100 must be 2nd, 111 must be present
	txn.Txn.Boxes = []transactions.BoxRef{{Index: 0, Name: "self"}, {Index: 0, Name: "other"}}
	txn.Txn.GlobalStateSchema = basics.StateSchema{NumUint: 3, NumByteSlice: 0}
	txn.Txn.LocalStateSchema = basics.StateSchema{NumUint: 1, NumByteSlice: 2}
	return txn
}

func makeSampleAppl() transactions.SignedTxn {
	sample := makeSampleTxn()
	sample.Txn.Type = protocol.ApplicationCallTx
	return sample
}

// makeSampleTxnGroup creates a sample txn group.  If less than two transactions
// are supplied, samples are used.
func makeSampleTxnGroup(txns ...transactions.SignedTxn) []transactions.SignedTxn {
	if len(txns) == 0 {
		txns = []transactions.SignedTxn{makeSampleTxn()}
	}
	if len(txns) == 1 {
		second := transactions.SignedTxn{}
		second.Txn.Type = protocol.PaymentTx
		second.Txn.Amount.Raw = 42
		second.Txn.Fee.Raw = 1066
		second.Txn.FirstValid = 42
		second.Txn.LastValid = 1066
		second.Txn.Sender = txns[0].Txn.Receiver
		second.Txn.Receiver = txns[0].Txn.Sender
		second.Txn.ExtraProgramPages = 2
		txns = append(txns, second)
	}
	return txns
}

func TestTxn(t *testing.T) {
	partitiontest.PartitionTest(t)

	t.Parallel()
	tests := map[uint64]string{
		1: testTxnProgramTextV1,
		2: testTxnProgramTextV2,
		3: testTxnProgramTextV3,
		4: testTxnProgramTextV4,
		5: testTxnProgramTextV5,
		6: testTxnProgramTextV6,
		7: testTxnProgramTextV7,
	}

	for i, txnField := range TxnFieldNames {
		fs := txnFieldSpecs[i]
		// Ensure that each field appears, starting in the version it was introduced
		for v := uint64(1); v <= uint64(LogicVersion); v++ {
			if v < fs.version {
				continue
			}
			if !strings.Contains(tests[v], txnField) {
				if txnField == FirstValidTime.String() {
					continue
				}
				// fields were introduced for itxn before they became available for txn
				if v < txnEffectsVersion && fs.effects {
					continue
				}
				t.Errorf("testTxnProgramTextV%d missing field %v", v, txnField)
			}
		}
	}

	clearOps := testProg(t, "int 1", 1)

	for v, source := range tests {
		t.Run(fmt.Sprintf("v=%d", v), func(t *testing.T) {
			ops := testProg(t, source, v)
			txn := makeSampleTxn()
			if v >= appsEnabledVersion {
				txn.Txn.Type = protocol.ApplicationCallTx
			}
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
			// Since we test GroupIndex ==3, we need a larger group
			ep := defaultEvalParams(txn, txn, txn, txn)
			ep.TxnGroup[2].EvalDelta.Logs = []string{"x", "prefilled"}
			if v < txnEffectsVersion {
				testLogicFull(t, ops.Program, 3, ep)
			} else {
				// Starting in txnEffectsVersion, there are fields we can't access all fields in Logic mode
				testLogicFull(t, ops.Program, 3, ep, "not allowed in current mode")
				// And the early tests use "arg" a lot - not allowed in stateful. So remove those tests.
				lastArg := strings.Index(source, "arg 10\n==\n&&")
				require.NotEqual(t, -1, lastArg)

				appSafe := "int 1" + strings.Replace(source[lastArg+12:], `txn Sender
int 0
args
==
assert`, "", 1)

				ops := testProg(t, appSafe, v)
				testAppFull(t, ops.Program, 3, basics.AppIndex(888), ep)
			}
		})
	}
}

func TestCachedTxIDs(t *testing.T) {
	partitiontest.PartitionTest(t)

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
	ops := testProg(t, cachedTxnProg, 2)

	ep, _, _ := makeSampleEnv()
	txid0 := ep.TxnGroup[0].ID()
	txid1 := ep.TxnGroup[1].ID()
	ep.TxnGroup[0].Lsig.Args = [][]byte{
		txid0[:],
		txid1[:],
	}
	testLogicBytes(t, ops.Program, ep)
}

func TestGaid(t *testing.T) {
	partitiontest.PartitionTest(t)

	t.Parallel()
	check0 := testProg(t, "gaid 0; int 100; ==", 4)
	appTxn := makeSampleTxn()
	appTxn.Txn.Type = protocol.ApplicationCallTx
	targetTxn := makeSampleTxn()
	targetTxn.Txn.Type = protocol.AssetConfigTx
	ep := defaultEvalParams(targetTxn, appTxn, makeSampleTxn())
	ep.Ledger = NewLedger(nil)

	// should fail when no creatable was created
	_, err := EvalApp(check0.Program, 1, 888, ep)
	require.Error(t, err)
	require.Contains(t, err.Error(), "did not create anything")

	ep.TxnGroup[0].ApplyData.ConfigAsset = 100
	pass, err := EvalApp(check0.Program, 1, 888, ep)
	if !pass || err != nil {
		t.Log(ep.Trace.String())
	}
	require.NoError(t, err)
	require.True(t, pass)

	// should fail when accessing future transaction in group
	check2 := testProg(t, "gaid 2; int 0; >", 4)
	_, err = EvalApp(check2.Program, 1, 888, ep)
	require.Error(t, err)
	require.Contains(t, err.Error(), "gaid can't get creatable ID of txn ahead of the current one")

	// should fail when accessing self
	_, err = EvalApp(check0.Program, 0, 888, ep)
	require.Error(t, err)
	require.Contains(t, err.Error(), "gaid is only for accessing creatable IDs of previous txns")

	// should fail on non-creatable
	ep.TxnGroup[0].Txn.Type = protocol.PaymentTx
	_, err = EvalApp(check0.Program, 1, 888, ep)
	require.Error(t, err)
	require.Contains(t, err.Error(), "can't use gaid on txn that is not an app call nor an asset config txn")
	ep.TxnGroup[0].Txn.Type = protocol.AssetConfigTx
}

func TestGtxn(t *testing.T) {
	partitiontest.PartitionTest(t)

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

	gtxnTextV2 := gtxnTextV1 + `gtxna 0 ApplicationArgs 0
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
	gtxnTextV4 := gtxnTextV2 + ` gtxn 0 ExtraProgramPages
int 0
==
&&
gtxn 1 ExtraProgramPages
int 2
==
&&
`

	gtxnTextV5 := gtxnTextV4 + `int 0
gtxnas 0 Accounts
gtxn 0 Sender
==
&&
int 0
int 0
gtxnsas Accounts
gtxn 0 Sender
==
&&
`

	gtxnTextV6 := gtxnTextV5 + `
`

	tests := map[uint64]string{
		1: gtxnTextV1,
		2: gtxnTextV2,
		4: gtxnTextV4,
		5: gtxnTextV5,
		6: gtxnTextV6,
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
			ep := defaultEvalParams(makeSampleTxnGroup(txn)...)
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

func testLogic(t *testing.T, program string, v uint64, ep *EvalParams, problems ...string) {
	t.Helper()
	ops := testProg(t, program, v)
	testLogicBytes(t, ops.Program, ep, problems...)
}

func testLogicBytes(t *testing.T, program []byte, ep *EvalParams, problems ...string) {
	t.Helper()
	testLogicFull(t, program, 0, ep, problems...)
}

func testLogicFull(t *testing.T, program []byte, gi int, ep *EvalParams, problems ...string) {
	t.Helper()

	var checkProblem string
	var evalProblem string
	switch len(problems) {
	case 2:
		checkProblem = problems[0]
		evalProblem = problems[1]
	case 1:
		evalProblem = problems[0]
	case 0:
	default:
		require.Fail(t, "Misused testLogic: %d problems", len(problems))
	}

	sb := &strings.Builder{}
	ep.Trace = sb

	ep.TxnGroup[0].Lsig.Logic = program
	err := CheckSignature(gi, ep)
	if checkProblem == "" {
		require.NoError(t, err, sb.String())
	} else {
		require.Error(t, err, "Check\n%s\nExpected: %v", sb, checkProblem)
		require.Contains(t, err.Error(), checkProblem)
	}

	// We continue on to check Eval() of things that failed Check() because it's
	// a nice confirmation that Check() is usually stricter than Eval(). This
	// may mean that the problems argument is often duplicated, but this seems
	// the best way to be concise about all sorts of tests.

	pass, err := EvalSignature(gi, ep)
	if evalProblem == "" {
		require.NoError(t, err, "Eval%s\nExpected: PASS", sb)
		assert.True(t, pass, "Eval%s\nExpected: PASS", sb)
		return
	}

	// There is an evalProblem to check. REJECT is special and only means that
	// the app didn't accept.  Maybe it's an error, maybe it's just !pass.
	if evalProblem == "REJECT" {
		require.True(t, err != nil || !pass, "Eval%s\nExpected: REJECT", sb)
	} else {
		require.Error(t, err, "Eval%s\nExpected: %v", sb, evalProblem)
		require.Contains(t, err.Error(), evalProblem)
	}
}

func TestTxna(t *testing.T) {
	partitiontest.PartitionTest(t)

	t.Parallel()
	source := `txna Accounts 1
txna ApplicationArgs 0
==
`
	ops := testProg(t, source, AssemblerMaxVersion)
	var txn transactions.SignedTxn
	txn.Txn.Accounts = make([]basics.Address, 1)
	txn.Txn.Accounts[0] = txn.Txn.Sender
	txn.Txn.ApplicationArgs = [][]byte{txn.Txn.Sender[:]}
	ep := defaultEvalParams(txn)
	testLogicBytes(t, ops.Program, ep)

	// modify txn field
	saved := ops.Program[2]
	ops.Program[2] = 0x01
	testLogicBytes(t, ops.Program, ep, "unsupported array field")

	// modify txn field to unknown one
	ops.Program[2] = 99
	testLogicBytes(t, ops.Program, ep, "invalid txn field 99")

	// modify txn array index
	ops.Program[2] = saved
	saved = ops.Program[3]
	ops.Program[3] = 0x02
	testLogicBytes(t, ops.Program, ep, "invalid Accounts index")

	// modify txn array index in the second opcode
	ops.Program[3] = saved
	saved = ops.Program[6]
	ops.Program[6] = 0x01
	testLogicBytes(t, ops.Program, ep, "invalid ApplicationArgs index")
	ops.Program[6] = saved

	// check special case: Account 0 == Sender
	// even without any additional context
	source = `txna Accounts 0
txn Sender
==
`
	ops2 := testProg(t, source, AssemblerMaxVersion)
	var txn2 transactions.SignedTxn
	copy(txn2.Txn.Sender[:], []byte("aoeuiaoeuiaoeuiaoeuiaoeuiaoeui00"))
	ep2 := defaultEvalParams(txn2)
	testLogicBytes(t, ops2.Program, ep2)

	// check gtxna
	source = `gtxna 0 Accounts 1
txna ApplicationArgs 0
==`
	ops = testProg(t, source, AssemblerMaxVersion)
	testLogicBytes(t, ops.Program, ep)

	// modify gtxn index
	saved = ops.Program[2]
	ops.Program[2] = 0x01
	testLogicBytes(t, ops.Program, ep, "txn index 1, len(group) is 1")

	// modify gtxn field
	ops.Program[2] = saved
	saved = ops.Program[3]
	ops.Program[3] = 0x01
	testLogicBytes(t, ops.Program, ep, "unsupported array field")

	// modify gtxn field to unknown one
	ops.Program[3] = 99
	testLogicBytes(t, ops.Program, ep, "invalid txn field 99")

	// modify gtxn array index
	ops.Program[3] = saved
	saved = ops.Program[4]
	ops.Program[4] = 0x02
	testLogicBytes(t, ops.Program, ep, "invalid Accounts index")
	ops.Program[4] = saved

	// check special case: Account 0 == Sender
	// even without any additional context
	source = `gtxna 0 Accounts 0
txn Sender
==
`
	ops3 := testProg(t, source, AssemblerMaxVersion)
	var txn3 transactions.SignedTxn
	copy(txn2.Txn.Sender[:], []byte("aoeuiaoeuiaoeuiaoeuiaoeuiaoeui00"))
	ep3 := defaultEvalParams(txn3)
	testLogicBytes(t, ops3.Program, ep3)
}

// check empty values in ApplicationArgs and Account
func TestTxnaEmptyValues(t *testing.T) {
	partitiontest.PartitionTest(t)

	t.Parallel()
	source := `txna ApplicationArgs 0
btoi
int 0
==
`
	ops := testProg(t, source, AssemblerMaxVersion)

	var txn transactions.SignedTxn
	txn.Txn.ApplicationArgs = make([][]byte, 1)
	txn.Txn.ApplicationArgs[0] = []byte("")
	testLogicBytes(t, ops.Program, defaultEvalParams(txn))

	txn.Txn.ApplicationArgs[0] = nil
	testLogicBytes(t, ops.Program, defaultEvalParams(txn))

	source2 := `txna Accounts 1
global ZeroAddress
==
`
	ops = testProg(t, source2, AssemblerMaxVersion)

	var txn2 transactions.SignedTxn
	txn2.Txn.Accounts = make([]basics.Address, 1)
	txn2.Txn.Accounts[0] = basics.Address{}
	testLogicBytes(t, ops.Program, defaultEvalParams(txn2))

	txn2.Txn.Accounts = make([]basics.Address, 1)
	testLogicBytes(t, ops.Program, defaultEvalParams(txn2))
}

func TestTxnas(t *testing.T) {
	partitiontest.PartitionTest(t)

	t.Parallel()

	source := `int 1
txnas Accounts
int 0
txnas ApplicationArgs
==
`
	ops := testProg(t, source, AssemblerMaxVersion)
	var txn transactions.SignedTxn
	txn.Txn.Accounts = make([]basics.Address, 1)
	txn.Txn.Accounts[0] = txn.Txn.Sender
	txn.Txn.ApplicationArgs = [][]byte{txn.Txn.Sender[:]}
	ep := defaultEvalParams(txn)
	testLogicBytes(t, ops.Program, ep)

	// check special case: Account 0 == Sender
	// even without any additional context
	source = `int 0
txnas Accounts
txn Sender
==
`
	ops = testProg(t, source, AssemblerMaxVersion)
	var txn2 transactions.SignedTxn
	copy(txn2.Txn.Sender[:], []byte("aoeuiaoeuiaoeuiaoeuiaoeuiaoeui00"))
	testLogicBytes(t, ops.Program, defaultEvalParams(txn2))

	// check gtxnas
	source = `int 1
gtxnas 0 Accounts
txna ApplicationArgs 0
==`
	ops = testProg(t, source, AssemblerMaxVersion)
	testLogicBytes(t, ops.Program, ep)

	// check special case: Account 0 == Sender
	// even without any additional context
	source = `int 0
gtxnas 0 Accounts
txn Sender
==
	`
	ops = testProg(t, source, AssemblerMaxVersion)
	var txn3 transactions.SignedTxn
	copy(txn3.Txn.Sender[:], []byte("aoeuiaoeuiaoeuiaoeuiaoeuiaoeui00"))
	testLogicBytes(t, ops.Program, defaultEvalParams(txn3))

	// check gtxnsas
	source = `int 0
int 1
gtxnsas Accounts
txna ApplicationArgs 0
==`
	ops = testProg(t, source, AssemblerMaxVersion)
	testLogicBytes(t, ops.Program, ep)
}

func TestBitOps(t *testing.T) {
	partitiontest.PartitionTest(t)

	t.Parallel()
	testAccepts(t, `int 0x17
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
==`, 1)
}

func TestStringOps(t *testing.T) {
	partitiontest.PartitionTest(t)

	t.Parallel()
	testAccepts(t, `byte 0x123456789abc
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
&&`, 2) // substring, concat, substring3 came in v2
}

func TestConsOverflow(t *testing.T) {
	partitiontest.PartitionTest(t)

	t.Parallel()
	justfits := `byte 0xf000000000000000
dup; concat				// 16
dup; concat				// 32
dup; concat				// 64
dup; concat				// 128
dup; concat				// 256
dup; concat				// 512
dup; concat				// 1024
dup; concat				// 2048
dup; concat				// 4096
`
	testAccepts(t, justfits+"len", 2)
	testPanics(t, justfits+"byte 0x11; concat; len", 2)
}

func TestSubstringFlop(t *testing.T) {
	partitiontest.PartitionTest(t)

	t.Parallel()
	// fails in compiler
	testProg(t, `byte 0xf000000000000000
substring
len`, 2, Expect{2, "substring expects 2 immediate arguments"})

	// fails in compiler
	testProg(t, `byte 0xf000000000000000
substring 1
len`, 2, Expect{2, "substring expects 2 immediate arguments"})

	// fails in compiler
	testProg(t, `byte 0xf000000000000000
substring 4 2
len`, 2, Expect{2, "substring end is before start"})

	// fails at runtime
	testPanics(t, `byte 0xf000000000000000
int 4
int 2
substring3
len`, 2)

	// fails at runtime
	err := testPanics(t, `byte 0xf000000000000000
int 4
int 0xFFFFFFFFFFFFFFFE
substring3
len`, 2)
	require.Contains(t, err.Error(), "substring range beyond length of string")
}

func TestSubstringRange(t *testing.T) {
	partitiontest.PartitionTest(t)

	t.Parallel()
	testPanics(t, `byte 0xf000000000000000
substring 2 99
len`, 2)
}

func TestExtractOp(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()
	testAccepts(t, "byte 0x123456789abc; extract 1 2; byte 0x3456; ==", 5)
	testAccepts(t, "byte 0x123456789abc; extract 0 6; byte 0x123456789abc; ==", 5)
	testAccepts(t, "byte 0x123456789abc; extract 3 0; byte 0x789abc; ==", 5)
	testAccepts(t, "byte 0x123456789abc; extract 6 0; len; int 0; ==", 5)
	testAccepts(t, "byte 0x123456789abcaa; extract 0 6; byte 0x123456789abcaa; !=", 5)

	testAccepts(t, "byte 0x123456789abc; int 5; int 1; extract3; byte 0xbc; ==", 5)

	testAccepts(t, "byte 0x123456789abcdef0; int 1; extract_uint16; int 0x3456; ==", 5)
	testAccepts(t, "byte 0x123456789abcdef0; int 1; extract_uint32; int 0x3456789a; ==", 5)
	testAccepts(t, "byte 0x123456789abcdef0; int 0; extract_uint64; int 0x123456789abcdef0; ==", 5)
	testAccepts(t, "byte 0x123456789abcdef0; int 0; extract_uint64; int 0x123456789abcdef; !=", 5)

	testAccepts(t, `byte "hello"; extract 5 0; byte ""; ==`, 5)
	testAccepts(t, `byte "hello"; int 5; int 0; extract3; byte ""; ==`, 5)
}

func TestExtractFlop(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()
	// fails in compiler
	testProg(t, `byte 0xf000000000000000
	extract
	len`, 5, Expect{2, "extract expects 2 immediate arguments"})

	testProg(t, `byte 0xf000000000000000
	extract 1
	len`, 5, Expect{2, "extract expects 2 immediate arguments"})

	// fails at runtime
	err := testPanics(t, `byte 0xf000000000000000
	extract 1 8
	len`, 5)
	require.Contains(t, err.Error(), "extract range beyond length of string")

	err = testPanics(t, `byte 0xf000000000000000
	extract 9 0
	len`, 5)
	require.Contains(t, err.Error(), "extract range beyond length of string")

	err = testPanics(t, `byte 0xf000000000000000
	int 4
	int 0xFFFFFFFFFFFFFFFE
	extract3
	len`, 5)
	require.Contains(t, err.Error(), "extract range beyond length of string")

	err = testPanics(t, `byte 0xf000000000000000
	int 100
	int 2
	extract3
	len`, 5)
	require.Contains(t, err.Error(), "extract range beyond length of string")

	err = testPanics(t, `byte 0xf000000000000000
	int 55
	extract_uint16`, 5)
	require.Contains(t, err.Error(), "extract range beyond length of string")

	err = testPanics(t, `byte 0xf000000000000000
	int 9
	extract_uint32`, 5)
	require.Contains(t, err.Error(), "extract range beyond length of string")

	err = testPanics(t, `byte 0xf000000000000000
	int 1
	extract_uint64`, 5)
	require.Contains(t, err.Error(), "extract range beyond length of string")
}

func TestLoadStore(t *testing.T) {
	partitiontest.PartitionTest(t)

	t.Parallel()
	testAccepts(t, "load 3; int 0; ==;", 1)

	testAccepts(t, `int 37
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
&&`, 1)
}

func TestLoadStoreStack(t *testing.T) {
	partitiontest.PartitionTest(t)

	t.Parallel()
	testAccepts(t, "int 3; loads; int 0; ==;", 5)
	testAccepts(t, `int 37
int 1
int 37
stores
int 42
byte 0xabbacafe
stores
int 37
==
int 0
swap
stores
int 42
loads
byte 0xabbacafe
==
int 0
loads
int 1
loads
+
&&`, 5)
}

func TestLoadStore2(t *testing.T) {
	partitiontest.PartitionTest(t)

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
	testAccepts(t, progText, 1)
}

func TestGload(t *testing.T) {
	partitiontest.PartitionTest(t)

	t.Parallel()

	// for simple app-call-only transaction groups
	type scratchTestCase struct {
		tealSources []string
		errTxn      int
		errContains string
	}

	simpleCase := scratchTestCase{
		tealSources: []string{
			`
int 2
store 0
int 1`,
			`
gload 0 0
int 2
==
`,
		},
	}

	multipleTxnCase := scratchTestCase{
		tealSources: []string{
			`
byte "txn 1"
store 0
int 1`,
			`
byte "txn 2"
store 2
int 1`,
			`
gload 0 0
byte "txn 1"
==
gload 1 2
byte "txn 2"
==
&&
`,
		},
	}

	selfCase := scratchTestCase{
		tealSources: []string{
			`
gload 0 0
int 2
store 0
int 1
`,
		},
		errTxn:      0,
		errContains: "can't use gload on self, use load instead",
	}

	laterTxnSlotCase := scratchTestCase{
		tealSources: []string{
			`
gload 1 0
int 2
==`,
			`
int 2
store 0
int 1`,
		},
		errTxn:      0,
		errContains: "gload can't get future scratch space from txn with index 1",
	}

	cases := []scratchTestCase{
		simpleCase, multipleTxnCase, selfCase, laterTxnSlotCase,
	}

	for i, testCase := range cases {
		t.Run(fmt.Sprintf("i=%d", i), func(t *testing.T) {
			sources := testCase.tealSources

			// Initialize txgroup
			txgroup := make([]transactions.SignedTxn, len(sources))
			for j := range txgroup {
				txgroup[j].Txn.Type = protocol.ApplicationCallTx
			}

			if testCase.errContains != "" {
				testApps(t, sources, txgroup, LogicVersion, nil, Expect{testCase.errTxn, testCase.errContains})
			} else {
				testApps(t, sources, txgroup, LogicVersion, nil)
			}
		})
	}

	// for more complex group transaction cases
	type failureCase struct {
		firstTxn    transactions.SignedTxn
		runMode     runMode
		errContains string
	}

	nonAppCall := failureCase{
		firstTxn: transactions.SignedTxn{
			Txn: transactions.Transaction{
				Type: protocol.PaymentTx,
			},
		},
		runMode:     modeApp,
		errContains: "can't use gload on non-app call txn with index 0",
	}

	logicSigCall := failureCase{
		firstTxn: transactions.SignedTxn{
			Txn: transactions.Transaction{
				Type: protocol.ApplicationCallTx,
			},
		},
		runMode:     modeSig,
		errContains: "gload not allowed in current mode",
	}

	failCases := []failureCase{nonAppCall, logicSigCall}
	for j, failCase := range failCases {
		t.Run(fmt.Sprintf("j=%d", j), func(t *testing.T) {
			program := testProg(t, "gload 0 0", AssemblerMaxVersion).Program

			txgroup := []transactions.SignedTxnWithAD{
				{SignedTxn: failCase.firstTxn},
				{},
			}

			ep := &EvalParams{
				Proto:       makeTestProto(),
				TxnGroup:    txgroup,
				pastScratch: make([]*scratchSpace, 2),
			}

			switch failCase.runMode {
			case modeApp:
				testAppBytes(t, program, ep, failCase.errContains)
			default:
				testLogicBytes(t, program, ep, failCase.errContains, failCase.errContains)
			}
		})
	}
}

// TestGloads tests gloads and gloadss
func TestGloads(t *testing.T) {
	partitiontest.PartitionTest(t)

	t.Parallel()

	// Multiple app calls
	source1 := `
byte "txn 1"
store 0
int 1`
	source2 := `
byte "txn 2"
store 1
int 1`
	source3 := `
int 0
gloads 0
byte "txn 1"
==
assert
int 1
gloads 1
byte "txn 2"
==
assert
int 0
int 0
gloadss
byte "txn 1"
==
assert
int 1
int 1
gloadss
byte "txn 2"
==
assert
int 1
`

	sources := []string{source1, source2, source3}

	txgroup := make([]transactions.SignedTxn, len(sources))
	for j := range txgroup {
		txgroup[j].Txn.Type = protocol.ApplicationCallTx
	}

	testApps(t, sources, txgroup, LogicVersion, nil)
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
	partitiontest.PartitionTest(t)

	t.Parallel()
	testAccepts(t, testCompareProgramText, 1)
}

func TestSlowLogic(t *testing.T) {
	partitiontest.PartitionTest(t)

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
	// We should never Eval this after it fails Check(), but nice to see it also fails.
	testLogicBytes(t, ops.Program, defaultEvalParamsWithVersion(1),
		"static cost", "dynamic cost")
	// v2overspend passes Check, even on v2 proto, because the old low cost is "grandfathered"
	ops = testProg(t, v2overspend, 1)
	testLogicBytes(t, ops.Program, defaultEvalParamsWithVersion(2))

	// even the shorter, v2overspend, fails when compiled as v2 code
	ops = testProg(t, v2overspend, 2)
	testLogicBytes(t, ops.Program, defaultEvalParamsWithVersion(2),
		"static cost", "dynamic cost")

	// in v4 cost is still 134, but only matters in Eval, not Check, so both fail there
	ep4 := defaultEvalParamsWithVersion(4)
	ops = testProg(t, v1overspend, 4)
	testLogicBytes(t, ops.Program, ep4, "dynamic cost")

	ops = testProg(t, v2overspend, 4)
	testLogicBytes(t, ops.Program, ep4, "dynamic cost")
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
	partitiontest.PartitionTest(t)

	t.Parallel()
	for v := uint64(1); v <= AssemblerMaxVersion; v++ {
		t.Run(fmt.Sprintf("v=%d", v), func(t *testing.T) {
			ops := testProg(t, `int 1`, v)
			ops.Program = append(ops.Program, 0x08) // +
			testLogicBytes(t, ops.Program, defaultEvalParams(), "stack underflow")
		})
	}
}

func TestWrongStackTypeRuntime(t *testing.T) {
	partitiontest.PartitionTest(t)

	t.Parallel()
	for v := uint64(1); v <= AssemblerMaxVersion; v++ {
		t.Run(fmt.Sprintf("v=%d", v), func(t *testing.T) {
			ops := testProg(t, `int 1`, v)
			ops.Program = append(ops.Program, 0x01, 0x15) // sha256, len
			testLogicBytes(t, ops.Program, defaultEvalParams(), "sha256 arg 0 wanted")
		})
	}
}

func TestEqMismatch(t *testing.T) {
	partitiontest.PartitionTest(t)

	t.Parallel()
	for v := uint64(1); v <= AssemblerMaxVersion; v++ {
		t.Run(fmt.Sprintf("v=%d", v), func(t *testing.T) {
			ops := testProg(t, `byte 0x1234; int 1`, v)
			ops.Program = append(ops.Program, 0x12) // ==
			testLogicBytes(t, ops.Program, defaultEvalParams(), "cannot compare")
			// TODO: Check should know the type stack was wrong
		})
	}
}

func TestNeqMismatch(t *testing.T) {
	partitiontest.PartitionTest(t)

	t.Parallel()
	for v := uint64(1); v <= AssemblerMaxVersion; v++ {
		t.Run(fmt.Sprintf("v=%d", v), func(t *testing.T) {
			ops := testProg(t, `byte 0x1234; int 1`, v)
			ops.Program = append(ops.Program, 0x13) // !=
			testLogicBytes(t, ops.Program, defaultEvalParams(), "cannot compare")
		})
	}
}

func TestWrongStackTypeRuntime2(t *testing.T) {
	partitiontest.PartitionTest(t)

	t.Parallel()
	for v := uint64(1); v <= AssemblerMaxVersion; v++ {
		t.Run(fmt.Sprintf("v=%d", v), func(t *testing.T) {
			ops := testProg(t, `byte 0x1234; int 1`, v)
			ops.Program = append(ops.Program, 0x08) // +
			testLogicBytes(t, ops.Program, defaultEvalParams(), "+ arg 0 wanted")
		})
	}
}

func TestIllegalOp(t *testing.T) {
	partitiontest.PartitionTest(t)

	t.Parallel()
	for v := uint64(1); v <= AssemblerMaxVersion; v++ {
		t.Run(fmt.Sprintf("v=%d", v), func(t *testing.T) {
			ops := testProg(t, `int 1`, v)
			for opcode, spec := range opsByOpcode[v] {
				if spec.op == nil {
					ops.Program = append(ops.Program, byte(opcode))
					break
				}
			}
			testLogicBytes(t, ops.Program, defaultEvalParams(), "illegal opcode", "illegal opcode")
		})
	}
}

func TestShortProgram(t *testing.T) {
	partitiontest.PartitionTest(t)

	t.Parallel()
	for v := uint64(1); v <= AssemblerMaxVersion; v++ {
		t.Run(fmt.Sprintf("v=%d", v), func(t *testing.T) {
			ops := testProg(t, `int 1
bnz done
done:
int 1
`, v)
			// cut two last bytes - intc_1 and last byte of bnz
			ops.Program = ops.Program[:len(ops.Program)-2]
			testLogicBytes(t, ops.Program, defaultEvalParams(),
				"bnz program ends short", "bnz program ends short")
		})
	}
}

func TestShortProgramTrue(t *testing.T) {
	partitiontest.PartitionTest(t)

	t.Parallel()
	ops := testProg(t, `intcblock 1
intc 0
intc 0
bnz done
done:`, 2)
	testLogicBytes(t, ops.Program, defaultEvalParams())
}

func TestShortBytecblock(t *testing.T) {
	partitiontest.PartitionTest(t)

	t.Parallel()
	for v := uint64(1); v <= AssemblerMaxVersion; v++ {
		t.Run(fmt.Sprintf("v=%d", v), func(t *testing.T) {
			fullops, err := AssembleStringWithVersion(`bytecblock 0x123456 0xababcdcd "test"`, v)
			require.NoError(t, err)
			fullops.Program[2] = 50 // fake 50 elements
			for i := 2; i < len(fullops.Program); i++ {
				program := fullops.Program[:i]
				t.Run(hex.EncodeToString(program), func(t *testing.T) {
					testLogicBytes(t, program, defaultEvalParams(),
						"bytecblock", "bytecblock")
				})
			}
		})
	}
}

func TestShortBytecblock2(t *testing.T) {
	partitiontest.PartitionTest(t)

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
			testLogicBytes(t, program, defaultEvalParams(), "bytecblock", "bytecblock")
		})
	}
}

const panicString = "out of memory, buffer overrun, stack overflow, divide by zero, halt and catch fire"

func opPanic(cx *EvalContext) error {
	panic(panicString)
}
func checkPanic(cx *EvalContext) error {
	panic(panicString)
}

func TestPanic(t *testing.T) {
	partitiontest.PartitionTest(t)

	log := logging.TestingLog(t)
	for v := uint64(1); v <= AssemblerMaxVersion; v++ {
		t.Run(fmt.Sprintf("v=%d", v), func(t *testing.T) {
			ops := testProg(t, `int 1`, v)
			var hackedOpcode int
			var oldSpec OpSpec
			// Find an unused opcode to temporarily convert to a panicing opcde,
			// and append it to program.
			for opcode, spec := range opsByOpcode[v] {
				if spec.op == nil {
					hackedOpcode = opcode
					oldSpec = spec
					opsByOpcode[v][opcode].op = opPanic
					opsByOpcode[v][opcode].Modes = modeAny
					opsByOpcode[v][opcode].OpDetails.FullCost.baseCost = 1
					opsByOpcode[v][opcode].OpDetails.check = checkPanic
					ops.Program = append(ops.Program, byte(opcode))
					break
				}
			}
			params := defaultEvalParams()
			params.logger = log
			params.TxnGroup[0].Lsig.Logic = ops.Program
			err := CheckSignature(0, params)
			require.Error(t, err)
			if pe, ok := err.(PanicError); ok {
				require.Equal(t, panicString, pe.PanicValue)
				pes := pe.Error()
				require.True(t, strings.Contains(pes, "panic"))
			} else {
				t.Errorf("expected PanicError object but got %T %#v", err, err)
			}
			var txn transactions.SignedTxn
			txn.Lsig.Logic = ops.Program
			params = defaultEvalParams(txn)
			params.logger = log
			pass, err := EvalSignature(0, params)
			if pass {
				t.Log(hex.EncodeToString(ops.Program))
				t.Log(params.Trace.String())
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
	partitiontest.PartitionTest(t)

	t.Parallel()
	var program [12]byte
	vlen := binary.PutUvarint(program[:], evalMaxVersion+1)
	testLogicBytes(t, program[:vlen], defaultEvalParams(),
		"greater than max supported", "greater than max supported")
}

func TestInvalidVersion(t *testing.T) {
	partitiontest.PartitionTest(t)

	t.Parallel()
	program, err := hex.DecodeString("ffffffffffffffffffffffff")
	require.NoError(t, err)
	testLogicBytes(t, program, defaultEvalParams(), "invalid version", "invalid version")
}

func TestProgramProtoForbidden(t *testing.T) {
	partitiontest.PartitionTest(t)

	t.Parallel()
	var program [12]byte
	vlen := binary.PutUvarint(program[:], evalMaxVersion)
	ep := defaultEvalParams()
	ep.Proto = &config.ConsensusParams{
		LogicSigVersion: evalMaxVersion - 1,
	}
	testLogicBytes(t, program[:vlen], ep, "greater than protocol", "greater than protocol")
}

func TestMisalignedBranch(t *testing.T) {
	partitiontest.PartitionTest(t)

	t.Parallel()
	for v := uint64(1); v <= AssemblerMaxVersion; v++ {
		t.Run(fmt.Sprintf("v=%d", v), func(t *testing.T) {
			ops := testProg(t, `int 1
bnz done
bytecblock 0x01234576 0xababcdcd 0xf000baad
done:
int 1`, v)
			//t.Log(hex.EncodeToString(program))
			canonicalProgramString := mutateProgVersion(v, "01200101224000112603040123457604ababcdcd04f000baad22")
			canonicalProgramBytes, err := hex.DecodeString(canonicalProgramString)
			require.NoError(t, err)
			require.Equal(t, ops.Program, canonicalProgramBytes)
			ops.Program[7] = 3 // clobber the branch offset to be in the middle of the bytecblock
			// Since Eval() doesn't know the jump is bad, we reject "by luck"
			testLogicBytes(t, ops.Program, defaultEvalParams(), "aligned", "REJECT")

			// back branches are checked differently, so test misaligned back branch
			ops.Program[6] = 0xff // Clobber the two bytes of offset with 0xff 0xff = -1
			ops.Program[7] = 0xff // That jumps into the offset itself (pc + 3 -1)
			if v < backBranchEnabledVersion {
				testLogicBytes(t, ops.Program, defaultEvalParams(), "negative branch", "negative branch")
			} else {
				// Again, if we were ever to Eval(), we would not know it's wrong. But we reject here "by luck"
				testLogicBytes(t, ops.Program, defaultEvalParams(), "back branch target", "REJECT")
			}
		})
	}
}

func TestBranchTooFar(t *testing.T) {
	partitiontest.PartitionTest(t)

	t.Parallel()
	for v := uint64(1); v <= AssemblerMaxVersion; v++ {
		t.Run(fmt.Sprintf("v=%d", v), func(t *testing.T) {
			ops := testProg(t, `int 1
bnz done
bytecblock 0x01234576 0xababcdcd 0xf000baad
done:
int 1`, v)
			//t.Log(hex.EncodeToString(ops.Program))
			canonicalProgramString := mutateProgVersion(v, "01200101224000112603040123457604ababcdcd04f000baad22")
			canonicalProgramBytes, err := hex.DecodeString(canonicalProgramString)
			require.NoError(t, err)
			require.Equal(t, ops.Program, canonicalProgramBytes)
			ops.Program[7] = 200 // clobber the branch offset to be beyond the end of the program
			testLogicBytes(t, ops.Program, defaultEvalParams(),
				"outside of program", "outside of program")
		})
	}
}

func TestBranchTooLarge(t *testing.T) {
	partitiontest.PartitionTest(t)

	t.Parallel()
	for v := uint64(1); v <= AssemblerMaxVersion; v++ {
		t.Run(fmt.Sprintf("v=%d", v), func(t *testing.T) {
			ops := testProg(t, `int 1
bnz done
bytecblock 0x01234576 0xababcdcd 0xf000baad
done:
int 1`, v)
			//t.Log(hex.EncodeToString(ops.Program))
			// (br)anch byte, (hi)gh byte of offset,  (lo)w byte:     brhilo
			canonicalProgramString := mutateProgVersion(v, "01200101224000112603040123457604ababcdcd04f000baad22")
			canonicalProgramBytes, err := hex.DecodeString(canonicalProgramString)
			require.NoError(t, err)
			require.Equal(t, ops.Program, canonicalProgramBytes)
			ops.Program[6] = 0x70 // clobber hi byte of branch offset
			testLogicBytes(t, ops.Program, defaultEvalParams(), "outside", "outside")
		})
	}
	branches := []string{
		"bz done",
		"b done",
	}
	template := `intcblock 0 1
intc_0
%s
done:
intc_1
`
	for _, line := range branches {
		t.Run(fmt.Sprintf("branch=%s", line), func(t *testing.T) {
			source := fmt.Sprintf(template, line)
			ops, err := AssembleStringWithVersion(source, AssemblerMaxVersion)
			require.NoError(t, err)
			ops.Program[7] = 0xf0 // clobber the branch offset - highly negative
			ops.Program[8] = 0xff // clobber the branch offset
			testLogicBytes(t, ops.Program, defaultEvalParams(),
				"outside of program", "outside of program")
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

func evalLoop(b *testing.B, runs int, program []byte) {
	b.ResetTimer()
	for i := 0; i < runs; i++ {
		var txn transactions.SignedTxn
		txn.Lsig.Logic = program
		pass, err := EvalSignature(0, benchmarkEvalParams(txn))
		if !pass {
			// rerun to trace it.  tracing messes up timing too much
			ep := benchmarkEvalParams(txn)
			ep.Trace = &strings.Builder{}
			pass, err = EvalSignature(0, ep)
			b.Log(ep.Trace.String())
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

func benchmarkBasicProgram(b *testing.B, source string) {
	ops := testProg(b, source, AssemblerMaxVersion)
	evalLoop(b, b.N, ops.Program)
}

// Rather than run b.N times, build a program that runs the operation
// 2000 times, and does so for b.N / 2000 runs.  This lets us amortize
// away the creation and teardown of the evaluation system.  We report
// the "extra/op" as the number of extra instructions that are run
// during the "operation".  They are presumed to be fast (15/ns), so
// the idea is that you can subtract that out from the reported speed
func benchmarkOperation(b *testing.B, prefix string, operation string, suffix string) {
	runs := 1 + b.N/2000
	inst := strings.Count(operation, ";") + strings.Count(operation, "\n")
	source := prefix + ";" + strings.Repeat(operation+";", 2000) + ";" + suffix
	source = strings.ReplaceAll(source, ";", "\n")
	ops := testProg(b, source, AssemblerMaxVersion)
	evalLoop(b, runs, ops.Program)
	b.ReportMetric(float64(inst), "extra/op")
}

func BenchmarkUintMath(b *testing.B) {
	benches := [][]string{
		{"dup", "int 23423", "dup; pop", ""},
		{"pop1", "", "int 1234576; pop", "int 1"},
		{"pop", "", "int 1234576; int 6712; pop; pop", "int 1"},
		{"add", "", "int 1234576; int 6712; +; pop", "int 1"},
		{"addw", "", "int 21276237623; int 32387238723; addw; pop; pop", "int 1"},
		{"sub", "", "int 1234576; int 2; -; pop", "int 1"},
		{"mul", "", "int 212; int 323; *; pop", "int 1"},
		{"mulw", "", "int 21276237623; int 32387238723; mulw; pop; pop", "int 1"},
		{"div", "", "int 736247364; int 892; /; pop", "int 1"},
		{"divw", "", "int 736; int 892; int 892; divw; pop", "int 1"},
		{"divmodw", "", "int 736247364; int 892; int 126712; int 71672; divmodw; pop; pop; pop; pop", "int 1"},
		{"sqrt", "", "int 736247364; sqrt; pop", "int 1"},
		{"exp", "", "int 734; int 5; exp; pop", "int 1"},
		{"expw", "", "int 734; int 10; expw; pop; pop", "int 1"},
	}
	for _, bench := range benches {
		b.Run(bench[0], func(b *testing.B) {
			b.ReportAllocs()
			benchmarkOperation(b, bench[1], bench[2], bench[3])
		})
	}
}

func BenchmarkUintCmp(b *testing.B) {
	ops := []string{"==", "!=", "<", "<=", ">", ">="}
	for _, op := range ops {
		b.Run(op, func(b *testing.B) {
			benchmarkOperation(b, "", "int 7263; int 273834; "+op+"; pop", "int 1")
		})
	}
}
func BenchmarkByteLogic(b *testing.B) {
	benches := [][]string{
		{"b&", "", "byte 0x012345678901feab; byte 0x01ffffffffffffff; b&; pop", "int 1"},
		{"b|", "", "byte 0x0ffff1234576abef; byte 0x1202120212021202; b|; pop", "int 1"},
		{"b^", "", "byte 0x0ffff1234576abef; byte 0x1202120212021202; b^; pop", "int 1"},
		{"b~", "byte 0x0123457673624736", "b~", "pop; int 1"},

		{"b&big",
			"byte 0x0123457601234576012345760123457601234576012345760123457601234576",
			"byte 0x01ffffffffffffff01ffffffffffffff01234576012345760123457601234576; b&",
			"pop; int 1"},
		{"b|big",
			"byte 0x0123457601234576012345760123457601234576012345760123457601234576",
			"byte           0xffffff01ffffffffffffff01234576012345760123457601234576; b|",
			"pop; int 1"},
		{"b^big", "", // u256^u256
			`byte 0x123457601234576012345760123457601234576012345760123457601234576a
			 byte 0xf123457601234576012345760123457601234576012345760123457601234576; b^; pop`,
			"int 1"},
		{"b~big", "byte 0xa123457601234576012345760123457601234576012345760123457601234576",
			"b~",
			"pop; int 1"},
	}
	for _, bench := range benches {
		b.Run(bench[0], func(b *testing.B) {
			b.ReportAllocs()
			benchmarkOperation(b, bench[1], bench[2], bench[3])
		})
	}
}

func BenchmarkByteMath(b *testing.B) {
	benches := [][]string{
		{"bpop", "", "byte 0x01ffffffffffffff; pop", "int 1"},

		{"b+", "byte 0x01234576", "byte 0x01ffffffffffffff; b+", "pop; int 1"},
		{"b-", "byte 0x0ffff1234576", "byte 0x1202; b-", "pop; int 1"},
		{"b*", "", "byte 0x01234576; byte 0x0223627389; b*; pop", "int 1"},
		{"b/", "", "byte 0x0123457673624736; byte 0x0223627389; b/; pop", "int 1"},
		{"b%", "", "byte 0x0123457673624736; byte 0x0223627389; b/; pop", "int 1"},
		{"bsqrt", "", "byte 0x0123457673624736; bsqrt; pop", "int 1"},

		{"b+big", // u256 + u256
			"byte 0x0123457601234576012345760123457601234576012345760123457601234576",
			"byte 0x01ffffffffffffff01ffffffffffffff01234576012345760123457601234576; b+",
			"pop; int 1"},
		{"b-big", // second is a bit small, so we can subtract it over and over
			"byte 0x0123457601234576012345760123457601234576012345760123457601234576",
			"byte           0xffffff01ffffffffffffff01234576012345760123457601234576; b-",
			"pop; int 1"},
		{"b*big", "", // u256*u256
			`byte 0xa123457601234576012345760123457601234576012345760123457601234576
			 byte 0xf123457601234576012345760123457601234576012345760123457601234576; b*; pop`,
			"int 1"},
		{"b/big", "", // u256 / u128 (half sized divisor seems pessimal)
			`byte 0xa123457601234576012345760123457601234576012345760123457601234576
			 byte 0x34576012345760123457601234576312; b/; pop`,
			"int 1"},
		{"b%big", "", // u256 / u128 (half sized divisor seems pessimal)
			`byte 0xa123457601234576012345760123457601234576012345760123457601234576
			 byte 0x34576012345760123457601234576312; b/; pop`,
			"int 1"},
		{"bsqrt-big", "",
			`byte 0xa123457601234576012345760123457601234576012345760123457601234576
			 bsqrt; pop`,
			"int 1"},
	}
	for _, bench := range benches {
		b.Run(bench[0], func(b *testing.B) {
			benchmarkOperation(b, bench[1], bench[2], bench[3])
		})
	}
}

func BenchmarkBase64Decode(b *testing.B) {
	smallStd := "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
	smallURL := "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
	medStd := strings.Repeat(smallStd, 16)
	medURL := strings.Repeat(smallURL, 16)
	bigStd := strings.Repeat(medStd, 4)
	bigURL := strings.Repeat(medURL, 4)

	tags := []string{"0", "64", "1024", "4096"}
	stds := []string{"", smallStd, medStd, bigStd}
	urls := []string{"", smallURL, medURL, bigURL}
	ops := []string{
		"int 1; int 2; +; pop",
		"b~",
		"int 1; pop",
		"base64_decode StdEncoding",
		"base64_decode URLEncoding",
	}
	benches := [][]string{}
	for i, tag := range tags {
		for _, op := range ops {
			testName := op
			encoded := stds[i]
			if op == "base64_decode URLEncoding" {
				encoded = urls[i]
			}
			if len(op) > 0 {
				op += "; "
			}
			op += "pop"
			benches = append(benches, []string{
				fmt.Sprintf("%s_%s", testName, tag),
				"",
				fmt.Sprintf(`byte "%s"; %s`, encoded, op),
				"int 1",
			})
		}
	}
	for _, bench := range benches {
		b.Run(bench[0], func(b *testing.B) {
			benchmarkOperation(b, bench[1], bench[2], bench[3])
		})
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

func BenchmarkCheckx5(b *testing.B) {
	sourcePrograms := []string{
		tlhcProgramText,
		testTxnProgramTextV3,
		testCompareProgramText,
		addBenchmarkSource,
		addBenchmark2Source,
	}

	programs := make([][]byte, len(sourcePrograms))
	for i, text := range sourcePrograms {
		ops := testProg(b, text, AssemblerMaxVersion)
		programs[i] = ops.Program
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		for _, program := range programs {
			var txn transactions.SignedTxn
			txn.Lsig.Logic = program
			err := CheckSignature(0, defaultEvalParams(txn))
			if err != nil {
				require.NoError(b, err)
			}
		}
	}
}

func TestEvalVersions(t *testing.T) {
	partitiontest.PartitionTest(t)

	t.Parallel()

	text := `intcblock 1
intc_0
txna ApplicationArgs 0
pop
`
	ops := testProg(t, text, AssemblerMaxVersion)

	var txn transactions.SignedTxn
	txn.Lsig.Logic = ops.Program
	txn.Txn.ApplicationArgs = [][]byte{[]byte("test")}

	ep := defaultEvalParams(txn)
	testLogicBytes(t, ops.Program, ep)

	ep = defaultEvalParamsWithVersion(1, txn)
	testLogicBytes(t, ops.Program, ep,
		"greater than protocol supported version 1", "greater than protocol supported version 1")

	// hack the version and fail on illegal opcode
	ops.Program[0] = 0x1
	ep = defaultEvalParamsWithVersion(1, txn)
	testLogicBytes(t, ops.Program, ep, "illegal opcode 0x36", "illegal opcode 0x36") // txna
}

func TestStackOverflow(t *testing.T) {
	partitiontest.PartitionTest(t)

	t.Parallel()
	source := "int 1; int 2;"
	for i := 1; i < maxStackDepth/2; i++ {
		source += "dup2;"
	}
	testAccepts(t, source+"return", 2)
	testPanics(t, source+"dup2; return", 2)
}

func TestDup(t *testing.T) {
	partitiontest.PartitionTest(t)

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
	testAccepts(t, text, 2)
	testAccepts(t, "int 1; int 2; dup2; pop; pop; pop", 2)
	testPanics(t, "int 1; int 2; dup2; pop; pop", 2)
}

func TestStringLiteral(t *testing.T) {
	partitiontest.PartitionTest(t)

	t.Parallel()

	text := `byte "foo bar"
byte b64(Zm9vIGJhcg==)
==
`
	testAccepts(t, text, 1)

	text = `byte "foo bar // not a comment"
byte b64(Zm9vIGJhciAvLyBub3QgYSBjb21tZW50)
==
`
	testAccepts(t, text, 1)

	text = `byte ""
byte 0x
==
`
	testAccepts(t, text, 1)

	text = `byte "" // empty string literal
byte 0x // empty byte constant
==
`
	testAccepts(t, text, 1)
}

func TestArgType(t *testing.T) {
	partitiontest.PartitionTest(t)

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
	partitiontest.PartitionTest(t)

	t.Parallel()
	const source = "int 1"

	txn := makeSampleTxn()
	txn.Txn.Type = protocol.ApplicationCallTx
	txn.Txn.RekeyTo = basics.Address{}
	ep := defaultEvalParams(txn)

	for v := uint64(0); v < appsEnabledVersion; v++ {
		ops := testProg(t, source, v)
		e := fmt.Sprintf("program version must be >= %d", appsEnabledVersion)
		testAppBytes(t, ops.Program, ep, e, e)
	}

	testApp(t, source, ep)
}

func TestAnyRekeyToOrApplicationRaisesMinTealVersion(t *testing.T) {
	partitiontest.PartitionTest(t)

	t.Parallel()
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
			ep := defaultEvalParams(cse.group...)

			// Computed MinTealVersion should be == validFromVersion
			calc := ComputeMinTealVersion(ep.TxnGroup)
			require.Equal(t, calc, cse.validFromVersion)

			// Should fail for all versions < validFromVersion
			expected := fmt.Sprintf("program version must be >= %d", cse.validFromVersion)
			for v := uint64(0); v < cse.validFromVersion; v++ {
				ops := testProg(t, source, v)
				testAppBytes(t, ops.Program, ep, expected, expected)
				testLogicBytes(t, ops.Program, ep, expected, expected)
			}

			// Should succeed for all versions >= validFromVersion
			for v := cse.validFromVersion; v <= AssemblerMaxVersion; v++ {
				ops := testProg(t, source, v)
				testAppBytes(t, ops.Program, ep)
				testLogicBytes(t, ops.Program, ep)
			}
		})
	}
}

// check all v2 opcodes: allowed in v2 and not allowed in v1 and v0
func TestAllowedOpcodesV2(t *testing.T) {
	partitiontest.PartitionTest(t)

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
		"substring3":        "byte 0x41; int 0; int 1; substring3",
		"balance":           "int 1; balance",
		"app_opted_in":      "int 0; dup; app_opted_in",
		"app_local_get":     "int 0; byte 0x41; app_local_get",
		"app_local_get_ex":  "int 0; dup; byte 0x41; app_local_get_ex",
		"app_global_get":    "int 0; byte 0x41; app_global_get",
		"app_global_get_ex": "int 0; byte 0x41; app_global_get_ex",
		"app_local_put":     "int 0; byte 0x41; dup; app_local_put",
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

	ep := defaultEvalParams()

	cnt := 0
	for _, spec := range OpSpecs {
		if spec.Version == 2 && !excluded[spec.Name] {
			source, ok := tests[spec.Name]
			require.True(t, ok, "Missed opcode in the test: %s", spec.Name)
			require.Contains(t, source, spec.Name)
			ops := testProg(t, source, AssemblerMaxVersion)
			// all opcodes allowed in stateful mode so use CheckStateful/EvalContract
			err := CheckContract(ops.Program, ep)
			require.NoError(t, err, source)
			_, err = EvalApp(ops.Program, 0, 0, ep)
			if spec.Name != "return" {
				// "return" opcode always succeeds so ignore it
				require.Error(t, err, source)
				require.NotContains(t, err.Error(), "illegal opcode")
			}

			for v := byte(0); v <= 1; v++ {
				ops.Program[0] = v
				testLogicBytes(t, ops.Program, ep, "illegal opcode", "illegal opcode")
				testAppBytes(t, ops.Program, ep, "illegal opcode", "illegal opcode")
			}
			cnt++
		}
	}
	require.Equal(t, len(tests), cnt)
}

// check all v3 opcodes: allowed in v3 and not allowed before
func TestAllowedOpcodesV3(t *testing.T) {
	partitiontest.PartitionTest(t)

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

	ep := defaultEvalParams()

	cnt := 0
	for _, spec := range OpSpecs {
		if spec.Version == 3 {
			source, ok := tests[spec.Name]
			require.True(t, ok, "Missed opcode in the test: %s", spec.Name)
			require.Contains(t, source, spec.Name)
			ops := testProg(t, source, AssemblerMaxVersion)
			// all opcodes allowed in stateful mode so use CheckStateful/EvalContract
			testAppBytes(t, ops.Program, ep, "REJECT")

			for v := byte(0); v <= 1; v++ {
				ops.Program[0] = v
				testLogicBytes(t, ops.Program, ep, "illegal opcode", "illegal opcode")
				testAppBytes(t, ops.Program, ep, "illegal opcode", "illegal opcode")
			}
			cnt++
		}
	}
	require.Len(t, tests, cnt)
}

// TestLinearOpcodes ensures we don't have a linear cost opcode (which
// inherently requires a dynamic cost model) before backBranchEnabledVersion,
// which introduced our dynamic model.
func TestLinearOpcodes(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()
	for _, spec := range OpSpecs {
		if spec.Version < backBranchEnabledVersion {
			require.Zero(t, spec.OpDetails.FullCost.chunkCost, spec)
		}
	}
}

func TestRekeyFailsOnOldVersion(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	for v := uint64(0); v < rekeyingEnabledVersion; v++ {
		t.Run(fmt.Sprintf("v=%d", v), func(t *testing.T) {
			ops := testProg(t, `int 1`, v)
			var txn transactions.SignedTxn
			txn.Txn.RekeyTo = basics.Address{1, 2, 3, 4}
			ep := defaultEvalParams(txn)
			e := fmt.Sprintf("program version must be >= %d", rekeyingEnabledVersion)
			testLogicBytes(t, ops.Program, ep, e, e)
		})
	}
}

func notrack(program string) string {
	// Put a prefix on the program that does nothing interesting,
	// but prevents assembly from detecting type errors.  Allows
	// evaluation testing of a program that would be rejected by
	// assembler.
	pragma := "#pragma typetrack false\n"
	if strings.Contains(program, pragma) {
		return program // Already done.  Tests sometimes use at multiple levels
	}
	return pragma + program
}

type evalTester func(pass bool, err error) bool

func testEvaluation(t *testing.T, program string, introduced uint64, tester evalTester) error {
	t.Helper()

	var outer error
	for v := uint64(1); v <= AssemblerMaxVersion; v++ {
		t.Run(fmt.Sprintf("v=%d", v), func(t *testing.T) {
			t.Helper()
			if v < introduced {
				testProg(t, notrack(program), v, Expect{0, "...was introduced..."})
				return
			}
			ops := testProg(t, program, v)
			// Programs created with a previous assembler
			// should still operate properly with future
			// EvalParams, so try all forward versions.
			for lv := v; lv <= AssemblerMaxVersion; lv++ {
				t.Run(fmt.Sprintf("lv=%d", lv), func(t *testing.T) {
					t.Helper()
					var txn transactions.SignedTxn
					txn.Lsig.Logic = ops.Program
					ep := defaultEvalParamsWithVersion(lv, txn)
					err := CheckSignature(0, ep)
					if err != nil {
						t.Log(ep.Trace.String())
					}
					require.NoError(t, err)
					ep = defaultEvalParamsWithVersion(lv, txn)
					pass, err := EvalSignature(0, ep)
					ok := tester(pass, err)
					if !ok {
						t.Log(ep.Trace.String())
						t.Log(err)
					}
					require.True(t, ok)
					isNotPanic(t, err) // Never want a Go level panic.
					if err != nil {
						// Use wisely. This could probably return any of the concurrent runs' errors.
						outer = err
					}
				})
			}
		})
	}
	return outer
}

func testAccepts(t *testing.T, program string, introduced uint64) {
	t.Helper()
	testEvaluation(t, program, introduced, func(pass bool, err error) bool {
		return pass && err == nil
	})
}
func testRejects(t *testing.T, program string, introduced uint64) {
	t.Helper()
	testEvaluation(t, program, introduced, func(pass bool, err error) bool {
		// Returned False, but didn't panic
		return !pass && err == nil
	})
}
func testPanics(t *testing.T, program string, introduced uint64) error {
	t.Helper()
	return testEvaluation(t, program, introduced, func(pass bool, err error) bool {
		// TEAL panic! not just reject at exit
		return !pass && err != nil
	})
}

func TestAssert(t *testing.T) {
	partitiontest.PartitionTest(t)

	t.Parallel()
	testAccepts(t, "int 1;assert;int 1", 3)
	testRejects(t, "int 1;assert;int 0", 3)
	testPanics(t, "int 0;assert;int 1", 3)
	testPanics(t, notrack("assert;int 1"), 3)
	testPanics(t, notrack(`byte "john";assert;int 1`), 3)
}

func TestBits(t *testing.T) {
	partitiontest.PartitionTest(t)

	t.Parallel()
	testAccepts(t, "int 1; int 0; getbit; int 1; ==", 3)
	testAccepts(t, "int 1; int 1; getbit; int 0; ==", 3)

	testAccepts(t, "int 1; int 63; getbit; int 0; ==", 3)
	testPanics(t, "int 1; int 64; getbit; int 0; ==", 3)

	testAccepts(t, "int 0; int 3; int 1; setbit; int 8; ==", 3)
	testPanics(t, "int 0; int 3; int 2; setbit; pop; int 1", 3)
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
	partitiontest.PartitionTest(t)

	t.Parallel()
	testAccepts(t, "byte 0x12345678; int 2; getbyte; int 0x56; ==", 3)
	testPanics(t, "byte 0x12345678; int 4; getbyte; int 0x56; ==", 3)

	testAccepts(t, `byte "john"; int 0; getbyte; int 106; ==`, 3) // ascii j
	testAccepts(t, `byte "john"; int 1; getbyte; int 111; ==`, 3) // ascii o
	testAccepts(t, `byte "john"; int 2; getbyte; int 104; ==`, 3) // ascii h
	testAccepts(t, `byte "john"; int 3; getbyte; int 110; ==`, 3) // ascii n
	testPanics(t, `byte "john"; int 4; getbyte; int 1; ==`, 3)    // past end

	testAccepts(t, `byte "john"; int 2; int 105; setbyte; byte "join"; ==`, 3)
	testPanics(t, `byte "john"; int 2; int 256; setbyte; pop; int 1;`, 3)

	testPanics(t, `global ZeroAddress; dup; concat; int 64; int 7; setbyte; int 1; return`, 3)
	testAccepts(t, `global ZeroAddress; dup; concat; int 63; int 7; setbyte; int 1; return`, 3)

	// These test that setbyte is not modifying a shared value.
	// Since neither bytec nor dup copies, the first test is
	// insufficient, the setbyte changes the original constant (if
	// it fails to copy).
	testAccepts(t, `byte "john"; dup; int 2; int 105; setbyte; pop; byte "john"; ==`, 3)
	testAccepts(t, `byte "jo"; byte "hn"; concat; dup; int 2; int 105; setbyte; pop; byte "john"; ==`, 3)

	testAccepts(t, `byte "john"; byte "john"; ==`, 1)
}

func TestMethod(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()
	// Although 'method' is new around the time of v5, it is a
	// pseudo-op, so it's ok to use it earlier, as it compiles to
	// existing opcodes.
	testAccepts(t, "method \"add(uint64,uint64)uint128\"; byte 0x8aa3b61f; ==", 1)
}

func TestSwap(t *testing.T) {
	partitiontest.PartitionTest(t)

	t.Parallel()
	testAccepts(t, "int 1; byte 0x1234; swap; int 1; ==; assert; byte 0x1234; ==", 3)
	testPanics(t, notrack("int 1; swap; int 1; return"), 3)
}

func TestSelect(t *testing.T) {
	partitiontest.PartitionTest(t)

	t.Parallel()

	testAccepts(t, "int 1; byte 0x1231; int 0; select", 3) // selects the 1
	testRejects(t, "int 0; byte 0x1232; int 0; select", 3) // selects the 0

	testAccepts(t, "int 0; int 1; int 1; select", 3)      // selects the 1
	testPanics(t, "int 1; byte 0x1233; int 1; select", 3) // selects the bytes
}

func TestDig(t *testing.T) {
	partitiontest.PartitionTest(t)

	t.Parallel()
	testAccepts(t, "int 3; int 2; int 1; dig 1; int 2; ==; return", 3)
	testPanics(t, notrack("int 3; int 2; int 1; dig 11; int 2; ==; return"), 3)
}

func TestCover(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()
	testAccepts(t, "int 4; int 3; int 2; int 1; cover 0; int 1; ==; return", 5)
	testAccepts(t, "int 4; int 3; int 2; int 1; cover 1; int 2; ==; return", 5)
	testAccepts(t, "int 4; int 3; int 2; int 1; cover 2; int 2; ==; return", 5)
	testAccepts(t, "int 4; int 3; int 2; int 1; cover 2; pop; pop; int 1; ==; return", 5)
	testPanics(t, notrack("int 4; int 3; int 2; int 1; cover 11; int 2; ==; return"), 5)
	testPanics(t, notrack("int 4; int 3; int 2; int 1; cover 4; int 2; ==; return"), 5)
}

func TestUncover(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()
	testAccepts(t, "int 4; int 3; int 2; int 1; uncover 0; int 1; ==; return", 5)
	testAccepts(t, "int 4; int 3; int 2; int 1; uncover 2; int 3; ==; return", 5)
	testAccepts(t, "int 4; int 3; int 2; int 1; uncover 3; int 4; ==; return", 5)
	testAccepts(t, "int 4; int 3; int 2; int 1; uncover 3; pop; int 1; ==; return", 5)
	testAccepts(t, "int 4; int 3; int 2; int 1; uncover 3; pop; pop; int 2; ==; return", 5)
	testAccepts(t, "int 1; int 3; int 2; int 1; uncover 3; pop; pop; int 2; ==; return", 5)
	testPanics(t, notrack("int 4; int 3; int 2; int 1; uncover 11; int 3; ==; return"), 5)
	testPanics(t, notrack("int 4; int 3; int 2; int 1; uncover 4; int 2; ==; return"), 5)
}

func TestPush(t *testing.T) {
	partitiontest.PartitionTest(t)

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
	partitiontest.PartitionTest(t)

	t.Parallel()
	// Double until > 10. Should be 16
	testAccepts(t, "int 1; loop: int 2; *; dup; int 10; <; bnz loop; int 16; ==", 4)

	testAccepts(t, "int 1; loop: int 2; *; dup; int 10; <; bnz loop; int 16; ==", 4)

	// Infinite loop because multiply by one instead of two
	testPanics(t, "int 1; loop:; int 1; *; dup; int 10; <; bnz loop; int 16; ==", 4)
}

func TestSubroutine(t *testing.T) {
	partitiontest.PartitionTest(t)

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

func TestShifts(t *testing.T) {
	partitiontest.PartitionTest(t)

	t.Parallel()
	testAccepts(t, "int 1; int 0; shl; int 1; ==", 4)
	testAccepts(t, "int 1; int 1; shl; int 2; ==", 4)
	testAccepts(t, "int 1; int 2; shl; int 4; ==", 4)
	testAccepts(t, "int 3; int 2; shl; int 12; ==", 4)
	testAccepts(t, "int 2; int 63; shl; int 0; ==", 4)

	testAccepts(t, "int 3; int 0; shr; int 3; ==", 4)
	testAccepts(t, "int 1; int 1; shr; int 0; ==", 4)
	testAccepts(t, "int 1; int 2; shr; int 0; ==", 4)
	testAccepts(t, "int 3; int 1; shr; int 1; ==", 4)
	testAccepts(t, "int 96; int 3; shr; int 12; ==", 4)
	testAccepts(t, "int 8756675; int 63; shr; int 0; ==", 4)

	testPanics(t, "int 8756675; int 64; shr; int 0; ==", 4)
	testPanics(t, "int 8756675; int 64; shl; int 0; ==", 4)
}

func TestSqrt(t *testing.T) {
	partitiontest.PartitionTest(t)

	t.Parallel()
	testAccepts(t, "int 0; sqrt; int 0; ==", 4)
	testAccepts(t, "int 1; sqrt; int 1; ==", 4)
	testAccepts(t, "int 2; sqrt; int 1; ==", 4)
	testAccepts(t, "int 4; sqrt; int 2; ==", 4)
	testAccepts(t, "int 5; sqrt; int 2; ==", 4)

	testAccepts(t, "int 3735928559; sqrt; int 61122; ==", 4)
	testAccepts(t, "int 244837814094590; sqrt; int 15647294; ==", 4)

	testAccepts(t, "int 2024; sqrt; int 44; ==", 4)
	testAccepts(t, "int 2025; sqrt; int 45; ==", 4)
	testAccepts(t, "int 2026; sqrt; int 45; ==", 4)

	// Largest possible uint64
	testAccepts(t, "int 18446744073709551615; sqrt; int 4294967295; ==", 4)

	// The actual square of that largest possible sqrt
	testAccepts(t, "int 18446744065119617025; sqrt; int 4294967295; ==", 4)
	testAccepts(t, "int 18446744065119617024; sqrt; int 4294967294; ==", 4)

}

func TestExp(t *testing.T) {
	partitiontest.PartitionTest(t)

	t.Parallel()
	testPanics(t, "int 0; int 0; exp; int 1; ==", 4)
	testAccepts(t, "int 0; int 200; exp; int 0; ==", 4)
	testAccepts(t, "int 1000; int 0; exp; int 1; ==", 4)
	testAccepts(t, "int 1; int 2; exp; int 1; ==", 4)
	testAccepts(t, "int 3; int 1; exp; int 3; ==", 4)
	testAccepts(t, "int 96; int 3; exp; int 884736; ==", 4)
	testPanics(t, "int 96; int 15; exp; int 884736; >", 4)

	// These seem the same but check different code paths
	testPanics(t, "int 2; int 64; exp; pop; int 1", 4)
	testPanics(t, "int 4; int 32; exp; pop; int 1", 4)
}

func TestExpw(t *testing.T) {
	partitiontest.PartitionTest(t)

	t.Parallel()
	testPanics(t, "int 0; int 0; expw; int 1; ==; assert; int 0; ==", 4)
	testAccepts(t, "int 0; int 200; expw; int 0; ==; assert; int 0; ==", 4)
	testAccepts(t, "int 1000; int 0; expw; int 1; ==; assert; int 0; ==", 4)
	testAccepts(t, "int 1; int 2; expw; int 1; ==; assert; int 0; ==", 4)
	testAccepts(t, "int 3; int 1; expw; int 3; ==; assert; int 0; ==", 4)
	testAccepts(t, "int 96; int 3; expw; int 884736; ==; assert; int 0; ==", 4)
	testAccepts(t, "int 64; int 21; expw; pop; pop; int 1", 4) // (2^6)^21 = 2^126
	testPanics(t, "int 64; int 22; expw; pop; pop; int 1", 4)  // (2^6)^22 = 2^132

	testAccepts(t, "int 97; int 15; expw; int 10271255586529954209; ==; assert; int 34328615749; ==;", 4)

	testPanics(t, "int 2; int 128; expw; pop; pop; int 1", 4) // 2^128 is too big
	// looks the same, but different code path
	testPanics(t, "int 4; int 64; expw; pop; pop; int 1", 4) // 2^128 is too big
}

func TestBitLen(t *testing.T) {
	partitiontest.PartitionTest(t)

	t.Parallel()
	testAccepts(t, "int 0; bitlen; int 0; ==", 4)
	testAccepts(t, "int 1; bitlen; int 1; ==", 4)
	testAccepts(t, "int 2; bitlen; int 2; ==", 4)
	testAccepts(t, "int 4; bitlen; int 3; ==", 4)
	testAccepts(t, "int 5; bitlen; int 3; ==", 4)
	testAccepts(t, "int 8; bitlen; int 4; ==", 4)

	testAccepts(t, "byte 0x; bitlen; int 0; ==", 4)
	testAccepts(t, "byte 0x00; bitlen; int 0; ==", 4)
	testAccepts(t, "byte 0x01; bitlen; int 1; ==", 4)
	testAccepts(t, "byte 0x02; bitlen; int 2; ==", 4)
	testAccepts(t, "byte 0x03; bitlen; int 2; ==", 4)
	testAccepts(t, "byte 0x04; bitlen; int 3; ==", 4)
	testAccepts(t, "byte 0xf0; bitlen; int 8; ==", 4)
	testAccepts(t, "byte 0x0100; bitlen; int 9; ==", 4)
	testAccepts(t, "byte 0x010001000100010001000100010001000100; bitlen; int 137; ==", 4)

}

func TestBytesMath(t *testing.T) {
	partitiontest.PartitionTest(t)

	t.Parallel()
	testAccepts(t, "byte 0x01; byte 0x01; b+; byte 0x02; ==", 4)
	testAccepts(t, "byte 0x01FF; byte 0x01; b+; byte 0x0200; ==", 4)

	effs := strings.Repeat("ff", 64)
	// 64 byte long inputs are accepted, even if they produce longer outputs
	testAccepts(t, fmt.Sprintf("byte 0x%s; byte 0x10; b+; len; int 65; ==", effs), 4)
	// 65 byte inputs are not ok.
	testPanics(t, fmt.Sprintf("byte 0x%s00; byte 0x10; b-; len; int 65; ==", effs), 4)

	testAccepts(t, `byte 0x01; byte 0x01; b-; byte ""; ==`, 4)
	testAccepts(t, "byte 0x0200; byte 0x01; b-; byte 0x01FF; ==", 4)
	// returns are smallest possible
	testAccepts(t, "byte 0x0100; byte 0x01; b-; byte 0xFF; ==", 4)
	testPanics(t, "byte 0x01; byte 0x02; b-; int 1; return", 4)

	testAccepts(t, "byte 0x01; byte 0x01; b/; byte 0x01; ==", 4)
	testPanics(t, "byte 0x0200; byte b64(); b/; int 1; return", 4)
	testPanics(t, "byte 0x01; byte 0x00; b/; int 1; return", 4)

	testAccepts(t, "byte 0x10; byte 0x07; b%; byte 0x02; ==; return", 4)
	testPanics(t, "byte 0x01; byte 0x00; b%; int 1; return", 4)

	// Even 128 byte outputs are ok
	testAccepts(t, fmt.Sprintf("byte 0x%s; byte 0x%s; b*; len; int 128; ==", effs, effs), 4)

	testAccepts(t, "byte 0x00; bsqrt; byte 0x; ==; return", 6)
	testAccepts(t, "byte 0x01; bsqrt; byte 0x01; ==; return", 6)
	testAccepts(t, "byte 0x10; bsqrt; byte 0x04; ==; return", 6)
	testAccepts(t, "byte 0x11; bsqrt; byte 0x04; ==; return", 6)
	testAccepts(t, "byte 0xffffff; bsqrt; len; int 2; ==; return", 6)
	// 64 byte long inputs are accepted, even if they produce longer outputs
	testAccepts(t, fmt.Sprintf("byte 0x%s; bsqrt; len; int 32; ==", effs), 6)
	// 65 byte inputs are not ok.
	testPanics(t, fmt.Sprintf("byte 0x%s00; bsqrt; pop; int 1", effs), 6)
}

func TestBytesCompare(t *testing.T) {
	partitiontest.PartitionTest(t)

	t.Parallel()
	testAccepts(t, "byte 0x10; byte 0x10; b*; byte 0x0100; ==", 4)
	testAccepts(t, "byte 0x100000000000; byte 0x00; b*; byte b64(); ==", 4)

	testAccepts(t, "byte 0x10; byte 0x10; b<; !", 4)
	testAccepts(t, "byte 0x10; byte 0x10; b<=", 4)
	testAccepts(t, "byte 0x10; int 64; bzero; b>", 4)
	testPanics(t, "byte 0x10; int 65; bzero; b>", 4)

	testAccepts(t, "byte 0x11; byte 0x10; b>", 4)
	testAccepts(t, "byte 0x11; byte 0x0010; b>", 4)

	testAccepts(t, "byte 0x11; byte 0x10; b>=", 4)
	testAccepts(t, "byte 0x11; byte 0x0011; b>=", 4)

	testAccepts(t, "byte 0x11; byte 0x11; b==", 4)
	testAccepts(t, "byte 0x0011; byte 0x11; b==", 4)
	testAccepts(t, "byte 0x11; byte 0x00000000000011; b==", 4)
	testAccepts(t, "byte 0x00; int 64; bzero; b==", 4)
	testPanics(t, "byte 0x00; int 65; bzero; b==", 4)

	testAccepts(t, "byte 0x11; byte 0x00; b!=", 4)
	testAccepts(t, "byte 0x0011; byte 0x1100; b!=", 4)
	testPanics(t, notrack("byte 0x11; int 17; b!="), 4)
}

func TestBytesBits(t *testing.T) {
	partitiontest.PartitionTest(t)

	t.Parallel()
	testAccepts(t, "byte 0x11; byte 0x10; b|; byte 0x11; ==", 4)
	testAccepts(t, "byte 0x01; byte 0x10; b|; byte 0x11; ==", 4)
	testAccepts(t, "byte 0x0201; byte 0x10f1; b|; byte 0x12f1; ==", 4)
	testAccepts(t, "byte 0x0001; byte 0x00f1; b|; byte 0x00f1; ==", 4)

	testAccepts(t, "byte 0x11; byte 0x10; b&; byte 0x10; ==", 4)
	testAccepts(t, "byte 0x01; byte 0x10; b&; byte 0x00; ==", 4)
	testAccepts(t, "byte 0x0201; byte 0x10f1; b&; byte 0x0001; ==", 4)
	testAccepts(t, "byte 0x01; byte 0x00f1; b&; byte 0x0001; ==", 4)

	testAccepts(t, "byte 0x11; byte 0x10; b^; byte 0x01; ==", 4)
	testAccepts(t, "byte 0x01; byte 0x10; b^; byte 0x11; ==", 4)
	testAccepts(t, "byte 0x0201; byte 0x10f1; b^; byte 0x12f0; ==", 4)
	testAccepts(t, "byte 0x0001; byte 0xf1; b^; byte 0x00f0; ==", 4)

	testAccepts(t, "byte 0x0001; b~; byte 0xfffe; ==", 4)
	testAccepts(t, "byte 0x; b~; byte 0x; ==", 4)
	testAccepts(t, "byte 0xf001; b~; byte 0x0ffe; ==", 4)

	testAccepts(t, "int 3; bzero; byte 0x000000; ==", 4)
	testAccepts(t, "int 33; bzero; byte 0x000000000000000000000000000000000000000000000000000000000000000000; ==", 4)

	testAccepts(t, "int 4096; bzero; len; int 4096; ==", 4)
	testPanics(t, "int 4097; bzero; len; int 4097; ==", 4)
}

func TestBytesConversions(t *testing.T) {
	partitiontest.PartitionTest(t)

	t.Parallel()
	testAccepts(t, "byte 0x11; byte 0x10; b+; btoi; int 0x21; ==", 4)
	testAccepts(t, "byte 0x0011; byte 0x10; b+; btoi; int 0x21; ==", 4)
}

func TestLog(t *testing.T) {
	partitiontest.PartitionTest(t)

	t.Parallel()
	var txn transactions.SignedTxn
	txn.Txn.Type = protocol.ApplicationCallTx
	ledger := NewLedger(nil)
	ledger.NewApp(txn.Txn.Receiver, 0, basics.AppParams{})
	ep := defaultEvalParams(txn)
	ep.Proto = makeTestProtoV(LogicVersion)
	ep.Ledger = ledger
	testCases := []struct {
		source string
		loglen int
	}{
		{
			source: `byte  "a logging message"; log; int 1`,
			loglen: 1,
		},
		{
			source: `byte  "a logging message"; log; byte  "a logging message"; log; int 1`,
			loglen: 2,
		},
		{
			source: fmt.Sprintf(`%s int 1`, strings.Repeat(`byte "a logging message"; log;`, maxLogCalls)),
			loglen: maxLogCalls,
		},
		{
			source: `int 1; loop: byte "a logging message"; log; int 1; +; dup; int 30; <=; bnz loop;`,
			loglen: 30,
		},
		{
			source: fmt.Sprintf(`byte "%s"; log; int 1`, strings.Repeat("a", maxLogSize)),
			loglen: 1,
		},
	}

	//track expected number of logs in cx.EvalDelta.Logs
	for i, s := range testCases {
		delta := testApp(t, s.source, ep)
		require.Len(t, delta.Logs, s.loglen)
		if i == len(testCases)-1 {
			require.Equal(t, strings.Repeat("a", maxLogSize), delta.Logs[0])
		} else {
			for _, l := range delta.Logs {
				require.Equal(t, "a logging message", l)
			}
		}
	}

	msg := strings.Repeat("a", 400)
	failCases := []struct {
		source      string
		runMode     runMode
		errContains string
	}{
		{
			source:      fmt.Sprintf(`byte  "%s"; log; int 1`, strings.Repeat("a", maxLogSize+1)),
			errContains: fmt.Sprintf(">  %d bytes limit", maxLogSize),
			runMode:     modeApp,
		},
		{
			source:      fmt.Sprintf(`byte  "%s"; log; byte  "%s"; log; byte  "%s"; log; int 1`, msg, msg, msg),
			errContains: fmt.Sprintf(">  %d bytes limit", maxLogSize),
			runMode:     modeApp,
		},
		{
			source:      fmt.Sprintf(`%s; int 1`, strings.Repeat(`byte "a"; log;`, maxLogCalls+1)),
			errContains: "too many log calls",
			runMode:     modeApp,
		},
		{
			source:      `int 1; loop: byte "a"; log; int 1; +; dup; int 35; <; bnz loop;`,
			errContains: "too many log calls",
			runMode:     modeApp,
		},
		{
			source:      fmt.Sprintf(`int 1; loop: byte "%s"; log; int 1; +; dup; int 6; <; bnz loop;`, strings.Repeat(`a`, 400)),
			errContains: fmt.Sprintf(">  %d bytes limit", maxLogSize),
			runMode:     modeApp,
		},
		{
			source:      `load 0; log`,
			errContains: "log arg 0 wanted []byte but got uint64",
			runMode:     modeApp,
		},
		{
			source:      `byte  "a logging message"; log; int 1`,
			errContains: "log not allowed in current mode",
			runMode:     modeSig,
		},
	}

	for _, c := range failCases {
		switch c.runMode {
		case modeApp:
			testApp(t, c.source, ep, c.errContains)
		default:
			testLogic(t, c.source, AssemblerMaxVersion, ep, c.errContains, c.errContains)
		}
	}
}

func TestPcDetails(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	var tests = []struct {
		source string
		pc     int
		det    string
	}{
		{"int 1; int 2; -", 5, "pushint 1\npushint 2\n-\n"},
		{"int 1; err", 3, "pushint 1\nerr\n"},
		{"int 1; dup; int 2; -; +", 6, "dup\npushint 2\n-\n"},
		{"b end; end:", 4, ""},
	}
	for i, test := range tests {
		t.Run(fmt.Sprintf("i=%d", i), func(t *testing.T) {
			ops := testProg(t, test.source, LogicVersion)
			ep, _, _ := makeSampleEnv()
			ep.Trace = &strings.Builder{}

			pass, cx, err := EvalContract(ops.Program, 0, 888, ep)
			require.Error(t, err)
			require.False(t, pass)
			require.NotNil(t, cx) // cx comes back nil if we couldn't even run

			assert.Equal(t, test.pc, cx.pc, ep.Trace.String())

			pc, det := cx.PcDetails()
			assert.Equal(t, test.pc, pc)
			assert.Equal(t, test.det, det)
		})
	}
}

func TestOpBase64Decode(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	testCases := []struct {
		encoded string
		alph    string
		decoded string
		error   string
	}{
		{"TU9CWS1ESUNLOwoKb3IsIFRIRSBXSEFMRS4KCgpCeSBIZXJtYW4gTWVsdmlsbGU=",
			"StdEncoding",
			`MOBY-DICK;

or, THE WHALE.


By Herman Melville`, "",
		},
		{"TU9CWS1ESUNLOwoKb3IsIFRIRSBXSEFMRS4KCgpCeSBIZXJtYW4gTWVsdmlsbGU=",
			"URLEncoding",
			`MOBY-DICK;

or, THE WHALE.


By Herman Melville`, "",
		},

		// Test that a string that doesn't need padding can't have it
		{"cGFk", "StdEncoding", "pad", ""},
		{"cGFk=", "StdEncoding", "pad", "input byte 4"},
		{"cGFk==", "StdEncoding", "pad", "input byte 4"},
		{"cGFk===", "StdEncoding", "pad", "input byte 4"},
		// Ensures that extra padding, even if 0%4
		{"cGFk====", "StdEncoding", "pad", "input byte 4"},

		// Test that padding must be correct or absent
		{"bm9wYWQ=", "StdEncoding", "nopad", ""},
		{"bm9wYWQ", "StdEncoding", "nopad", ""},
		{"bm9wYWQ==", "StdEncoding", "nopad", "illegal"},

		{"YWJjMTIzIT8kKiYoKSctPUB+", "StdEncoding", "abc123!?$*&()'-=@~", ""},
		{"YWJjMTIzIT8kKiYoKSctPUB+", "StdEncoding", "abc123!?$*&()'-=@~", ""},
		{"YWJjMTIzIT8kKiYoKSctPUB-", "URLEncoding", "abc123!?$*&()'-=@~", ""},
		{"YWJjMTIzIT8kKiYoKSctPUB+", "URLEncoding", "", "input byte 23"},
		{"YWJjMTIzIT8kKiYoKSctPUB-", "StdEncoding", "", "input byte 23"},

		// try extra ='s and various whitespace:
		{"", "StdEncoding", "", ""},
		{"", "URLEncoding", "", ""},
		{"=", "StdEncoding", "", "byte 0"},
		{"=", "URLEncoding", "", "byte 0"},
		{" ", "StdEncoding", "", "byte 0"},
		{" ", "URLEncoding", "", "byte 0"},
		{"\t", "StdEncoding", "", "byte 0"},
		{"\t", "URLEncoding", "", "byte 0"},
		{"\r", "StdEncoding", "", ""},
		{"\r", "URLEncoding", "", ""},
		{"\n", "StdEncoding", "", ""},
		{"\n", "URLEncoding", "", ""},

		{"YWJjMTIzIT8kKiYoKSctPUB+\n", "StdEncoding", "abc123!?$*&()'-=@~", ""},
		{"YWJjMTIzIT8kKiYoKSctPUB-\n", "URLEncoding", "abc123!?$*&()'-=@~", ""},
		{"YWJjMTIzIT8kK\riYoKSctPUB+\n", "StdEncoding", "abc123!?$*&()'-=@~", ""},
		{"YWJjMTIzIT8kK\riYoKSctPUB-\n", "URLEncoding", "abc123!?$*&()'-=@~", ""},
		{"\n\rYWJjMTIzIT8\rkKiYoKSctPUB+\n", "StdEncoding", "abc123!?$*&()'-=@~", ""},
		{"\n\rYWJjMTIzIT8\rkKiYoKSctPUB-\n", "URLEncoding", "abc123!?$*&()'-=@~", ""},

		// padding and extra legal whitespace
		{"SQ==", "StdEncoding", "I", ""},
		{"SQ==", "URLEncoding", "I", ""},
		{"\rS\r\nQ=\n=\r\r\n", "StdEncoding", "I", ""},
		{"\rS\r\nQ=\n=\r\r\n", "URLEncoding", "I", ""},

		// If padding is there, it must be correct, but if absent, that's fine.
		{"SQ==", "StdEncoding", "I", ""},
		{"SQ==", "URLEncoding", "I", ""},
		{"S=Q=", "StdEncoding", "", "byte 1"},
		{"S=Q=", "URLEncoding", "", "byte 1"},
		{"=SQ=", "StdEncoding", "", "byte 0"},
		{"=SQ=", "URLEncoding", "", "byte 0"},
		{"SQ", "StdEncoding", "I", ""},
		{"SQ", "URLEncoding", "I", ""},
		{"SQ=", "StdEncoding", "", "byte 3"},
		{"SQ=", "URLEncoding", "", "byte 3"},
		{"SQ===", "StdEncoding", "", "byte 4"},
		{"SQ===", "URLEncoding", "", "byte 4"},

		// Strict decoding. "Y" is normally encoded as "WQ==", as confirmed by the first test
		{"WQ==", "StdEncoding", "Y", ""},
		// When encoding one byte, the Y (90) becomes a 6bit value (the W) and a
		// 2bit value (the first 2 bits of the Q. Q is the 16th b64 digit, it is
		// 0b010000. For encoding Y, only those first two bits matter. In
		// Strict() mode, the rest must be 0s. So using R (0b010001) should
		// fail.
		{"WR==", "StdEncoding", "Y", "byte 2"},
	}

	template := `byte 0x%s; byte 0x%s; base64_decode %s; ==`
	for _, tc := range testCases {
		source := fmt.Sprintf(template, hex.EncodeToString([]byte(tc.decoded)), hex.EncodeToString([]byte(tc.encoded)), tc.alph)
		if tc.error == "" {
			if LogicVersion < fidoVersion {
				testProg(t, source, AssemblerMaxVersion, Expect{0, "unknown opcode..."})
			} else {
				testAccepts(t, source, fidoVersion)
			}
		} else {
			if LogicVersion < fidoVersion {
				testProg(t, source, AssemblerMaxVersion, Expect{0, "unknown opcode..."})
			} else {
				err := testPanics(t, source, fidoVersion)
				require.Error(t, err)
				require.Contains(t, err.Error(), tc.error)
			}
		}
	}
}

func TestBase64CostVariation(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	source := `
byte ""
base64_decode URLEncoding
pop
global OpcodeBudget
int ` + fmt.Sprintf("%d", 20_000-3-1) + ` // base64_decode cost = 1
==
`
	testAccepts(t, source, fidoVersion)

	source = `
byte "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
base64_decode URLEncoding
pop
global OpcodeBudget
int ` + fmt.Sprintf("%d", 20_000-3-5) + ` // base64_decode cost = 5 (64 bytes -> 1 + 64/16)
==
`
	testAccepts(t, source, fidoVersion)

	source = `
byte "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz01234567"
base64_decode URLEncoding
pop
global OpcodeBudget
int ` + fmt.Sprintf("%d", 20_000-3-5) + ` // base64_decode cost = 5 (60 bytes -> 1 + ceil(60/16))
==
`
	testAccepts(t, source, fidoVersion)

	source = `
byte "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_AA=="
base64_decode URLEncoding
pop
global OpcodeBudget
int ` + fmt.Sprintf("%d", 20_000-3-6) + ` // base64_decode cost = 6 (68 bytes -> 1 + ceil(68/16))
==
`
	testAccepts(t, source, fidoVersion)
}

func TestHasDuplicateKeys(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()
	testCases := []struct {
		text []byte
	}{
		{
			text: []byte(`{"key0": "1","key0": "2", "key1":1}`),
		},
		{
			text: []byte(`{"key0": "1","key1": [1], "key0":{"key2": "a"}}`),
		},
	}
	for _, s := range testCases {
		hasDuplicates, _, err := hasDuplicateKeys(s.text)
		require.Nil(t, err)
		require.True(t, hasDuplicates)
	}

	noDuplicates := []struct {
		text []byte
	}{
		{
			text: []byte(`{"key0": "1","key1": "2", "key2":3}`),
		},
		{
			text: []byte(`{"key0": "1","key1": [{"key0":1,"key0":2},{"key0":1,"key0":2}], "key2":{"key5": "a","key5": "b"}}`),
		},
	}
	for _, s := range noDuplicates {
		hasDuplicates, _, err := hasDuplicateKeys(s.text)
		require.Nil(t, err)
		require.False(t, hasDuplicates)
	}
}

func TestOpJSONRef(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	var txn transactions.SignedTxn
	txn.Txn.Type = protocol.ApplicationCallTx
	ledger := NewLedger(nil)
	ledger.NewApp(txn.Txn.Receiver, 0, basics.AppParams{})
	ep := defaultEvalParams(txn)
	ep.Ledger = ledger
	testCases := []struct {
		source             string
		previousVersErrors []Expect
	}{
		{
			source: `byte  "{\"key0\": 0,\"key1\": \"algo\",\"key2\":{\"key3\": \"teal\", \"key4\":3}, \"key5\": 18446744073709551615 }";
			byte "key0";
			json_ref JSONUint64;
			int 0;
			==`,
			previousVersErrors: []Expect{{5, "unknown opcode: json_ref"}},
		},
		{
			source: `byte  "{\"key0\": 0,\"key1\": \"algo\",\"key2\":{\"key3\": \"teal\", \"key4\": 3}, \"key5\": 18446744073709551615 }";
			byte "key5";
			json_ref JSONUint64;
			int 18446744073709551615; //max uint64 value
			==`,
			previousVersErrors: []Expect{{5, "unknown opcode: json_ref"}},
		},
		{
			source: `byte  "{\"key0\": 0,\"key1\": \"algo\",\"key2\":{\"key3\": \"teal\", \"key4\": 3}, \"key5\": 18446744073709551615 }";
			byte "key1";
			json_ref JSONString;
			byte "algo";
			==`,
			previousVersErrors: []Expect{{5, "unknown opcode: json_ref"}},
		},
		{
			source: `byte  "{\"key0\": 0,\"key1\": \"\\u0061\\u006C\\u0067\\u006F\",\"key2\":{\"key3\": \"teal\", \"key4\": 3}, \"key5\": 18446744073709551615 }";
			byte "key1";
			json_ref JSONString;
			byte "algo";
			==`,
			previousVersErrors: []Expect{{5, "unknown opcode: json_ref"}},
		},
		{
			source: `byte  "{\"key0\": 0,\"key1\": \"algo\",\"key2\":{\"key3\": \"teal\", \"key4\": {\"key40\": 10}}, \"key5\": 18446744073709551615 }";
			byte "key2";
			json_ref JSONObject;
			byte "key4";
			json_ref JSONObject;
			byte "key40";
			json_ref JSONUint64
			int 10
			==`,
			previousVersErrors: []Expect{{5, "unknown opcode: json_ref"}, {9, "unknown opcode: json_ref"}},
		},
		{
			source: `byte  "{\"key0\": 0,\"key1\": \"algo\",\"key2\":{\"key3\": \"teal\", \"key4\": {\"key40\": 10}}, \"key5\": 18446744073709551615 }";
			byte "key2";
			json_ref JSONObject;
			byte "key3";
			json_ref JSONString;
			byte "teal"
			==`,
			previousVersErrors: []Expect{{5, "unknown opcode: json_ref"}, {9, "unknown opcode: json_ref"}},
		},
		{
			source: `byte  "{\"key0\": 0,\"key1\": \"algo\",\"key2\":{\"key3\": \"\\"teal\\"\", \"key4\": {\"key40\": 10}}, \"key5\": 18446744073709551615 }";
			byte "key2";
			json_ref JSONObject;
			byte "key3";
			json_ref JSONString;
			byte ""teal"" // quotes match
			==`,
			previousVersErrors: []Expect{{5, "unknown opcode: json_ref"}, {9, "unknown opcode: json_ref"}},
		},
		{
			source: `byte  "{\"key0\": 0,\"key1\": \"algo\",\"key2\":{\"key3\": \" teal \", \"key4\": {\"key40\": 10}}, \"key5\": 18446744073709551615 }";
			byte "key2";
			json_ref JSONObject;
			byte "key3";
			json_ref JSONString;
			byte " teal " // spaces match
			==`,
			previousVersErrors: []Expect{{5, "unknown opcode: json_ref"}, {9, "unknown opcode: json_ref"}},
		},
		{
			source: `byte  "{\"key0\": 0,\"key1\": \"algo\",\"key2\":{\"key3\": \"teal\", \"key4\": {\"key40\": 10, \"key40\": \"10\"}}, \"key5\": 18446744073709551615 }";
			byte "key2";
			json_ref JSONObject;
			byte "key4";
			json_ref JSONObject;
			byte "{\"key40\": 10, \"key40\": \"10\"}"
			==
			`,
			previousVersErrors: []Expect{{5, "unknown opcode: json_ref"}},
		},
		{
			source: `byte  "{\"rawId\": \"responseId\",\"id\": \"0\",\"response\": {\"attestationObject\": \"based64url_encoded_buffer\",\"clientDataJSON\":  \" based64url_encoded_client_data\"},\"getClientExtensionResults\": {},\"type\": \"public-key\"}";
			byte "response";
			json_ref JSONObject;
			byte "{\"attestationObject\": \"based64url_encoded_buffer\",\"clientDataJSON\":  \" based64url_encoded_client_data\"}" // object as it appeared in input
			==`,
			previousVersErrors: []Expect{{5, "unknown opcode: json_ref"}},
		},
		{
			source: `byte  "{\"rawId\": \"responseId\",\"id\": \"0\",\"response\": {\"attestationObject\": \"based64url_encoded_buffer\",\"clientD\\u0061taJSON\":  \" based64url_encoded_client_data\"},\"getClientExtensionResults\": {},\"type\": \"public-key\"}";
			byte "response";
			json_ref JSONObject;
			byte "{\"attestationObject\": \"based64url_encoded_buffer\",\"clientD\\u0061taJSON\":  \" based64url_encoded_client_data\"}" // object as it appeared in input
			==`,
			previousVersErrors: []Expect{{5, "unknown opcode: json_ref"}},
		},
		{
			source: `byte  "{\"rawId\": \"responseId\",\"id\": \"0\",\"response\": {\"attestationObject\": \"based64url_encoded_buffer\",\"clientDataJSON\":  \" based64url_encoded_client_data\"},\"getClientExtensionResults\": {},\"type\": \"public-key\"}";
			byte "response";
			json_ref JSONObject;
			byte "clientDataJSON";
			json_ref JSONString;
			byte " based64url_encoded_client_data";
			==`,
			previousVersErrors: []Expect{{5, "unknown opcode: json_ref"}, {9, "unknown opcode: json_ref"}},
		},
		{
			source: `byte  "{\"\\u0072\\u0061\\u0077\\u0049\\u0044\": \"responseId\",\"id\": \"0\",\"response\": {\"attestationObject\": \"based64url_encoded_buffer\",\"clientDataJSON\":  \" based64url_encoded_client_data\"},\"getClientExtensionResults\": {},\"type\": \"public-key\"}";
			byte "rawID";
			json_ref JSONString;
			byte "responseId"
			==`,
			previousVersErrors: []Expect{{5, "unknown opcode: json_ref"}},
		},
	}

	for _, s := range testCases {
		for v := uint64(2); v < fidoVersion; v++ {
			expectedErrs := s.previousVersErrors
			if fidoVersion <= AssemblerMaxVersion {
				for i := range expectedErrs {
					if strings.Contains(expectedErrs[i].s, "json_ref") {
						expectedErrs[i].s = fmt.Sprintf("json_ref opcode was introduced in TEAL v%d", fidoVersion)
					}
				}
			}
			testProg(t, s.source, v, expectedErrs...)
		}
		if fidoVersion > AssemblerMaxVersion {
			continue
		}
		ops := testProg(t, s.source, AssemblerMaxVersion)

		err := CheckContract(ops.Program, ep)
		require.NoError(t, err, s)

		pass, _, err := EvalContract(ops.Program, 0, 888, ep)
		require.NoError(t, err)
		require.True(t, pass)
	}

	failedCases := []struct {
		source             string
		error              string
		previousVersErrors []Expect
	}{
		{
			source:             `byte  "{\"key0\": 1 }"; byte "key0"; json_ref JSONString;`,
			error:              "json: cannot unmarshal number into Go value of type string",
			previousVersErrors: []Expect{{3, "unknown opcode: json_ref"}},
		},
		{
			source:             `byte  "{\"key0\": [1] }"; byte "key0"; json_ref JSONString;`,
			error:              "json: cannot unmarshal array into Go value of type string",
			previousVersErrors: []Expect{{3, "unknown opcode: json_ref"}},
		},
		{
			source:             `byte  "{\"key0\": {\"key1\":1} }"; byte "key0"; json_ref JSONString;`,
			error:              "json: cannot unmarshal object into Go value of type string",
			previousVersErrors: []Expect{{3, "unknown opcode: json_ref"}},
		},
		{
			source:             `byte  "{\"key0\": \"1\" }"; byte "key0"; json_ref JSONUint64;`,
			error:              "json: cannot unmarshal string into Go value of type uint64",
			previousVersErrors: []Expect{{3, "unknown opcode: json_ref"}},
		},
		{
			source:             `byte  "{\"key0\": [\"1\"] }"; byte "key0"; json_ref JSONUint64;`,
			error:              "json: cannot unmarshal array into Go value of type uint64",
			previousVersErrors: []Expect{{3, "unknown opcode: json_ref"}},
		},
		{
			source:             `byte  "{\"key0\": {\"key1\":1} }"; byte "key0"; json_ref JSONUint64;`,
			error:              "json: cannot unmarshal object into Go value of type uint64",
			previousVersErrors: []Expect{{3, "unknown opcode: json_ref"}},
		},
		{
			source:             `byte  "{\"key0\": [1]}"; byte "key0"; json_ref JSONObject;`,
			error:              "json: cannot unmarshal array into Go value of type map[string]json.RawMessage",
			previousVersErrors: []Expect{{3, "unknown opcode: json_ref"}},
		},
		{
			source:             `byte  "{\"key0\": 1}"; byte "key0"; json_ref JSONObject;`,
			error:              "json: cannot unmarshal number into Go value of type map[string]json.RawMessage",
			previousVersErrors: []Expect{{3, "unknown opcode: json_ref"}},
		},
		{
			source:             `byte  "{\"key0\": \"1\"}"; byte "key0"; json_ref JSONObject;`,
			error:              "json: cannot unmarshal string into Go value of type map[string]json.RawMessage",
			previousVersErrors: []Expect{{3, "unknown opcode: json_ref"}},
		},
		{
			source:             `byte  "{\"key0\": 1,\"key1\": \"algo\",\"key2\":{\"key3\": \"teal\", \"key4\": [1,2,3]} }"; byte "key3"; json_ref JSONString;`,
			error:              "key key3 not found in JSON text",
			previousVersErrors: []Expect{{3, "unknown opcode: json_ref"}},
		},
		{
			source: `byte  "{\"key0\": 1,\"key1\": \"algo\",\"key2\":{\"key3\": \"teal\", \"key4\": [1,2,3]}}";
			byte "key2";
			json_ref JSONObject;
			byte "key5";
			json_ref JSONString
			`,
			error:              "key key5 not found in JSON text",
			previousVersErrors: []Expect{{5, "unknown opcode: json_ref"}, {9, "unknown opcode: json_ref"}},
		},
		{
			source:             `byte  "{\"key0\": -0,\"key1\": 2.5,\"key2\": -3}"; byte "key0"; json_ref JSONUint64;`,
			error:              "json: cannot unmarshal number -0 into Go value of type uint64",
			previousVersErrors: []Expect{{3, "unknown opcode: json_ref"}},
		},
		{
			source:             `byte  "{\"key0\": 1e10,\"key1\": 2.5,\"key2\": -3}"; byte "key0"; json_ref JSONUint64;`,
			error:              "json: cannot unmarshal number 1e10 into Go value of type uint64",
			previousVersErrors: []Expect{{3, "unknown opcode: json_ref"}},
		},
		{
			source:             `byte  "{\"key0\": 0.2e-2,\"key1\": 2.5,\"key2\": -3}"; byte "key0"; json_ref JSONUint64;`,
			error:              "json: cannot unmarshal number 0.2e-2 into Go value of type uint64",
			previousVersErrors: []Expect{{3, "unknown opcode: json_ref"}},
		},
		{
			source:             `byte  "{\"key0\": 1.0,\"key1\": 2.5,\"key2\": -3}"; byte "key0"; json_ref JSONUint64;`,
			error:              "json: cannot unmarshal number 1.0 into Go value of type uint64",
			previousVersErrors: []Expect{{3, "unknown opcode: json_ref"}},
		},
		{
			source:             `byte  "{\"key0\": 1.0,\"key1\": 2.5,\"key2\": -3}"; byte "key1"; json_ref JSONUint64;`,
			error:              "json: cannot unmarshal number 2.5 into Go value of type uint64",
			previousVersErrors: []Expect{{3, "unknown opcode: json_ref"}},
		},
		{
			source:             `byte  "{\"key0\": 1.0,\"key1\": 2.5,\"key2\": -3}"; byte "key2"; json_ref JSONUint64;`,
			error:              "json: cannot unmarshal number -3 into Go value of type uint64",
			previousVersErrors: []Expect{{3, "unknown opcode: json_ref"}},
		},
		{
			source:             `byte  "{\"key0\": 18446744073709551616}"; byte "key0"; json_ref JSONUint64;`,
			error:              "json: cannot unmarshal number 18446744073709551616 into Go value of type uint64",
			previousVersErrors: []Expect{{3, "unknown opcode: json_ref"}},
		},
		{
			source:             `byte  "{\"key0\": 1,}"; byte "key0"; json_ref JSONString;`,
			error:              "error while parsing JSON text, invalid json text",
			previousVersErrors: []Expect{{3, "unknown opcode: json_ref"}},
		},
		{
			source:             `byte  "{\"key0\": 1, \"key0\": \"3\"}"; byte "key0"; json_ref JSONString;`,
			error:              "error while parsing JSON text, invalid json text, duplicate keys not allowed",
			previousVersErrors: []Expect{{3, "unknown opcode: json_ref"}},
		},
		{
			source: `byte  "{\"key0\": 0,\"key1\": \"algo\",\"key2\":{\"key3\": \"teal\", \"key4\": {\"key40\": 10, \"key40\": \"should fail!\"}}}";
			byte "key2";
			json_ref JSONObject;
			byte "key4";
			json_ref JSONObject;
			byte "key40"
			json_ref JSONString
			`,
			error:              "error while parsing JSON text, invalid json text, duplicate keys not allowed",
			previousVersErrors: []Expect{{5, "unknown opcode: json_ref"}, {9, "unknown opcode: json_ref"}, {12, "unknown opcode: json_ref"}},
		},
		{
			source: `byte  "[1,2,3]";
			byte "key";
			json_ref JSONUint64
			`,
			error:              "error while parsing JSON text, invalid json text, only json object is allowed",
			previousVersErrors: []Expect{{5, "unknown opcode: json_ref"}},
		},
		{
			source: `byte  "2";
			byte "key";
			json_ref JSONUint64
			`,
			error:              "error while parsing JSON text, invalid json text, only json object is allowed",
			previousVersErrors: []Expect{{5, "unknown opcode: json_ref"}},
		},
		{
			source: `byte  "null";
			byte "key";
			json_ref JSONUint64
			`,
			error:              "error while parsing JSON text, invalid json text, only json object is allowed",
			previousVersErrors: []Expect{{5, "unknown opcode: json_ref"}},
		},
		{
			source: `byte  "true";
			byte "key";
			json_ref JSONUint64
			`,
			error:              "error while parsing JSON text, invalid json text, only json object is allowed",
			previousVersErrors: []Expect{{5, "unknown opcode: json_ref"}},
		},
		{
			source: `byte  "\"sometext\"";
			byte "key";
			json_ref JSONUint64
			`,
			error:              "error while parsing JSON text, invalid json text, only json object is allowed",
			previousVersErrors: []Expect{{5, "unknown opcode: json_ref"}},
		},
	}

	for _, s := range failedCases {
		for v := uint64(2); v < fidoVersion; v++ {
			expectedErrs := s.previousVersErrors
			if fidoVersion <= AssemblerMaxVersion {
				for i := range expectedErrs {
					if strings.Contains(expectedErrs[i].s, "json_ref") {
						expectedErrs[i].s = fmt.Sprintf("json_ref opcode was introduced in TEAL v%d", fidoVersion)
					}
				}
			}

			testProg(t, s.source, v, expectedErrs...)
		}
		if fidoVersion > AssemblerMaxVersion {
			continue
		}

		ops := testProg(t, s.source, AssemblerMaxVersion)

		err := CheckContract(ops.Program, ep)
		require.NoError(t, err, s)

		pass, _, err := EvalContract(ops.Program, 0, 888, ep)
		require.False(t, pass)
		require.Error(t, err)
		require.EqualError(t, err, s.error)
	}

}

func TestTypeComplaints(t *testing.T) {
	testProg(t, "err; store 0", AssemblerMaxVersion)
	testProg(t, "int 1; return; store 0", AssemblerMaxVersion)
}
