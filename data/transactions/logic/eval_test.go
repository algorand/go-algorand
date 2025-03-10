// Copyright (C) 2019-2025 Algorand, Inc.
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
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"math"
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

	"pgregory.net/rapid"
)

type protoOpt func(*config.ConsensusParams)

func protoVer(version uint64) protoOpt {
	return func(p *config.ConsensusParams) {
		p.LogicSigVersion = version
		p.Application = version >= appsEnabledVersion
	}
}

var testLogicBudget = 25_000 // In a var so that we can temporarily change it

func makeTestProtoV(version uint64) *config.ConsensusParams {
	return makeTestProto(protoVer(version))
}

func makeTestProto(opts ...protoOpt) *config.ConsensusParams {
	p := config.ConsensusParams{
		LogicSigVersion:   LogicVersion,
		Application:       true,
		LogicSigMaxCost:   uint64(testLogicBudget),
		MaxAppProgramCost: 700,

		MaxAppKeyLen:          64,
		MaxAppBytesValueLen:   64,
		MaxAppSumKeyValueLens: 128,

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
		MaxAppBoxReferences:      2,
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

		EnableAppCostPooling:      true,
		EnableLogicSigCostPooling: true,

		EnableInnerTransactionPooling: true,
		MinInnerApplVersion:           4,

		SupportBecomeNonParticipatingTransactions: true,

		UnifyInnerTxIDs: true,

		MaxBoxSize:           1000,
		BytesPerBoxReference: 100,

		Payouts: config.ProposerPayoutRules{
			Enabled:     true,
			GoOnlineFee: 3,
			Percent:     4,
			MinBalance:  5,
			MaxBalance:  6,
		},
	}
	for _, opt := range opts {
		if opt != nil { // so some callsites can take one arg and pass it in
			opt(&p)
		}
	}
	return &p
}

func benchmarkSigParams(txns ...transactions.SignedTxn) *EvalParams {
	ep := optSigParams(func(p *config.ConsensusParams) {
		p.LogicSigMaxCost = 1_000_000_000
	}, txns...)
	ep.Trace = nil // Tracing would slow down benchmarks
	return ep
}

func defaultSigParams(txns ...transactions.SignedTxn) *EvalParams {
	return optSigParams(nil, txns...)
}
func defaultSigParamsWithVersion(version uint64, txns ...transactions.SignedTxn) *EvalParams {
	return optSigParams(protoVer(version), txns...)
}
func optSigParams(opt protoOpt, txns ...transactions.SignedTxn) *EvalParams {
	if len(txns) == 0 {
		// We need a transaction to exist, because we'll be stuffing the
		// logicsig into it in order to test them.
		txns = make([]transactions.SignedTxn, 1)
	}
	// Make it non-Blank so NewSigEval does not short-circuit (but try to avoid
	// manipulating txns if they were actually supplied with other sigs.)
	if txns[0].Sig.Blank() && txns[0].Msig.Blank() && txns[0].Lsig.Blank() {
		txns[0].Lsig.Logic = []byte{LogicVersion + 1} // make sure it fails if used
	}

	ep := NewSigEvalParams(txns, makeTestProto(opt), &NoHeaderLedger{})
	ep.Trace = &strings.Builder{}
	return ep
}

func defaultAppParams(txns ...transactions.SignedTxn) *EvalParams {
	return defaultAppParamsWithVersion(LogicVersion, txns...)
}
func defaultAppParamsWithVersion(version uint64, txns ...transactions.SignedTxn) *EvalParams {
	if len(txns) == 0 {
		// Convince NewAppEvalParams not to return nil
		txns = []transactions.SignedTxn{{
			Txn: transactions.Transaction{Type: protocol.ApplicationCallTx},
		}}
	}
	ep := NewAppEvalParams(transactions.WrapSignedTxnsWithAD(txns), makeTestProtoV(version), &transactions.SpecialAddresses{})
	if ep != nil { // If supplied no apps, ep is nil.
		ep.Trace = &strings.Builder{}
		ledger := NewLedger(nil)
		ep.Ledger = ledger
		ep.SigLedger = ledger
	}
	return ep
}

func defaultEvalParams(txns ...transactions.SignedTxn) (sig *EvalParams, app *EvalParams) {
	return defaultEvalParamsWithVersion(LogicVersion, txns...)
}
func defaultEvalParamsWithVersion(version uint64, txns ...transactions.SignedTxn) (sig *EvalParams, app *EvalParams) {
	sig = defaultSigParamsWithVersion(version, txns...)
	app = defaultAppParamsWithVersion(version, txns...)
	// Let's share ledgers for easier testing and let sigs use it for block access
	if app != nil {
		sig.SigLedger = app.SigLedger
	}
	return sig, app
}

// reset puts an ep back into its original state.  This is in *_test.go because
// no real code should ever need this. EvalParams should be created to evaluate
// a group, and then thrown away.
func (ep *EvalParams) reset() {
	switch ep.runMode {
	case ModeSig:
		if ep.Proto.EnableLogicSigCostPooling {
			budget := int(ep.Proto.LogicSigMaxCost) * len(ep.TxnGroup)
			ep.PooledLogicSigBudget = &budget
		}
	case ModeApp:
		if ep.Proto.EnableAppCostPooling {
			budget := ep.Proto.MaxAppProgramCost
			ep.PooledApplicationBudget = &budget
		}
		if ep.Proto.EnableInnerTransactionPooling {
			inners := ep.Proto.MaxTxGroupSize * ep.Proto.MaxInnerTransactions
			ep.pooledAllowedInners = &inners
		}
		ep.pastScratch = [maxTxGroupSize]*scratchSpace{}
		for i := range ep.TxnGroup {
			ep.TxnGroup[i].ApplyData = transactions.ApplyData{}
		}
		ep.available = nil
		ep.readBudgetChecked = false
		ep.appAddrCache = make(map[basics.AppIndex]basics.Address)
		if ep.Trace != nil {
			ep.Trace = &strings.Builder{}
		}
		ep.txidCache = nil
		ep.innerTxidCache = nil
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
			pass, err := EvalSignature(0, defaultSigParams(txn))
			require.Error(t, err)
			require.False(t, pass)
		})
	}
}

func TestArgTooLarge(t *testing.T) {
	partitiontest.PartitionTest(t)

	t.Parallel()
	for v := uint64(1); v <= AssemblerMaxVersion; v++ {
		t.Run(fmt.Sprintf("v=%d", v), func(t *testing.T) {
			ops := testProg(t, "int 1", v)
			var txn transactions.SignedTxn
			txn.Lsig.Logic = ops.Program
			txn.Lsig.Args = [][]byte{make([]byte, transactions.MaxLogicSigArgSize+1)}
			pass, err := EvalSignature(0, defaultSigParams(txn))
			require.Error(t, err)
			require.False(t, pass)
		})
	}

}

func TestEmptyProgram(t *testing.T) {
	partitiontest.PartitionTest(t)

	t.Parallel()
	testLogicBytes(t, nil, nil, "invalid", "invalid program (empty)")
}

// TestMinAvmVersionParamEval tests eval/check reading the minAvmVersion from the param
func TestMinAvmVersionParamEvalCheckSignature(t *testing.T) {
	partitiontest.PartitionTest(t)

	t.Parallel()
	params := defaultSigParams()
	params.minAvmVersion = uint64(rekeyingEnabledVersion)
	program := make([]byte, binary.MaxVarintLen64)
	// set the program version to 1
	binary.PutUvarint(program, 1)

	verErr := fmt.Sprintf("program version must be >= %d", appsEnabledVersion)
	testLogicBytes(t, program, params, verErr, verErr)
}

func TestTxnFieldToTealValue(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

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

func TestTxnFirstValidTime(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	ep, tx, ledger := makeSampleEnv()
	// This is an unusual test that needs a ledger
	// even though it's testing signatures. So it's convenient to use
	// makeSampleEnv and then change the mode on the ep.
	ep.runMode = ModeSig

	// By default, test ledger uses an oddball round, ask it what round it's
	// going to use and prep fv, lv accordingly.
	current := ledger.Round()

	// txn FirstValidTime is unusual.  It's not really a field of a txn, but
	// since it looks at the past of the blockchain, it is "stateless"

	// Kill off ep.Ledger, to confirm it's not being used
	ep.Ledger = nil

	tx.FirstValid = current - 10
	tx.LastValid = current + 10
	testLogic(t, "txn FirstValidTime", 7, ep)

	tx.FirstValid = current
	testLogic(t, "txn FirstValidTime", 7, ep)

	tx.FirstValid = current - basics.Round(ep.Proto.MaxTxnLife)
	tx.LastValid = current
	testLogic(t, "txn FirstValidTime", 7, ep)

	// This test isn't really even possible because lifetime is too big. But
	// nothing here checks that, so we can write this imposible test.
	tx.FirstValid = current - basics.Round(ep.Proto.MaxTxnLife)
	tx.LastValid = current + 1
	testLogic(t, "txn FirstValidTime", 7, ep, "is not available")

	// But also test behavior at the beginning of chain's life by setting the
	// fake ledger round to a low number.
	ledger.rnd = 10
	tx.FirstValid = 2
	tx.LastValid = 100
	testLogic(t, "txn FirstValidTime; int 104; ==", 7, ep)

	tx.FirstValid = 3
	testLogic(t, "txn FirstValidTime; int 109; ==", 7, ep)

	// This ensure 0 is not available, even though it "should" be allowed by the
	// range check. round 0 doesn't exist!
	tx.FirstValid = 1
	testLogic(t, "txn FirstValidTime", 7, ep, "round 0 is not available")

	// glassbox test - we know available range depends on LastValid - Lifetime - 1
	tx.FirstValid = 1
	tx.LastValid = tx.FirstValid + basics.Round(ep.Proto.MaxTxnLife)
	testLogic(t, "txn FirstValidTime", 7, ep, "round 0 is not available")

	// Same, for even weirder case of asking for a wraparound, high round
	tx.FirstValid = 0 // I *guess* this is a legal txn early in chain's life
	testLogic(t, "txn FirstValidTime; int 4; ==", 7, ep, "round 18446744073709551615 is not available")
}

func TestWrongProtoVersion(t *testing.T) {
	partitiontest.PartitionTest(t)

	t.Parallel()
	for v := uint64(1); v <= AssemblerMaxVersion; v++ {
		t.Run(fmt.Sprintf("v=%d", v), func(t *testing.T) {
			ops := testProg(t, "int 1", v)
			ep := defaultSigParamsWithVersion(0)
			testLogicBytes(t, ops.Program, ep, "LogicSig not supported", "LogicSig not supported")
		})
	}
}

// TestBlankStackSufficient will fail if an opcode is added with more than the
// current max number of stack arguments. Update `blankStack` to be longer.
func TestBlankStackSufficient(t *testing.T) {
	partitiontest.PartitionTest(t)

	t.Parallel()
	for v := 0; v <= LogicVersion; v++ {
		t.Run(fmt.Sprintf("v=%d", v), func(t *testing.T) {
			for i := 0; i < 256; i++ {
				spec := opsByOpcode[v][i]
				argLen := len(spec.Arg.Types)
				blankStackLen := len(blankStack)
				require.GreaterOrEqual(t, blankStackLen, argLen, spec.Name)
			}
		})
	}
}

func TestSimpleMath(t *testing.T) {
	partitiontest.PartitionTest(t)

	t.Parallel()
	testAccepts(t, "int  2; int 3; + ; int  5; ==", 1)
	testAccepts(t, "int 22; int 3; - ; int 19; ==", 1)
	testAccepts(t, "int  8; int 7; * ; int 56; ==", 1)
	testAccepts(t, "int 21; int 7; / ; int  3; ==", 1)

	testPanics(t, "int 1; int 2; - ; int 0; ==", 1)

	testCost(t, "int 1; int 2; + ; int 3; ==", 5, 6)
}

// TestRapidMath uses rapid.Check to be a bit more exhaustive
func TestRapidMath(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	rapid.Check(t, func(r *rapid.T) {
		a := rapid.Uint64().Draw(r, "a")
		b := rapid.Uint64().Draw(r, "b")
		sum := a + b
		test := fmt.Sprintf("int %d; int %d; +; int %d; ==", a, b, sum)
		if sum < a {
			testPanics(t, test, 1)
		} else {
			testAccepts(t, test, 1)
		}

		diff := a - b
		test = fmt.Sprintf("int %d; int %d; -; int %d; ==", a, b, diff)
		if a < b {
			testPanics(t, test, 1)
		} else {
			testAccepts(t, test, 1)
		}

	})
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
			ep := defaultSigParams(txn)
			err := CheckSignature(0, ep)
			require.NoError(t, err)
			pass, cx, err := EvalSignatureFull(0, ep)
			require.True(t, pass)
			require.NoError(t, err)
			require.Greater(t, cx.Cost(), 0)
		})
	}
}

func TestBranchEnd(t *testing.T) {
	partitiontest.PartitionTest(t)

	t.Parallel()
	for v := uint64(2); v <= AssemblerMaxVersion; v++ {
		t.Run(fmt.Sprintf("v=%d", v), func(t *testing.T) {
			ops := testProg(t, `int 1
b end
end:
`, v)
			var txn transactions.SignedTxn
			txn.Lsig.Logic = ops.Program
			err := CheckSignature(0, defaultSigParams(txn))
			require.NoError(t, err)
		})
	}
	for v := uint64(2); v <= AssemblerMaxVersion; v++ {
		t.Run(fmt.Sprintf("v=%d", v), func(t *testing.T) {
			ops := testProg(t, `int 1
return
`, v)
			var txn transactions.SignedTxn
			txn.Lsig.Logic = ops.Program
			ep := defaultSigParams(txn)
			err := CheckSignature(0, ep)
			require.NoError(t, err)
		})
	}

	// now craft pushint \x01 + cut program and ensure the checker does not fail
	// this \x01 varint value forces nextpc=3 with program length=3
	pushint := OpsByName[LogicVersion]["pushint"]
	var txn transactions.SignedTxn
	txn.Lsig.Logic = []byte{LogicVersion, pushint.Opcode, 0x01}
	err := CheckSignature(0, defaultSigParams(txn))
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
			ep := defaultSigParams(txn)
			err := CheckSignature(0, ep)
			if err != nil {
				t.Log(hex.EncodeToString(ops.Program))
				t.Log(ep.Trace.String())
			}
			require.NoError(t, err)
			pass, cx, err := EvalSignatureFull(0, ep)
			if pass {
				t.Log(hex.EncodeToString(ops.Program))
				t.Log(ep.Trace.String())
				require.Greater(t, cx.cost, 0)
				require.Greater(t, cx.Cost(), 0)
			}
			require.False(t, pass)
			isNotPanic(t, err)

			txn.Txn.Receiver = a2
			txn.Txn.CloseRemainderTo = a2
			ep = defaultSigParams(txn)
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
			ep = defaultSigParams(txn)
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
			ep = defaultSigParams(txn)
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
			ep = defaultSigParams(txn)
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
	testProg(t, code, LogicVersion, exp(12, "+ expects 2 stack arguments..."))
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
	testPanics(t, "intc_1", 1, "intc 1 beyond 0 constants")
	testPanics(t, "intcblock 7; intc_1; pop", 1, "intc 1 beyond 1 constants")
}

func TestBytecTooFar(t *testing.T) {
	partitiontest.PartitionTest(t)

	t.Parallel()
	testPanics(t, "bytec_1; btoi", 1, "bytec 1 beyond 0 constants")
	testPanics(t, "bytecblock 0x23 0x45; bytec_2; btoi", 1, "bytec 2 beyond 2 constants")
}

func TestManualCBlockEval(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	// TestManualCBlock in assembler_test.go demonstrates that these will use
	// an inserted constant block because the blocks given are in dead code.
	testAccepts(t, "int 4; int 4; +; int 8; ==; return; intcblock 10", 2)
	testAccepts(t, "b skip; intcblock 10; skip: int 4; int 4; +; int 8; ==;", 2)
	testAccepts(t, "byte 0x2222; byte 0x2222; concat; len; int 4; ==; return; bytecblock 0x11", 2)
	testAccepts(t, "b skip; bytecblock 0x11; skip: byte 0x2222; byte 0x2222; concat; len; int 4; ==", 2)
}

func TestTxnBadField(t *testing.T) {
	partitiontest.PartitionTest(t)

	t.Parallel()
	program := []byte{0x01, 0x31, 0x7f}
	testLogicBytes(t, program, nil, "invalid txn field")
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
		testLogicBytes(t, ops.Program, nil, fmt.Sprintf("invalid txn field %s", field))
	}
}

func TestGtxnBadIndex(t *testing.T) {
	partitiontest.PartitionTest(t)

	t.Parallel()
	program := []byte{0x01, 0x33, 0x1, 0x01}
	testLogicBytes(t, program, nil, "txn index 1")
}

func TestGtxnBadField(t *testing.T) {
	partitiontest.PartitionTest(t)

	t.Parallel()
	program := []byte{0x01, 0x33, 0x0, 127}
	// TODO: Check should know the type stack was wrong
	testLogicBytes(t, program, nil, "invalid txn field TxnField(127)")

	// test gtxn does not accept ApplicationArgs and Accounts
	txnOpcode := OpsByName[LogicVersion]["txn"].Opcode
	txnaOpcode := OpsByName[LogicVersion]["txna"].Opcode

	fields := []TxnField{ApplicationArgs, Accounts}
	for _, field := range fields {
		source := fmt.Sprintf("txn %s 0", field.String())
		ops := testProg(t, source, AssemblerMaxVersion)
		require.Equal(t, txnaOpcode, ops.Program[1])
		ops.Program[1] = txnOpcode
		testLogicBytes(t, ops.Program, nil, fmt.Sprintf("invalid txn field %s", field))
	}
}

func TestGlobalBadField(t *testing.T) {
	partitiontest.PartitionTest(t)

	t.Parallel()
	program := []byte{0x01, 0x32, 127}
	testLogicBytes(t, program, nil, "invalid global field")
}

func TestArg(t *testing.T) {
	partitiontest.PartitionTest(t)

	t.Parallel()
	for v := uint64(1); v <= AssemblerMaxVersion; v++ {
		t.Run(fmt.Sprintf("v=%d", v), func(t *testing.T) {
			source := "arg 0; arg 1; ==; arg 2; arg 3; !=; &&; arg 4; len; int 9; <; &&; "
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
			testLogicBytes(t, ops.Program, defaultSigParams(txn))
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
addr ` + testAppCreator + `
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

const globalV8TestProgram = globalV7TestProgram + `
// No new globals in v8
`

const globalV9TestProgram = globalV8TestProgram + `
// No new globals in v9
`

const globalV10TestProgram = globalV9TestProgram + `
global AssetCreateMinBalance; int 1001; ==; &&
global AssetOptInMinBalance; int 1001; ==; &&
global GenesisHash; len; int 32; ==; &&
`

const globalV11TestProgram = globalV10TestProgram + `
global PayoutsEnabled; assert
global PayoutsGoOnlineFee; int 3; ==; assert
global PayoutsPercent; int 4; ==; assert
global PayoutsMinBalance; int 5; ==; assert
global PayoutsMaxBalance; int 6; ==; assert
`
const globalV12TestProgram = globalV11TestProgram + `
`

func TestAllGlobals(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	type desc struct {
		lastField GlobalField
		program   string
	}
	// Associate the highest allowed global constant with each version's test program
	tests := map[uint64]desc{
		0:  {GroupSize, globalV1TestProgram},
		1:  {GroupSize, globalV1TestProgram},
		2:  {CurrentApplicationID, globalV2TestProgram},
		3:  {CreatorAddress, globalV3TestProgram},
		4:  {CreatorAddress, globalV4TestProgram},
		5:  {GroupID, globalV5TestProgram},
		6:  {CallerApplicationAddress, globalV6TestProgram},
		7:  {CallerApplicationAddress, globalV7TestProgram},
		8:  {CallerApplicationAddress, globalV8TestProgram},
		9:  {CallerApplicationAddress, globalV9TestProgram},
		10: {GenesisHash, globalV10TestProgram},
		11: {PayoutsMaxBalance, globalV11TestProgram},
		12: {PayoutsMaxBalance, globalV12TestProgram},
	}
	// tests keys are versions so they must be in a range 1..AssemblerMaxVersion plus zero version
	require.LessOrEqual(t, len(tests), AssemblerMaxVersion+1)
	require.Len(t, globalFieldSpecs, int(invalidGlobalField))

	// ensure we are testing everything
	require.Equal(t, tests[AssemblerMaxVersion].lastField, invalidGlobalField-1,
		"did you add a new global field?")

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

			appcall := transactions.SignedTxn{
				Txn: transactions.Transaction{
					Type: protocol.ApplicationCallTx,
				},
			}
			appcall.Txn.Group = crypto.Digest{0x07, 0x06}

			ep := defaultAppParams(appcall)
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
						testLogicBytes(t, ops.Program, defaultSigParams(txn),
							"program version must be", "program version must be")
						return
					}
					testLogicBytes(t, ops.Program, defaultSigParams(txn))
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

const testTxnProgramTextV7 = testTxnProgramTextV6 + `
assert

txn NumApprovalProgramPages
int 1
==
assert

txna ApprovalProgramPages 0
txn ApprovalProgram
==
assert

txn NumClearStateProgramPages
int 1
==
assert

txna ClearStateProgramPages 0
txn ClearStateProgram
==
assert

txn FirstValidTime
int 0
>
assert

int 1
`

const testTxnProgramTextV8 = testTxnProgramTextV7 + `
assert
// though box refs introduced in v8, they are not exposed to AVM (yet?)
int 1
`

const testTxnProgramTextV9 = testTxnProgramTextV8 + `
assert
int 1
`
const testTxnProgramTextV10 = testTxnProgramTextV9 + `
assert
int 1
`

const testTxnProgramTextV11 = testTxnProgramTextV10 + `
assert
int 1
`

const testTxnProgramTextV12 = testTxnProgramTextV11 + `
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
	txn.Txn.Boxes = []transactions.BoxRef{{Index: 0, Name: []byte("self")}, {Index: 0, Name: []byte("other")}}
	txn.Txn.GlobalStateSchema = basics.StateSchema{NumUint: 3, NumByteSlice: 0}
	txn.Txn.LocalStateSchema = basics.StateSchema{NumUint: 1, NumByteSlice: 2}
	return txn
}

func makeSampleAppl(app basics.AppIndex) transactions.SignedTxn {
	sample := makeSampleTxn()
	sample.Txn.Type = protocol.ApplicationCallTx
	sample.Txn.ApplicationID = app
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
		1:  testTxnProgramTextV1,
		2:  testTxnProgramTextV2,
		3:  testTxnProgramTextV3,
		4:  testTxnProgramTextV4,
		5:  testTxnProgramTextV5,
		6:  testTxnProgramTextV6,
		7:  testTxnProgramTextV7,
		8:  testTxnProgramTextV8,
		9:  testTxnProgramTextV9,
		10: testTxnProgramTextV10,
		11: testTxnProgramTextV11,
		12: testTxnProgramTextV12,
	}

	for i, txnField := range TxnFieldNames {
		fs := txnFieldSpecs[i]
		// Ensure that each field appears, starting in the version it was introduced
		for v := uint64(1); v <= uint64(LogicVersion); v++ {
			if v < fs.version {
				continue
			}
			if !strings.Contains(tests[v], txnField) {
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
			t.Parallel()
			ops := testProg(t, source, v)
			txn := makeSampleTxn()
			if v >= appsEnabledVersion {
				txn.Txn.Type = protocol.ApplicationCallTx
			}
			txn.Txn.ApprovalProgram = ops.Program
			txn.Txn.ClearStateProgram = clearOps.Program
			txn.Txn.ExtraProgramPages = 2
			// RekeyTo not allowed in v1
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
			sep, aep := defaultEvalParams(txn, txn, txn, txn)
			if v < txnEffectsVersion {
				testLogicFull(t, ops.Program, 3, sep)
			} else {
				// Starting in txnEffectsVersion, there are fields we can't access in Logic mode
				testLogicFull(t, ops.Program, 3, sep, "not allowed in current mode")
				// And the early tests use "arg" a lot - not allowed in stateful. So remove those tests.
				lastArg := strings.Index(source, "arg 10\n==\n&&")
				require.NotEqual(t, -1, lastArg)
				source = source[lastArg+12:]

				aep.TxnGroup[2].EvalDelta.Logs = []string{"x", "prefilled"} // allows gtxn 2 NumLogs
				appSafe := "int 1" + strings.Replace(source, `txn Sender
int 0
args
==
assert`, "", 1)

				ops := testProg(t, appSafe, v)
				testAppFull(t, ops.Program, 3, basics.AppIndex(888), aep)
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

	ep := defaultSigParams(makeSampleTxnGroup()...)
	txid0 := ep.TxnGroup[0].ID()
	txid1 := ep.TxnGroup[1].ID()
	ep.TxnGroup[0].Lsig.Args = [][]byte{
		txid0[:],
		txid1[:],
	}
	testLogicBytes(t, ops.Program, ep)
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
			t.Parallel()
			txn := makeSampleTxn()
			// RekeyTo not allowed in v1
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
			ep := defaultSigParams(makeSampleTxnGroup(txn)...)
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
	if ep == nil {
		ep = defaultSigParams()
	} else {
		ep.reset()
	}
	testLogicFull(t, program, 0, ep, problems...)
}

// testLogicFull is the lowest-level so it does not create an ep or reset it.
func testLogicFull(t *testing.T, program []byte, gi int, ep *EvalParams, problems ...string) error {
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

	ep.Trace = &strings.Builder{}

	ep.TxnGroup[gi].Lsig.Logic = program
	err := CheckSignature(gi, ep)
	if checkProblem == "" {
		require.NoError(t, err, "Error in CheckSignature %v", ep.Trace)
	} else {
		require.ErrorContains(t, err, checkProblem, "Wrong error in CheckSignature %v", ep.Trace)
	}

	// We continue on to check Eval() of things that failed Check() because it's
	// a nice confirmation that Check() is usually stricter than Eval(). This
	// may mean that the problems argument is often duplicated, but this seems
	// the best way to be concise about all sorts of tests.

	pass, err := EvalSignature(gi, ep)
	if evalProblem == "" {
		require.NoError(t, err, "Eval\n%sExpected: PASS", ep.Trace)
		assert.True(t, pass, "Eval\n%sExpected: PASS", ep.Trace)
		return nil
	}

	// There is an evalProblem to check. REJECT is special and only means that
	// the app didn't accept.  Maybe it's an error, maybe it's just !pass.
	if evalProblem == "REJECT" {
		require.True(t, err != nil || !pass, "Eval\n%sExpected: REJECT", ep.Trace)
	} else {
		require.ErrorContains(t, err, evalProblem, "Wrong error in EvalSignature %v", ep.Trace)
	}
	return err
}

func testLogics(t *testing.T, programs []string, txgroup []transactions.SignedTxn, opt protoOpt, expected ...expect) error {
	t.Helper()
	proto := makeTestProto(opt)

	if txgroup == nil {
		for range programs {
			txgroup = append(txgroup, makeSampleTxn())
		}
	}
	// Place the logicsig code first, so NewSigEvalParams calcs budget
	for i, program := range programs {
		if program != "" {
			code := testProg(t, program, proto.LogicSigVersion).Program
			txgroup[i].Lsig.Logic = code
		}
	}
	ep := NewSigEvalParams(txgroup, proto, &NoHeaderLedger{})
	for i, program := range programs {
		if program != "" {
			if len(expected) > 0 && expected[0].l == i {
				// Stop after first failure
				return testLogicFull(t, txgroup[i].Lsig.Logic, i, ep, expected[0].s)
			}
			testLogicFull(t, txgroup[i].Lsig.Logic, i, ep)
		}
	}
	return nil
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
	ep := defaultSigParams(txn)
	testLogicBytes(t, ops.Program, ep)

	// modify txn field
	saved := ops.Program[2]
	ops.Program[2] = 0x01
	testLogicBytes(t, ops.Program, ep, "unsupported array field")

	// modify txn field to unknown one
	ops.Program[2] = 99
	testLogicBytes(t, ops.Program, ep, "invalid txn field TxnField(99)")

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
	testLogicBytes(t, ops2.Program, defaultSigParams(txn2))

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
	testLogicBytes(t, ops.Program, ep, "invalid txn field TxnField(99)")

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
	testLogicBytes(t, ops3.Program, defaultSigParams(txn3))
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
	testLogicBytes(t, ops.Program, defaultSigParams(txn))

	txn.Txn.ApplicationArgs[0] = nil
	testLogicBytes(t, ops.Program, defaultSigParams(txn))

	source2 := `txna Accounts 1
global ZeroAddress
==
`
	ops = testProg(t, source2, AssemblerMaxVersion)

	var txn2 transactions.SignedTxn
	txn2.Txn.Accounts = make([]basics.Address, 1)
	txn2.Txn.Accounts[0] = basics.Address{}
	testLogicBytes(t, ops.Program, defaultSigParams(txn2))

	txn2.Txn.Accounts = make([]basics.Address, 1)
	testLogicBytes(t, ops.Program, defaultSigParams(txn2))
}

func TestTxnBigPrograms(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	source := `
txna ApprovalProgramPages 0
len
int 4096
==
assert

txna ApprovalProgramPages 1
byte 0x01020304					// 4096 % 7 == 1, so the last four bytes start with 0x01
==
assert

int 1
`
	var txn transactions.SignedTxn
	txn.Txn.ApprovalProgram = make([]byte, 4100) // 4 bytes more than a page
	for i := range txn.Txn.ApprovalProgram {
		txn.Txn.ApprovalProgram[i] = byte(i % 7)
	}
	testLogic(t, source, AssemblerMaxVersion, defaultSigParams(txn))

	testLogic(t, `txna ApprovalProgramPages 2`, AssemblerMaxVersion, defaultSigParams(txn),
		"invalid ApprovalProgramPages index")

	// ClearStateProgram is not in the txn at all
	testLogic(t, `txn NumClearStateProgramPages; !`, AssemblerMaxVersion, defaultSigParams(txn))
	testLogic(t, `txna ClearStateProgramPages 0`, AssemblerMaxVersion, defaultSigParams(txn),
		"invalid ClearStateProgramPages index")
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
	ep := defaultSigParams(txn)
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
	testLogicBytes(t, ops.Program, defaultSigParams(txn2))

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
	testLogicBytes(t, ops.Program, defaultSigParams(txn3))

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
len`, 2, exp(2, "substring expects 2 immediate arguments"))

	// fails in compiler
	testProg(t, `byte 0xf000000000000000
substring 1
len`, 2, exp(2, "substring expects 2 immediate arguments"))

	// fails in compiler
	testProg(t, `byte 0xf000000000000000
substring 4 2
len`, 2, exp(2, "substring end is before start"))

	// fails at runtime
	testPanics(t, `byte 0xf000000000000000
int 4
int 2
substring3
len`, 2)

	// fails at runtime
	testPanics(t, `byte 0xf000000000000000
int 4
int 0xFFFFFFFFFFFFFFFE
substring3
len`, 2, "substring range beyond length of string")
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
	testAccepts(t, "byte 0x123456789abc; int 5; int 1; extract; byte 0xbc; ==", 5)
	testAccepts(t, "byte 0x123456789abcdef0; int 1; extract_uint16; int 0x3456; ==", 5)
	testAccepts(t, "byte 0x123456789abcdef0; int 1; extract_uint32; int 0x3456789a; ==", 5)
	testAccepts(t, "byte 0x123456789abcdef0; int 0; extract_uint64; int 0x123456789abcdef0; ==", 5)
	testAccepts(t, "byte 0x123456789abcdef0; int 0; extract_uint64; int 0x123456789abcdef; !=", 5)

	testAccepts(t, `byte "hello"; extract 5 0; byte ""; ==`, 5)
	testAccepts(t, `byte "hello"; int 5; int 0; extract3; byte ""; ==`, 5)
	testAccepts(t, `byte "hello"; int 5; int 0; extract; byte ""; ==`, 5)
}

func TestExtractFlop(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()
	// fails in compiler
	testProg(t, `byte 0xf000000000000000
	extract
	len`, 5, exp(2, "extract without immediates expects 3 stack arguments but stack height is 1"))

	testProg(t, `byte 0xf000000000000000
	extract 1
	len`, 5, exp(2, "extract expects 0 or 2 immediate arguments"))

	testProg(t, `byte 0xf000000000000000
	int 0
	int 5
	extract3 1 2
	len`, 5, exp(4, "extract3 expects 0 immediate arguments"))

	// fails at runtime
	testPanics(t, `byte 0xf000000000000000
	extract 1 8
	len`, 5, "extraction end 9")

	testPanics(t, `byte 0xf000000000000000
	extract 9 0
	len`, 5, "extraction start 9")

	testPanics(t, `byte 0xf000000000000000
	int 4
	int 0xFFFFFFFFFFFFFFFE
	extract3
	len`, 5, "extraction end exceeds uint64")

	testPanics(t, `byte 0xf000000000000000
	int 100
	int 2
	extract3
	len`, 5, "extraction start 100")

	testPanics(t, `byte 0xf000000000000000
	int 55
	extract_uint16`, 5, "extraction start 55")

	testPanics(t, `byte 0xf000000000000000
	int 9
	extract_uint32`, 5, "extraction start 9")

	testPanics(t, `byte 0xf000000000000000
	int 1
	extract_uint64`, 5, "extraction end 9")
}

func TestReplace(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	testAccepts(t, `byte 0x11111111; byte 0x2222; replace2 0; byte 0x22221111; ==`, 7)
	testAccepts(t, `byte 0x11111111; byte 0x2222; replace2 1; byte 0x11222211; ==`, 7)
	testAccepts(t, `byte 0x11111111; byte 0x2222; replace2 2; byte 0x11112222; ==`, 7)
	testPanics(t, `byte 0x11111111; byte 0x2222; replace2 3; byte 0x11112222; ==`, 7)

	testAccepts(t, `byte 0x11111111; int 0; byte 0x2222; replace3; byte 0x22221111; ==`, 7)
	testAccepts(t, `byte 0x11111111; int 1; byte 0x2222; replace3; byte 0x11222211; ==`, 7)
	testAccepts(t, `byte 0x11111111; int 2; byte 0x2222; replace3; byte 0x11112222; ==`, 7)
	testPanics(t, `byte 0x11111111; int 3; byte 0x2222; replace3; byte 0x11112222; ==`, 7)

	testAccepts(t, `byte 0x11111111; int 0; byte 0x; replace3; byte 0x11111111; ==`, 7)
	testAccepts(t, `byte 0x11111111; int 1; byte 0x; replace3; byte 0x11111111; ==`, 7)
	testAccepts(t, `byte 0x11111111; int 2; byte 0x; replace3; byte 0x11111111; ==`, 7)
	testAccepts(t, `byte 0x11111111; int 3; byte 0x; replace3; byte 0x11111111; ==`, 7)
	// unusual, perhaps, but legal. inserts 0 bytes at len(A)
	testAccepts(t, `byte 0x11111111; int 4; byte 0x; replace3; byte 0x11111111; ==`, 7)
	// but can't replace a byte there
	testPanics(t, `byte 0x11111111; int 4; byte 0x22; replace3; len`, 7)
	// even a zero byte replace fails after len(A)
	testPanics(t, `byte 0x11111111; int 5; byte 0x; replace3; len`, 7)

	testAccepts(t, `byte 0x; byte 0x; replace2 0; byte 0x; ==`, 7)
	testAccepts(t, `byte 0x; int 0; byte 0x; replace3; byte 0x; ==`, 7)
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

// TestLogicErrorDetails confirms that the error returned from logicsig failures
// has the right structured information.
func TestLogicErrorDetails(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	badsource := notrack(`
int 5; store 10					// store an int
byte 0x01020300; store 15		// store a bytes

int 100; byte 0x0201; == // types mismatch so this will fail
`)
	err := testPanics(t, badsource, 1, "cannot compare")
	attrs := basics.Attributes(err)
	zeros := [256]int{}
	scratch := convertSlice(zeros[:], func(i int) any { return uint64(i) })
	scratch[10] = uint64(5)
	scratch[15] = []byte{0x01, 0x02, 0x03, 0x00}
	require.Equal(t, map[string]any{
		"pc":          19,
		"group-index": 0,
		"eval-states": []evalState{
			{
				Stack:   []any{uint64(100), []byte{02, 01}},
				Scratch: scratch[:16],
			},
		},
	}, attrs)

	goodsource := `
int 4; store 2			// store an int
byte "jj"; store 3		// store a bytes
int 1
`
	gscratch := convertSlice(zeros[:], func(i int) any { return uint64(i) })
	gscratch[2] = uint64(4)
	gscratch[3] = []byte("jj")

	err = testLogics(t, []string{goodsource, badsource}, nil, nil, exp(1, "cannot compare"))
	attrs = basics.Attributes(err)
	require.Equal(t, map[string]any{
		"pc":          19,
		"group-index": 1,
		"eval-states": []evalState{
			{
				Scratch: gscratch[:4],
			},
			{
				Stack:   []any{uint64(100), []byte{02, 01}},
				Scratch: scratch[:16],
			},
		},
	}, attrs)
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
			`int 2; store 0; int 1`,
			`gload 0 0; int 2; ==`,
		},
	}

	multipleTxnCase := scratchTestCase{
		tealSources: []string{
			`byte "txn 1"; store 0; int 1`,
			`byte "txn 2"; store 2; int 1`,
			`gload 0 0; byte "txn 1"; ==; gload 1 2; byte "txn 2"; ==; &&`,
		},
	}

	selfCase := scratchTestCase{
		tealSources: []string{
			`gload 0 0; int 2; store 0; int 1`,
		},
		errTxn:      0,
		errContains: "can't use gload on self, use load instead",
	}

	laterTxnSlotCase := scratchTestCase{
		tealSources: []string{
			`gload 1 0; int 2; ==`,
			`int 2; store 0; int 1`,
		},
		errTxn:      0,
		errContains: "gload can't get future scratch space from txn with index 1",
	}

	cases := []scratchTestCase{
		simpleCase, multipleTxnCase, selfCase, laterTxnSlotCase,
	}

	for i, testCase := range cases {
		t.Run(fmt.Sprintf("i=%d", i), func(t *testing.T) {
			t.Parallel()
			sources := testCase.tealSources

			// Initialize txgroup
			txgroup := make([]transactions.SignedTxn, len(sources))
			for j := range txgroup {
				txgroup[j].Txn.Type = protocol.ApplicationCallTx
			}

			if testCase.errContains != "" {
				testApps(t, sources, txgroup, nil, nil, exp(testCase.errTxn, testCase.errContains))
			} else {
				testApps(t, sources, txgroup, nil, nil)
			}
		})
	}

	// for more complex group transaction cases
	type failureCase struct {
		firstTxn    transactions.SignedTxn
		runMode     RunMode
		errContains string
	}

	nonAppCall := failureCase{
		firstTxn: transactions.SignedTxn{
			Txn: transactions.Transaction{
				Type: protocol.PaymentTx,
			},
		},
		runMode:     ModeApp,
		errContains: "can't use gload on non-app call txn with index 0",
	}

	logicSigCall := failureCase{
		firstTxn: transactions.SignedTxn{
			Txn: transactions.Transaction{
				Type: protocol.ApplicationCallTx,
			},
		},
		runMode:     ModeSig,
		errContains: "gload not allowed in current mode",
	}

	failCases := []failureCase{nonAppCall, logicSigCall}
	for j, failCase := range failCases {
		t.Run(fmt.Sprintf("j=%d", j), func(t *testing.T) {
			t.Parallel()

			appcall := transactions.SignedTxn{
				Txn: transactions.Transaction{
					Type: protocol.ApplicationCallTx,
				},
			}

			program := testProg(t, "gload 0 0", AssemblerMaxVersion).Program
			switch failCase.runMode {
			case ModeApp:
				testAppBytes(t, program, defaultAppParams(failCase.firstTxn, appcall), failCase.errContains)
			default:
				testLogicBytes(t, program, defaultSigParams(failCase.firstTxn, appcall), failCase.errContains, failCase.errContains)
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

	testApps(t, sources, txgroup, nil, nil)
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
                     byte 0xc195eca25a6f4c82bfba0287082ddb0d602ae9230f9cf1f1a40b68f8e2c41567; ==; `

	// Sanity check. Running a short sequence of these fragments passes in all versions.
	source := fragment + strings.Repeat(fragment+"&&; ", 5)
	testAccepts(t, source, 1)

	// in v1, each repeat costs 30
	v1overspend := fragment + strings.Repeat(fragment+"&&; ", testLogicBudget/30)
	// in v2,v3 each repeat costs 134
	v2overspend := fragment + strings.Repeat(fragment+"&&; ", testLogicBudget/134)

	// v1overspend fails (on v1)
	ops := testProg(t, v1overspend, 1)
	// We should never Eval this after it fails Check(), but nice to see it also fails.
	testLogicBytes(t, ops.Program, defaultSigParamsWithVersion(1),
		"static cost", "dynamic cost")
	// v2overspend passes Check, even on v2 proto, because the old low cost is "grandfathered"
	ops = testProg(t, v2overspend, 1)
	testLogicBytes(t, ops.Program, defaultSigParamsWithVersion(2))

	// even the shorter, v2overspend, fails when compiled as v2 code
	ops = testProg(t, v2overspend, 2)
	testLogicBytes(t, ops.Program, defaultSigParamsWithVersion(2),
		"static cost", "dynamic cost")

	// in v4 cost is still 134, but only matters in Eval, not Check, so both fail there
	ep4 := defaultSigParamsWithVersion(4)
	ops = testProg(t, v1overspend, 4)
	testLogicBytes(t, ops.Program, ep4, "dynamic cost")

	ops = testProg(t, v2overspend, 4)
	testLogicBytes(t, ops.Program, ep4, "dynamic cost")
}

func TestSigBudget(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	source := func(budget int) string {
		return fmt.Sprintf(`
global OpcodeBudget
int %d
==
assert
global OpcodeBudget
int %d
==
`, budget-1, budget-5)
	}
	b := testLogicBudget
	testLogic(t, source(b), LogicVersion, nil)

	testLogics(t, []string{source(2 * b), source(2*b - 7)}, nil, nil)

	testLogics(t, []string{source(3 * b), source(3*b - 7), ""}, nil, nil)

	testLogics(t, []string{source(b), source(b)}, nil,
		func(p *config.ConsensusParams) { p.EnableLogicSigCostPooling = false })
}

func isNotPanic(t *testing.T, err error) {
	if err == nil {
		return
	}
	if pe, ok := err.(panicError); ok {
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
			testLogicBytes(t, ops.Program, nil, "stack underflow")
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
			testLogicBytes(t, ops.Program, nil, "sha256 arg 0 wanted")
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
			testLogicBytes(t, ops.Program, nil, "cannot compare")
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
			testLogicBytes(t, ops.Program, nil, "cannot compare")
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
			testLogicBytes(t, ops.Program, nil, "+ arg 0 wanted")
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
			testLogicBytes(t, ops.Program, nil, "illegal opcode", "illegal opcode")
		})
	}
}

func TestShortSimple(t *testing.T) {
	partitiontest.PartitionTest(t)

	t.Parallel()
	for v := uint64(1); v <= AssemblerMaxVersion; v++ {
		t.Run(fmt.Sprintf("v=%d", v), func(t *testing.T) {
			ops := testProg(t, `int 8; store 7`, v)
			testLogicBytes(t, ops.Program[:len(ops.Program)-1], nil,
				"program ends short of immediate values",
				"program ends short of immediate values")
		})
	}
}

func TestShortBranch(t *testing.T) {
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
			testLogicBytes(t, ops.Program[:len(ops.Program)-2], nil,
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
	testLogicBytes(t, ops.Program, nil)
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
					testLogicBytes(t, program, nil, "bytes list", "bytes list")
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
			t.Parallel()
			program, err := hex.DecodeString(src)
			require.NoError(t, err)
			testLogicBytes(t, program, nil, "const bytes list", "const bytes list")
		})
	}
}

const panicString = "out of memory, buffer overrun, stack overflow, divide by zero, halt and catch fire"

// withOpcode temporarily modifies the opsByOpcode array to include an
// additional opcode, specieid by op.
//
// WARNING: do not call this in a parallel test, since it's not safe for concurrent use.
func withOpcode(t *testing.T, version uint64, op OpSpec, f func(opcode byte)) {
	t.Helper()

	var foundEmptySpace bool
	var hackedOpcode byte
	var oldSpec OpSpec
	// Find an unused opcode to temporarily convert to op
	for opcode, spec := range opsByOpcode[version] {
		if spec.op == nil {
			foundEmptySpace = true
			require.LessOrEqual(t, opcode, math.MaxUint8)
			hackedOpcode = byte(opcode)
			oldSpec = spec
			copy := op
			copy.Opcode = hackedOpcode
			opsByOpcode[version][opcode] = copy
			OpsByName[version][op.Name] = copy
			break
		}
	}
	require.True(t, foundEmptySpace, "could not find an empty space for the opcode")
	defer func() {
		opsByOpcode[version][hackedOpcode] = oldSpec
		delete(OpsByName[version], op.Name)
	}()
	f(hackedOpcode)
}

// withPanicOpcode temporarily modifies the opsByOpcode array to include an additional panic opcode.
// This opcode will be named "panic".
//
// WARNING: do not call this in a parallel test, since it's not safe for concurrent use.
func withPanicOpcode(t *testing.T, version uint64, panicDuringCheck bool, f func(opcode byte)) {
	t.Helper()

	opPanic := func(cx *EvalContext) error {
		panic(panicString)
	}
	details := detDefault()
	if panicDuringCheck {
		details.check = opPanic
	}

	panicSpec := OpSpec{
		Name:      "panic",
		op:        opPanic,
		OpDetails: details,
	}

	withOpcode(t, version, panicSpec, f)
}

func TestPanic(t *testing.T) { //nolint:paralleltest // Uses withPanicOpcode
	partitiontest.PartitionTest(t)

	// These tests would generate a lot of log noise which shows up if *other*
	// tests fail. So it's pretty annoying to run `go test` on the whole
	// package.  `logSink` swallows log messages.
	logSink := logging.NewLogger()
	logSink.SetOutput(io.Discard)
	for v := uint64(1); v <= AssemblerMaxVersion; v++ {
		t.Run(fmt.Sprintf("v=%d", v), func(t *testing.T) { //nolint:paralleltest // Uses withPanicOpcode
			withPanicOpcode(t, v, true, func(opcode byte) {
				ops := testProg(t, `int 1`, v)
				ops.Program = append(ops.Program, opcode)

				ep := defaultSigParams()
				ep.logger = logSink
				ep.TxnGroup[0].Lsig.Logic = ops.Program
				err := CheckSignature(0, ep)
				var pe panicError
				require.ErrorAs(t, err, &pe)
				require.Equal(t, panicString, pe.PanicValue)
				require.ErrorContains(t, pe, "panic")

				var txn transactions.SignedTxn
				txn.Lsig.Logic = ops.Program
				ep = defaultSigParams(txn)
				ep.logger = logSink
				pass, err := EvalSignature(0, ep)
				if pass {
					t.Log(hex.EncodeToString(ops.Program))
					t.Log(ep.Trace.String())
				}
				require.False(t, pass)
				require.ErrorAs(t, err, &pe)
				require.Equal(t, panicString, pe.PanicValue)
				require.ErrorContains(t, pe, "panic")

				if v >= appsEnabledVersion {
					txn = transactions.SignedTxn{
						Txn: transactions.Transaction{
							Type: protocol.ApplicationCallTx,
						},
					}
					ep := defaultAppParams(txn)
					ep.logger = logSink
					pass, err = EvalApp(ops.Program, 0, 1, ep)
					require.False(t, pass)
					require.ErrorAs(t, err, &pe)
					require.Equal(t, panicString, pe.PanicValue)
					require.ErrorContains(t, pe, "panic")
				}
			})
		})
	}
}

func TestProgramTooNew(t *testing.T) {
	partitiontest.PartitionTest(t)

	t.Parallel()
	var program [12]byte
	vlen := binary.PutUvarint(program[:], LogicVersion+1)
	testLogicBytes(t, program[:vlen], nil,
		"greater than max supported", "greater than max supported")
}

func TestInvalidVersion(t *testing.T) {
	partitiontest.PartitionTest(t)

	t.Parallel()
	program, err := hex.DecodeString("ffffffffffffffffffffffff")
	require.NoError(t, err)
	testLogicBytes(t, program, nil, "invalid version", "invalid version")
}

func TestProgramProtoForbidden(t *testing.T) {
	partitiontest.PartitionTest(t)

	t.Parallel()
	var program [12]byte
	vlen := binary.PutUvarint(program[:], LogicVersion)
	ep := defaultSigParamsWithVersion(LogicVersion - 1)
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
			testLogicBytes(t, ops.Program, nil, "aligned", "REJECT")

			// back branches are checked differently, so test misaligned back branch
			ops.Program[6] = 0xff // Clobber the two bytes of offset with 0xff 0xff = -1
			ops.Program[7] = 0xff // That jumps into the offset itself (pc + 3 -1)
			if v < backBranchEnabledVersion {
				testLogicBytes(t, ops.Program, nil, "negative branch", "negative branch")
			} else {
				// Again, if we were ever to Eval(), we would not know it's wrong. But we reject here "by luck"
				testLogicBytes(t, ops.Program, nil, "back branch target", "REJECT")
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
			testLogicBytes(t, ops.Program, nil, "outside of program", "outside of program")
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
			testLogicBytes(t, ops.Program, nil, "outside", "outside")
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
			t.Parallel()
			source := fmt.Sprintf(template, line)
			ops, err := AssembleStringWithVersion(source, AssemblerMaxVersion)
			require.NoError(t, err)
			ops.Program[7] = 0xf0 // clobber the branch offset - highly negative
			ops.Program[8] = 0xff // clobber the branch offset
			testLogicBytes(t, ops.Program, nil, "outside of program", "outside of program")
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

func evalLoop(b *testing.B, runs int, programs ...[]byte) {
	program := programs[0]
	final := programs[len(programs)-1]
	b.Helper()
	b.ResetTimer()
	for i := 0; i < runs; i++ {
		var txn transactions.SignedTxn
		txn.Lsig.Logic = program
		if i == runs-1 {
			txn.Lsig.Logic = final
		}
		pass, err := EvalSignature(0, benchmarkSigParams(txn))
		if !pass {
			// rerun to trace it.  tracing messes up timing too much
			ep := benchmarkSigParams(txn)
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
	b.Helper()
	runs := b.N / 2000
	inst := strings.Count(operation, ";") + strings.Count(operation, "\n")
	source := prefix + ";" + strings.Repeat(operation+"\n", 2000) + ";" + suffix
	ops := testProg(b, source, AssemblerMaxVersion)
	finalOps := ops

	if b.N%2000 != 0 {
		runs++
		finalSource := prefix + ";" + strings.Repeat(operation+"\n", b.N%2000) + ";" + suffix
		finalOps = testProg(b, finalSource, AssemblerMaxVersion)
	}
	evalLoop(b, runs, ops.Program, finalOps.Program)
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

func BenchmarkDupnProto(b *testing.B) {
	benches := [][]string{
		{"dupn1", `
 b main
f:
 proto 1 1
 byte "repeat"
 dupn 0						// return 1 string
 retsub
main:
 int 777; dupn 0;			// start with 1 int on stack
`, "callsub f", "len"},
		{"dupn10", `
 b main
f:
 proto 10 10
 byte "repeat"
 dupn 9						// return 10 strings
 retsub
main:
 int 777; dupn 9; 			// start with 10 ints on stack
`, "callsub f", strings.Repeat("pop;", 9) + "len"},
		{"dupn100", `
 b main
f:
 proto 100 100
 byte "repeat"
 dupn 99						// return 100 strings
 retsub
main:
 int 777; dupn 99; 			// start with 100 ints on stack
`, "callsub f", strings.Repeat("pop;", 99) + "len"},
		{"dp1", "int 777", "dupn 1; popn 1", ""},
		{"dp10", "int 777", "dupn 10; popn 10", ""},
		{"dp100", "int 777", "dupn 100; popn 100", ""},
	}
	for _, bench := range benches {
		b.Run(bench[0], func(b *testing.B) {
			b.ReportAllocs()
			benchmarkOperation(b, bench[1], bench[2], bench[3])
		})
	}
}

func BenchmarkBytesDiv(b *testing.B) {
	for i := range 128 {
		size := (i + 1) * 32
		b.Run(fmt.Sprintf("b/ %d", size), func(b *testing.B) {
			b.ReportAllocs()
			benchmarkOperation(b, "", randBytes(size)+randBytes(size*3/8)+"b/; pop", "int 1")
		})
	}
}

// bigint multiply ought to have a weird cost function because Karatsuba kicks at 40 Words (320 bytes)
func BenchmarkBytesMulEqualSize(b *testing.B) {
	for i := range 32 {
		size := i * 64
		b.Run(fmt.Sprintf("b* %d", size), func(b *testing.B) {
			b.ReportAllocs()
			benchmarkOperation(b, "", randBytes(size)+randBytes(size)+"b*; pop", "int 1")
		})
	}
}

func BenchmarkBytesMulBySmall(b *testing.B) {
	for i := range 64 {
		size := i * 64
		b.Run(fmt.Sprintf("b* %d by 8", size), func(b *testing.B) {
			b.ReportAllocs()
			benchmarkOperation(b, "", randBytes(size)+randBytes(8)+"b*; pop", "int 1")
		})
	}
}

func BenchmarkBytesMulByMed(b *testing.B) {
	for i := range 64 {
		size := i * 48
		other := size / 3
		b.Run(fmt.Sprintf("b* %d by %d", size, other), func(b *testing.B) {
			b.ReportAllocs()
			benchmarkOperation(b, "", randBytes(size)+randBytes(other)+"b*; pop", "int 1")
		})
	}
}

func BenchmarkBytesSqrt(b *testing.B) {
	for i := range 64 {
		size := i * 16
		b.Run(fmt.Sprintf("bqsrt %d", size), func(b *testing.B) {
			b.ReportAllocs()
			benchmarkOperation(b, "", randBytes(size)+"bsqrt; pop", "int 1")
		})
	}
}

func BenchmarkBytesMulDifferingSizes(b *testing.B) {
	for awords := 1; awords <= 40; awords++ {
		product := 32 * 32
		bwords := product / awords
		if bwords > 40 {
			continue
		}
		b.Run(fmt.Sprintf("b* %d-%d", awords, bwords), func(b *testing.B) {
			b.ReportAllocs()
			benchmarkOperation(b, "", randBytes(8*awords)+randBytes(8*bwords)+"b*; pop", "int 1")
		})
	}
}

// BenchmarkFindWorstBytesDiv determines the relatiuve byte size of the dividend
// and divisor for worst case speed testing.  About 3/8.
func BenchmarkFindWorstBytesDiv(b *testing.B) {
	for divisor := 1600; divisor > 1500; divisor -= 10 {
		b.Run(fmt.Sprintf("b/ %d", divisor), func(b *testing.B) {
			b.ReportAllocs()
			benchmarkOperation(b, "", randBytes(4096)+randBytes(divisor)+"b/; pop", "int 1")
		})
	}
}

func BenchmarkBinaryByteLogic(b *testing.B) {
	for i := range 16 {
		size := i * 64
		for _, op := range []string{"b&", "b|", "b^"} {
			b.Run(fmt.Sprintf("%s %d", op, size), func(b *testing.B) {
				b.ReportAllocs()
				benchmarkOperation(b, "", randBytes(size)+randBytes(size)+op+";pop", "int 1")
			})
		}
	}
}

func BenchmarkByteNot(b *testing.B) {
	for i := range 16 {
		size := i * 64
		b.Run(fmt.Sprintf("b~ %d", size), func(b *testing.B) {
			b.ReportAllocs()
			benchmarkOperation(b, randBytes(size), "b~", "pop; int 1")
		})
	}
}

// randBytes generates a random `byte` constant of length `length`, replacing
// the leading bytes with optional `prefix` bytes.
func randBytes(length int, prefix ...byte) string {
	bytes := make([]byte, length)
	rand.Read(bytes)
	copy(bytes, prefix)
	return fmt.Sprintf("byte 0x%x;", bytes)
}

func BenchmarkByteAddSub(b *testing.B) {
	benches := [][]string{
		{"bytec", randBytes(16) + "pop"},

		{"b+ 8", randBytes(8) + randBytes(8) + "b+; pop"},
		{"b- 8", randBytes(8, 0xff) + randBytes(8, 0x11) + "b-; pop"},

		// maximum sizes, pre fullByteMathVersion
		{"b+ 64", randBytes(64) + randBytes(64) + "b+; pop"},
		{"b- 64", randBytes(64, 0xff) + randBytes(64, 0x11) + "b-; pop"},

		{"b+ 512", randBytes(512) + randBytes(512) + "b+; pop"},
		{"b- 512", randBytes(512, 0xff) + randBytes(512) + "b-; pop"},

		{"b+ 4096", randBytes(4096, 0x11) + randBytes(4096, 0x22) + "b+; pop"},
		{"b- 4096", randBytes(4096, 0xff) + randBytes(4096, 0x11) + "b-; pop"},

		{"bytec recheck", randBytes(16) + "pop"},
	}
	for _, bench := range benches {
		b.Run(bench[0], func(b *testing.B) {
			b.ReportAllocs()
			benchmarkOperation(b, "", bench[1], "int 1")
		})
	}
}

func BenchmarkByteCompare(b *testing.B) {
	u64 := "byte 0x8090a0b0c0d0e0f0;"
	hex128 := "102030405060708090a0b0c0d0e0f000"
	u128 := "byte 0x" + strings.Repeat(hex128, 1) + ";"
	u256 := "byte 0x" + strings.Repeat(hex128, 2) + ";"
	u512 := "byte 0x" + strings.Repeat(hex128, 4) + ";"
	u4k := "byte 0x" + strings.Repeat(hex128, 256) + ";"

	benches := [][]string{
		{"b== 64", u64 + u64 + "b==; pop"},
		{"b< 64", u64 + u64 + "b<; pop"},
		{"b<= 64", u64 + u64 + "b<=; pop"},
		{"b== 128", u128 + u128 + "b==; pop"},
		{"b< 128", u128 + u128 + "b<; pop"},
		{"b<= 128", u128 + u128 + "b<=; pop"},
		{"b== 256", u256 + u256 + "b==; pop"},
		{"b< 256", u256 + u256 + "b<; pop"},
		{"b<= 256", u256 + u256 + "b<=; pop"},
		{"b== 512", u512 + u512 + "b==; pop"},
		{"b< 512", u512 + u512 + "b<; pop"},
		{"b<= 512", u512 + u512 + "b<=; pop"},
		// These can only be run with the maxByteMathSize check removed. They
		// show that we can remove that check in a later AVM version, as there
		// is no appreciable cost to even a 4k compare.
		{"b== 4k", u4k + u4k + "b==; pop"},
		{"b< 4k", u4k + u4k + "b<; pop"},
		{"b<= 4k", u4k + u4k + "b<=; pop"},
	}
	for _, bench := range benches {
		b.Run(bench[0], func(b *testing.B) {
			b.ReportAllocs()
			benchmarkOperation(b, "", bench[1], "int 1")
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
			err := CheckSignature(0, defaultSigParams(txn))
			if err != nil {
				require.NoError(b, err)
			}
		}
	}
}

func makeNestedKeys(depth int) string {
	if depth <= 0 {
		return `{\"key0\":\"value0\"}`
	}
	return fmt.Sprintf(`{\"key0\":%s}`, makeNestedKeys(depth-1))
}

func BenchmarkJsonRef(b *testing.B) {
	// base case
	oneKey := `{\"key0\":\"value0\"}`

	// many keys
	sb := &strings.Builder{}
	sb.WriteString(`{`)
	for i := 0; i < 100; i++ {
		sb.WriteString(fmt.Sprintf(`\"key%d\":\"value%d\",`, i, i))
	}
	sb.WriteString(`\"key100\":\"value100\"}`) // so there is no trailing comma
	manyKeys := sb.String()

	lenOfManyKeys := len(manyKeys)
	longTextLen := lenOfManyKeys - 36 // subtract the difference
	mediumText := strings.Repeat("a", longTextLen/2)
	longText := strings.Repeat("a", longTextLen)

	// medium key
	mediumKey := fmt.Sprintf(`{\"%s\":\"value\",\"key1\":\"value2\"}`, mediumText)

	// long key
	longKey := fmt.Sprintf(`{\"%s\":\"value\",\"key1\":\"value2\"}`, longText)

	// long value
	longValue := fmt.Sprintf(`{\"key0\":\"%s\",\"key1\":\"value2\"}`, longText)

	// nested keys
	nestedKeys := makeNestedKeys(200)

	jsonLabels := []string{"one key", "many keys", "medium key", "long key", "long val", "nested keys"}
	jsonSamples := []string{oneKey, manyKeys, mediumKey, longKey, longValue, nestedKeys}
	keys := [][]string{
		{"key0"},
		{"key0", "key100"},
		{mediumText, "key1"},
		{longText, "key1"},
		{"key0", "key1"},
		{"key0"},
	}
	valueFmt := [][]string{
		{"JSONString"},
		{"JSONString", "JSONString"},
		{"JSONString", "JSONString"},
		{"JSONString", "JSONString"},
		{"JSONString", "JSONString"},
		{"JSONObject"},
	}
	benches := [][]string{}
	for i, label := range jsonLabels {
		for j, key := range keys[i] {
			prog := fmt.Sprintf(`byte "%s"; byte "%s"; json_ref %s; pop;`, jsonSamples[i], key, valueFmt[i][j])

			// indicate long key
			keyLabel := key
			if len(key) > 50 {
				keyLabel = fmt.Sprintf("long_key_%d", len(key))
			}

			benches = append(benches, []string{
				fmt.Sprintf("%s_%s", label, keyLabel), // label
				"",                                    // prefix
				prog,                                  // operation
				"int 1",                               // suffix
			})
		}
	}
	for _, bench := range benches {
		b.Run(bench[0], func(b *testing.B) {
			benchmarkOperation(b, bench[1], bench[2], bench[3])
		})
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

	testLogicBytes(t, ops.Program, defaultSigParams(txn))

	testLogicBytes(t, ops.Program, defaultSigParamsWithVersion(1, txn),
		"greater than protocol supported version 1", "greater than protocol supported version 1")

	// hack the version and fail on illegal opcode
	ops.Program[0] = 0x1
	testLogicBytes(t, ops.Program, defaultSigParamsWithVersion(1, txn),
		"illegal opcode 0x36", "illegal opcode 0x36") // txna
}

func TestStackOverflow(t *testing.T) {
	partitiontest.PartitionTest(t)

	t.Parallel()
	source := "int 1; int 2; "
	for i := 1; i < maxStackDepth/2; i++ {
		source += "dup2; "
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
	require.Equal(t, avmUint64, sv.avmType())
	sv.Bytes = []byte("")
	require.Equal(t, avmBytes, sv.avmType())
	sv.Uint = 1
	require.Equal(t, avmBytes, sv.avmType())
	sv.Bytes = nil
	require.Equal(t, avmUint64, sv.avmType())
}

func TestAnyRekeyToOrApplicationRaisesMinAvmVersion(t *testing.T) {
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
			t.Parallel()
			sep, aep := defaultEvalParams(cse.group...)

			// Computed MinAvmVersion should be == validFromVersion
			calc := computeMinAvmVersion(sep.TxnGroup)
			require.Equal(t, calc, cse.validFromVersion)

			calc = computeMinAvmVersion(aep.TxnGroup)
			require.Equal(t, calc, cse.validFromVersion)

			// Should fail for all versions < validFromVersion
			expected := fmt.Sprintf("program version must be >= %d", cse.validFromVersion)
			for v := uint64(0); v < cse.validFromVersion; v++ {
				ops := testProg(t, source, v)
				testAppBytes(t, ops.Program, aep, expected, expected)
				testLogicBytes(t, ops.Program, sep, expected, expected)
			}

			// Should succeed for all versions >= validFromVersion
			for v := cse.validFromVersion; v <= AssemblerMaxVersion; v++ {
				ops := testProg(t, source, v)
				testAppBytes(t, ops.Program, aep)
				testLogicBytes(t, ops.Program, sep)
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

	sep, aep := defaultEvalParamsWithVersion(2)

	cnt := 0
	for _, spec := range OpSpecs {
		if spec.Version == 2 && !excluded[spec.Name] {
			source, ok := tests[spec.Name]
			require.True(t, ok, "Missed opcode in the test: %s", spec.Name)
			require.Contains(t, source, spec.Name)
			ops := testProg(t, source, 2)
			// all opcodes allowed in stateful mode so use CheckStateful/EvalContract
			err := CheckContract(ops.Program, aep)
			require.NoError(t, err, source)
			_, err = EvalApp(ops.Program, 0, 0, aep)
			if spec.Name != "return" {
				// "return" opcode always succeeds so ignore it
				require.Error(t, err, source)
				require.NotContains(t, err.Error(), "illegal opcode")
			}

			for v := byte(0); v <= 1; v++ {
				ops.Program[0] = v
				testLogicBytes(t, ops.Program, sep, "illegal opcode", "illegal opcode")
				// let the program run even though minAvmVersion would ban it,
				// so we can have this sanity check
				aep.minAvmVersion = uint64(v)
				testAppBytes(t, ops.Program, aep, "illegal opcode", "illegal opcode")
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

	sep, aep := defaultEvalParamsWithVersion(3)

	cnt := 0
	for _, spec := range OpSpecs {
		if spec.Version == 3 {
			source, ok := tests[spec.Name]
			require.True(t, ok, "Missed opcode in the test: %s", spec.Name)
			require.Contains(t, source, spec.Name)
			ops := testProg(t, source, 3)
			// all opcodes allowed in stateful mode so use CheckStateful/EvalContract
			testAppBytes(t, ops.Program, aep, "REJECT")

			for v := byte(0); v <= 2; v++ {
				ops.Program[0] = v
				testLogicBytes(t, ops.Program, sep, "illegal opcode", "illegal opcode")
				// let the program run even though minAvmVersion would ban it,
				// so we can have this sanity check
				aep.minAvmVersion = uint64(v)
				testAppBytes(t, ops.Program, aep, "illegal opcode", "illegal opcode")
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
			ops := testProg(t, "int 1", v)
			var txn transactions.SignedTxn
			txn.Txn.RekeyTo = basics.Address{1, 2, 3, 4}
			e := fmt.Sprintf("program version must be >= %d", rekeyingEnabledVersion)
			testLogicBytes(t, ops.Program, defaultSigParams(txn), e, e)
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

type evalTester func(t *testing.T, pass bool, err error) bool

func testEvaluation(t *testing.T, program string, start uint64, stop uint64, tester evalTester) error {
	t.Helper()

	var outer error
	for v := start; v <= stop; v++ {
		t.Run(fmt.Sprintf("v=%d", v), func(t *testing.T) {
			t.Helper()
			ops := testProg(t, program, v)
			// Programs created with a previous assembler
			// should still operate properly with future
			// EvalParams, so try all forward versions.
			for lv := v; lv <= stop; lv++ {
				t.Run(fmt.Sprintf("lv=%d", lv), func(t *testing.T) {
					t.Helper()
					var txn transactions.SignedTxn
					txn.Lsig.Logic = ops.Program
					ep := defaultSigParamsWithVersion(lv, txn)
					err := CheckSignature(0, ep)
					if err != nil {
						t.Log(ep.Trace.String())
					}
					require.NoError(t, err)
					ep = defaultSigParamsWithVersion(lv, txn)
					pass, err := EvalSignature(0, ep)
					ok := tester(t, pass, err)
					if !ok {
						t.Log(ep.Trace.String())
						t.Log(err)
					}
					require.True(t, ok)
					isNotPanic(t, err) // Never want a Go level panic.
					if err != nil {
						// Use `outer` wisely. It could return any of the concurrent runs' errors.
						var se *basics.SError
						require.ErrorAs(t, err, &se)
						var ee EvalError
						require.ErrorAs(t, err, &ee)
						outer = err
					}
				})
			}
		})
	}
	return outer
}

// testCost ensures that the program accepts and that the cost as described
func testCost(t *testing.T, program string, cost uint64, ver uint64) {
	t.Helper()
	if ver < 6 {
		panic("testCost doesn't work until ver 6")
	}
	// compare the OpCodeBudget remaining to the cost supplied, but add 2 to
	// account for the access instructionms.  use pushint to avoid influencing
	// the way `int` might be compiled in the test program. leave the stack as
	// it was found.
	program += fmt.Sprintf("; pushint %d; global OpcodeBudget; -; pushint 2; -; pushint %d; ==; assert", testLogicBudget, cost)
	testAcceptRange(t, program, ver, ver)
}

func testAccepts(t *testing.T, program string, introduced uint64) {
	t.Helper()
	testPreexist(t, program, introduced)
	testAcceptRange(t, program, introduced, AssemblerMaxVersion)
}

func testAcceptRange(t *testing.T, program string, start uint64, stop uint64) {
	t.Helper()
	testEvaluation(t, program, start, stop, func(t *testing.T, pass bool, err error) bool {
		return pass && err == nil
	})
}

func testRejects(t *testing.T, program string, introduced uint64) {
	t.Helper()
	testPreexist(t, program, introduced)
	testRejectRange(t, program, introduced, AssemblerMaxVersion)
}

func testRejectRange(t *testing.T, program string, start uint64, stop uint64) {
	t.Helper()
	testEvaluation(t, program, start, stop, func(t *testing.T, pass bool, err error) bool {
		// Returned False, but didn't panic
		return !pass && err == nil
	})
}

func testPanics(t *testing.T, program string, introduced uint64, pattern ...string) error {
	t.Helper()
	testPreexist(t, program, introduced)
	return testPanicRange(t, program, introduced, AssemblerMaxVersion)
}

func testPreexist(t *testing.T, program string, introduced uint64) {
	for v := uint64(1); v < introduced; v++ {
		t.Run(fmt.Sprintf("v=%d", v), func(t *testing.T) {
			t.Helper()
			testProg(t, notrack(program), v, exp(0, "...was introduced..."))
		})
	}
}

func testPanicRange(t *testing.T, program string, start uint64, stop uint64, pattern ...string) error {
	t.Helper()
	return testEvaluation(t, program, start, stop, func(t *testing.T, pass bool, err error) bool {
		t.Helper()
		// TEAL panic! not just reject at exit
		if pass {
			return false
		}
		if err == nil {
			t.Log("program rejected rather panicked")
			return false
		}
		for _, p := range pattern {
			if !strings.Contains(err.Error(), p) {
				t.Log(err, "does not contain", p)
				return false
			}
		}
		return true
	})
}

func TestAssert(t *testing.T) {
	partitiontest.PartitionTest(t)

	t.Parallel()
	testAccepts(t, "int 1; assert; int 1", 3)
	testRejects(t, "int 1; assert; int 0", 3)
	testPanics(t, "int 0; assert; int 1", 3)
	testPanics(t, notrack("assert; int 1"), 3)
	testPanics(t, notrack(`byte "john"; assert; int 1`), 3)
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

func TestBury(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	// bury 0 panics
	source := "int 3; int 2; int 7; bury 0; int 1; return"
	testProg(t, source, 8, exp(1, "bury 0 always fails"))
	testPanics(t, notrack("int 3; int 2; int 7; bury 0; int 1; return"), 8, "bury outside stack")

	// bury 1 pops the ToS and replaces the thing "1 down", which becomes the new ToS
	testAccepts(t, "int 3; int 2; int 7; bury 1; int 7; ==; assert; int 3; ==", 8)

	// bury 2
	testAccepts(t, `int 3; int 2; int 7;
		bury 2;
		int 2; ==; assert
		int 7; ==;
`, 8)

	// bury too deep
	testPanics(t, notrack("int 3; int 2; int 7;	bury 3; int 1; return"), 8, "bury outside stack")
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

// BenchmarkBytesModExpRealistic is used to benchmark bmodexp for more realistic
// values, things that will take less than 500k ticks. (320k is the most you can get today. (16 * 20k)
func BenchmarkBytesModExpRealistic(b *testing.B) {
	base := 32
	for i := range 32 {
		exp := i * 16
		if i == 0 {
			i = 1
		}
		b.Run(fmt.Sprintf("bmodexp-%d-%d", base, exp), func(b *testing.B) {
			b.ReportAllocs()
			// 0xaa ensures top bit is set, plus "some"
			benchmarkOperation(b, "", randBytes(base)+randBytes(exp, 0xaa)+randBytes(base)+"bmodexp; pop", "int 1")
		})
	}
	base = 64
	for i := range 16 {
		exp := i * 32
		if i == 0 {
			i = 1
		}
		b.Run(fmt.Sprintf("bmodexp-%d-%d", base, exp), func(b *testing.B) {
			b.ReportAllocs()
			benchmarkOperation(b, "", randBytes(base)+randBytes(exp, 0xaa)+randBytes(base)+"bmodexp; pop", "int 1")
		})
	}
	base = 96
	for i := range 16 {
		exp := i * 32
		if i == 0 {
			i = 1
		}
		b.Run(fmt.Sprintf("bmodexp-%d-%d", base, exp), func(b *testing.B) {
			b.ReportAllocs()
			benchmarkOperation(b, "", randBytes(base)+randBytes(exp, 0xaa)+randBytes(base)+"bmodexp; pop", "int 1")
		})
	}
	base = 512 // Typical RSA max key exp (4096 bits)
	for i := range 16 {
		exp := 1 + i*2 // RSA typically uses 65537 for verify, which has a *byte* width of just 3 (bit width = 17)
		b.Run(fmt.Sprintf("bmodexp-%d-%d", base, exp), func(b *testing.B) {
			b.ReportAllocs()
			benchmarkOperation(b, "", randBytes(base)+randBytes(exp, 0xaa)+randBytes(base)+"bmodexp; pop", "int 1")
		})
	}
	base = 1024 // Barely ever used (8192 bits)
	for i := range 16 {
		exp := 1 + i // RSA typically uses 65537 for verify, which has a *byte* width of just 3 (bit width = 17)
		b.Run(fmt.Sprintf("bmodexp-%d-%d", base, exp), func(b *testing.B) {
			b.ReportAllocs()
			benchmarkOperation(b, "", randBytes(base)+randBytes(exp, 0xaa)+randBytes(base)+"bmodexp; pop", "int 1")
		})
	}
}

// BenchmarkBytesModExpLinearExponent is used to show that bmodexp takes linear time in the width of the exponent
func BenchmarkBytesModExpLinearExponent(b *testing.B) {
	for i := range 32 {
		exp := (i + 1) * 128
		b.Run(fmt.Sprintf("bmodexp64-%d", exp), func(b *testing.B) {
			b.ReportAllocs()
			// 0xaa ensures top bit is set, plus "some"
			benchmarkOperation(b, "", randBytes(64)+randBytes(exp, 0xaa)+randBytes(64)+"bmodexp; pop", "int 1")
		})
	}
	for i := range 32 {
		exp := (i + 1) * 128
		b.Run(fmt.Sprintf("bmodexp512-%d", exp), func(b *testing.B) {
			b.ReportAllocs()
			benchmarkOperation(b, "", randBytes(512)+randBytes(exp, 0xaa)+randBytes(512)+"bmodexp; pop", "int 1")
		})
	}
}

// BenchmarkBytesModBitlen shows why we use bitlen in the cost
// function. Exponent of 0x0f is roughly half as costly as exponent of 0xf0,
// even though both are 1 byte. (And RSA uses 3 as an exponent)
func BenchmarkBytesModExpBitlen(b *testing.B) {
	for i := range 32 {
		size := (i + 1) * 128
		b.Run("bmodexp0x0f", func(b *testing.B) {
			b.ReportAllocs()
			benchmarkOperation(b, "", randBytes(size)+"byte 0x0f;"+randBytes(size)+"bmodexp; pop", "int 1")
		})
	}
	for i := range 32 {
		size := (i + 1) * 128
		b.Run("bmodexp0xf0", func(b *testing.B) {
			b.ReportAllocs()
			benchmarkOperation(b, "", randBytes(size)+"byte 0xf0;"+randBytes(size)+"bmodexp; pop", "int 1")
		})
	}
}

func BenchmarkBytesModExp(b *testing.B) {
	type ModexpTestVector struct {
		Base     string
		Exponent string
		Modulus  string
		Name     string
	}

	// Define the accepted test vectors using nested loops
	modexpTestVectors := []ModexpTestVector{}
	incr := 128
	maxDim := 1024
	for baseLen := incr; baseLen <= maxDim; baseLen += incr {
		for expLen := incr; expLen <= maxDim; expLen += incr {
			for modLen := incr; modLen <= maxDim; modLen += incr {
				modexpTestVectors = append(modexpTestVectors, ModexpTestVector{
					Name:     fmt.Sprintf(`TestVector_Dim(%d,%d,%d)`, baseLen, expLen, modLen),
					Base:     randBytes(baseLen),
					Exponent: randBytes(expLen),
					Modulus:  randBytes(modLen),
				})
			}
		}
	}
	b.Run("bmod_cost", func(b *testing.B) {
		b.ReportAllocs()
		progText := randBytes(64) + randBytes(64) + " b%; pop"
		benchmarkOperation(b, "", progText, "int 1")
	})
	b.Run("max_bmodexp_cost", func(b *testing.B) {
		b.ReportAllocs()
		progText := randBytes(4096) + randBytes(4096) + randBytes(4096) + "bmodexp; pop"
		benchmarkOperation(b, "", progText, "int 1")
	})
	// Iterate through the test vectors and benchmark the bmodexp computation
	for _, tv := range modexpTestVectors {
		b.Run(tv.Name, func(b *testing.B) {
			b.ReportAllocs()
			progText := tv.Base + tv.Exponent + tv.Modulus + "bmodexp; pop"
			benchmarkOperation(b, "", progText, "int 1")
		})
	}
}

func TestBytesModExp(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()
	type testOutcome int
	const (
		Accept testOutcome = iota
		Reject
		Panic
	)
	type ModexpTestVector struct {
		Base        string
		Exponent    string
		Modulus     string
		Result      string
		LogicCost   uint64 // The cost of the bmodexp instruction
		TestOutcome testOutcome
	}
	cases := []ModexpTestVector{
		{"0x01", "0x01", "0x", "0x00", 0, Panic},     // Modulo of 0 should panic
		{"0x01", "0x01", "0x0000", "0x00", 0, Panic}, // Modulo of 0 should panic
		{"0x01", "0x01", "0x", "0x01", 0, Panic},     // Modulo of 0 should panic
		{"0x01", "0x01", "0x0000", "0x01", 0, Panic}, // Modulo of 0 should panic
		{"0x54b7", "0x00", "0x01", "0x", 200, Accept},
		{"0x286e0b2a3fea08c786634bdf0a608fb22009c512e6f1f174", "0x9cebf0aae57f76408a", "0xcf5d2d1fdc2e3233adcc13c8b3fc2fb0a3d3c1032ee14288c9026968c59d6fd7f8c9ef82e63bea29304ebb91b150", "0x9e26c7578c46f09e26e67224526193f5af3512662276e54cb91944d9f80514b31fba2d4c6231c97309a79cfc09b0", 507, Accept},
		{"0xb04336dca137d1284edf958923d01c83f6a09e50bcfb1b509c2afe63bca4f64bf28a482f202cdf08e4fad627acde33c4a5206086641acf2ceab1669bf99b5d672dc71a5d2fc7ff99152f2ecb71e95543cb72be06151e3b75c12961773a0b20e59ceb18713ee7313cb3c146b10188a23de2dab3b733d2dbc4b30258e6e8cde85d1c394a76784a2038a0499feaf4851f22c48b30a7eedf02de934f8a31930d90426fd93241862614943e7a6e2e7f3ef9b08ce14030dcb8ca51d53743ac", "0x3bc794defa8e", "0xf418c1ba14622a93b40859b6fa5c8869ceeab204991a18bba8b414a03bab048c016a98c190ca7f4edb82745e8d91ce930b28c3e8c6f783ff6ea7cf4e092fe845d81189c8d77e4d6b2a3c967ed3d64a7310be13260589531e6485ddf9b065bed8142d7189fe22e213847bc0e10c5ff21e5f12c513f91357db5de6dc879f1e622dc386be6521f48cd476adb021050c09b913147ccb0c7e9ea2712f63b1c2273c4eb70267d366c8eb9548d3bcc19972dce8538767cd53d010e35a3bbab920afd498184d587f3f081fcc7018fd9ad448076a4a8ff231fc", "0x7d01fce371b80532a8ba65fc442e3adb4a5cae46d734258d342fbabaad7e83b14474fd21a5cee7e4a53f3de7e6f3c497b893f0cf23d9a743c4dfa736fb8080d54083a03b20f598ec1eed1d83714465914aa9171cdb1c3a56fb9c021e0c80f44a4d2b4b5c4e078fdc818474af5e0a334b25ac3f069d2dcc72dca335d05ac24fdbfabf07b17ce6e9fb996100509545bd9a0e5df48215112e04a68b2cc700b1a379e3a5df9d2913498cb8e15c92bec53a3c5775dd7fdfa9a5b515f738c88dc404b09cc2a4c389ee6334da58364d5c22482b905a1ec3fc", 2592, Accept},
		{"0x3e1c6d61105021cbd5388fbad1bd004929932619359415cbf63b2a5ba087a615ac387a710e19affd897f750581c815ab75c56ab0f7f43fe29ef0a2c10a582ee7cbf548a1e58d3be900f2edd57ecc3e3ce2543730a5b7241f640215", "0xa80794b876bc56a2031a0fe504ee9047dac05791fe78917dc82dc06bdeb519ce285713e9c3a97d4bbe065be9cdf6d7d845f0206bad7d23eace4856", "0x33f27976478080519dd19e89950d04b1e65f3e4bd5e684b234f68584c54415f2896440391e2b36a65bb3e3fafb10a9c6ffae6c5b8ce5223bf786fa0a7a3a6d5a54985f26936fdbc70b2b94790d712de3ed0ecf34332e805da31224f83041efa739e958634529d94f8bd4c64d39a8e3e3d2741623912d97c33751aa0d", "0x2d6f597bb2771b5e9eafeeebb220a157d9bc7a7acb3eb0fed18272da51d1abef322e4b85b02c7ac79bddae7ac8708cc7f01e774e8e8b87023374567b52c3f8e9df28063abfdcb19152d95e2b6b3077acfb687e45e32164c132b0931c587eaa3f34ac474ec0512c6b57bad2b98ef83dca85d23a7c9b114893170501f2", 10363, Accept},
		{"0x4de679ab106df6431f37cb20e60491eab2a00fda0017e3788856589e332db9596eda1ec03ea4e641ae4b22e7923662537ddd4ae130148ecd193b5e4578d7409e5371b50f45e92293d8c786b824eb26dd6c31419f8ad6383327772cd10b84b40d10a7438c1b3a92aedb718a0c97137e1064ad67484d7206487902ef8f8b7a34318474ba0f6113e9dc15c4e30e7711f641a82f6672ad2e039a09228db6db2287", "0xd021d1d6cc99274c090b16afe3a1c4314f48316dcd2a2cdebaaa2896c51c9f3d779bd7be01a2fdc17093c2c9a633", "0xb7a91bb84e0abaef90b4d4293d0c4968a2", "0x62c668fb320f44c7fec283e7827a6ce1ff", 12083, Accept},
		{"0x51ebd23d2a02f976d3d9aae2061e06a8c0452b4b556443606ade0c71ea57a8463bbad81a5d6312237f8ab6194e18feb808631d40318b608cb7fe876d3ded24f04bbddc053a3be4579f5c6cdadc3ed1192a5016c609ff80a76677ed214ed0e5e04bf70bc03b6c15b999c4d343466b0324fa5a0a42ad60885885ab43f928991f30783819caba87e247837b0948b1d8d050ed", "0x1fbe100e76befa9e13", "0x576df8720f308d6e342644063415492caa9d4a11c80030e25f7541e56e62869d15b08a8807d789870194b0c7a325cf9d13e49c654b08965c8eb3e144145fb7", "0x197bcf7eafab09fa4776dbaa9ebb8cc2ff6787d1a800819cd75f507a1372157085dc171f6e501edf2b44d46038d3fa49e0db8ebac4b41461bdce184585edd9", 2117, Accept},
		{"0x9c61f9e2209144eeabc02cb02e5db1484544e33478eb374a18be5baf71b16e91d9ab86882984ea9ba16fde77eb0ef161c497c1883e0cbdb8dca844ad7b8f270073ab640c385e4f9512", "0x648110c896453b6f1a3a0b234f5c0f8b7c4b4d958458280372a6232f9d98cd1420df6a5691fa1bf773f6bd", "0xe5e14e935f795ad814f54d95248b0102b2b0c351e8a5112541343c024d90dfa43c702eea820354a2670563425ee515c4dcc2c6bed73234b0e77384f3ba64a1b8b068149b2363566cdf9c80af", "0xa1d077b5157b4e829c814a0e8fb7e9b83e30e65ff46d3264dc619063a2de57fb171e050c5ec85715b73a8a8a7d2b155a6a77855edea62c9a6850c8dec1551bde227304b7df2811245405fdd5", 3525, Accept},
		{"0xe1b779ff6951aee456aeaf87a963678eaaae4ed61f387b68e4f196ff71440a5955b9a8c2144dbe4c00717b157564f21b54c8c3934bb43754af039068ba03d1ab7c53f9d5526842cb", "0x6bc12883963b0f0b6eb6c275bcc9", "0x072c23cab0e4dbc633b86e45a6b9bdfaf87076bf618c08b142d42b7ad8c3ea4795e873dad518ace0f9e84a4e265191972e303bfbbd6cff781de09a1ccb19f0dc5d874dfc3b89bfa666b391068c3dc9c183f04e4dcd1ec80ed92fd4c792e102904817a41ae1208ed39a9484d61e10491859924a0a04a9455e36458702dcd8a312176e9a05e0e45a14783ecaa7e93f410a8a51848ad706d014467d634fa7c0d6756f54e5f980", "0x06d4a5ffa4568bf3bc20ff29f74941b212ec9121d936d6becbfde46dca5034e0749fead5293e42331a922d1e6a64efc42bf165ca3853c2a80248d32fdf70a6c233ef32851b85ea1c1b51ca364dd2bcd9f25a6249c014dc36b123382099f5f060eb8c0b6d13e4facb932fa49ae140b917dad9e82076e71b407928405aa449fb66eacd97429296a8f8d3cafd8660d124f5d98e6fdb9f1a74ba10a76b724bb8ef4ec98c749b6b", 4007, Accept},
		{"0x4594ea63dd8b77f34701aaae1f430d4adee9811213bde681fd750cd4bff65322654553180248e580de54da02365dbcc61ad6039a61c0c5783872038cccf618ce10757b50d4f58529cc2d6d9ca30543e8ddedc481757a679101", "0xd32aab68fadf838e361d75da2ce241dd0b95dd38e3ceb860975e39d4eab04e84581269d22dc8880395c6c091b3859cd9fa031186af5bc0f23d6ada8fbfae9f7dcc307d862c", "0x7b646597ae005c1b0c2bc981917294e669a47fc12b27d08c1741caa5d31c68", "0x317c66d1e4a6e22d60a1299aaec61f9e8668e08bb94b11e59e32d1daad8e11", 7122, Accept},
		{"0x44dfe16a0cc499362a5a6b6b5d4167b9e45c3bbd1b98b494e99ff71010013a8c816816f112a69f9e70a320625c149555e1276bad70999da1b3c124e5c54cbeb02b534f845ffdfcede15b01fa8d0bd8f22b95ace6cf5d0aa97cb81f1688afecef51cc48fdf3155185090e8249795af2c26997ea1a915fd85b5a8bf9cce7c7dbbb6f268cd424e6b86331d32a6e4cf783957160", "0xc392b4bfe312f474a02d0860823a05a8a6d5846f1db0a9245a1f64cb354b5ab91590d24ebba8ef68a369d25932b1acfcb33b6af52a260313bcc0493c", "0x5492af9556e685fd639f80e42fae3e0cc4588233f4683017d376c5746b3eea", "0x4e13bec8183024e881e1688458437e0a3c49959c3099329c4540c0b5840a70", 13688, Accept},
		{"0x2ea1312db704ff29e0", "0x038302a78381a38adcb7581cbeb7a0797289d82d14a85cf4c36df72c5b5c3d464c4a280f930a85ef4aefb54ce935d01a18afd42d9a679140a360f2b185ac37fde9890d2808a6675e3d73bc696921babefa9cb1985b948e65734fae0515f0e6b7ef782bef9f1a4921c5df3e340e764bf6c347614c5649e645f3bdaaa2c7dbcc16b5107056", "0x71166d7a0b32f8cbd2f682474b61c5535e2867562bcf5dd5e43d2a4e036b78e871b18145e6da2ef327da994965ade4bb985f4f2402da936a6f90d0913512add104dc10741c06b948e911b8fbe9", "0x4540d8df3bc9cd82ff6e431440f65fd58165a43783dccabc315f5a33fa3a581068ca5ae3ede591e302fc863eff657b962d0e671235fc97456439921ec9023eff5b8256b056eb47eae5911f2e6b", 10598, Accept},
		{"0x1f206df741a36c542fb5e609c9299e62a96ee677ca7266d85d086d4ebd6ab9b52c56539c41b0a1a69a0a5dfc794cd6076360643660147c053f821992bf5c787a1fed53eab8f61e0d538aa3a352616774d419c7be55415e60a86f296d1baa199284ebd2ff12eb2b84a7dfedbe1d34efd3219265f302b91963416e42145bfbdf7d0132b1d32c98129521a61d92e2318f94b87f96f68eefe5263717999ab1780f9c15e895a5c188e47518b209f61c3a501e315c4ea0504de653d9b3f9d25658c1c30b99fa6b2a02ff99838d04b86bbeb13ca94d90fd96aca7eae17bc76cf13e33cf37769ad7bf98c6f151c3961d2157aa63ebd577f2f5dbb67805df9a649942843c", "0x37c463", "0x8eb38552534a9ca188412677f154eeba8f011cf6ae00472dcca54c068d57825ff7f703b1a8380d2fc9a7e1e142f8770a7da52e2d47638853aacbe450a80f2c35a9ce0e5feca7bfff871252ec2c5754cafdcde3cd20ce4767c23042570d3d9641e8517ea4c3f10d7f4ea927824d948aed87de2b856347faba08be786ad3d9f30cd1bc4b036dd4a0053c59d11fc2840aefde47222a0273323f45b08539313de7393d24ade84f8f57c719986db04a0f3f483375e5779c8b8ce913991a80ea6cb368bb3f1f2c3dc3d424d7c0ae607c6d052dc7b0ae170250e1ad10e6b327857cb8610904c526d51430c31931d4ba3d5ebab8d6321c48d6d482f5b129f69871f4405f", "0x1d6e8af1caa1098ce2429e32eb831598f6b28a65376e54fe863283b545949586e2f3b41285d6047fcd52d164be131325f80412d2ca8bb84dd945ae69b3e1bc4fa861905b1f3032ea7279d2ed3c03f78ece1c0d0f159e0a4776d1ee47516e4379105491c37d6bc86bc26420966076d114f5a4091e800259f59073fd5f7c0100fbcbc10a9f7cef6fcd03c04ae97b54994ea479e168bc00ae9ea84ad07497aa470d3d438ccfa669de5d99ccf36a2ab1773378101123f5bcdd9a6f5a1df889b8a0bbc071d692d68b69801cfa467bdcb8d00dc5f32be5ca907433667691527534c229701ec929ef836c7caef7a088205082f98a08860ed72d383e6ac256aa3680f3c6", 1744, Accept},
		{"0x7c391cf4e56c7c104d90177402b2e1a0f9179a06304f4357e4b146e116cd12e0f1c12bfc66171b8c8be104d09c304c340e125c4b6fda63b94315d74ad0e8b8178edac81b475da5dc7e825c309a4c0b5fb3c3e0bd7f94dc661cd8ac546940779e54edf58c6ace5589914541935bc66fff64442d8bc2e6dc8420257c8ab0a877729fe8", "0x74d69cdea330c38633c7bca9fb46d2e1e2050e5220c5fa3194584c62b4ebd3e85a70fd2f994d04681fc8aa32e580f87484b78ff8d3bab0412874e55772411288f4a6196f9da6db7aaebbf0d62e4e42275dfa475ac35802d912aacfb4f77e945f4e5e3c28610ddbd479280df848cd57829746fcc6452a5d4127b4f8b27a3149bc", "0x9000b0b587f64e78f51645a75d98b64d7fa1001d1636bcae53ea41f9f955f67f79c442adbca55d59c61642ed91364feef5e5147ed229cd5ff1d31b6c333a65f95e80c576f11ce4790c3162c351bd7df796c6e2184a387edea127c6ddf46a6eae6ade4066de609d655832b98b", "0x810f16edd6ffee0cad631b2f59ad6b3847f80974ce4376353ad1f8f487dae65e93ddb9552cc93b0725acb1ba3551132c138ef730568c3fde71918608edf3f78130170124d0a4d3d28fcd2cefb256465eb18e80ea0576fd1df44e76786a450285a0eef852b7df639925795293", 23991, Accept},
		{"0x9b7e403f0d0134635f90d344dbce30ac511e8e5e274a3436ccb75503d0ee72a3ba59c2a9b774ee74abe082e09702c65151186706c62200241d306d8cb18b40278c885222db5d001aecceff20e4be25ed83d4ff7d40c4c6e513a63238a5c07e45da3a24868caa67fae36047d955a648dd1c741284cdb8bc282c01b9d66d2c5b651268ff1d50356f1dc6be6d59814d7787e6", "0x30c54b", "0x093fd6b228d5d2268a36b0a1b8fb7dbcb4669c22e0cc2a5deaa3c3da890c5fa23dc0", "0x2a3d94206458cce1a0cee7ef45b3812de4f2ae4ee9b347acf55385eca217159f6b76b7c14774aa54e9667bb172d66b25d907682576a2ec7f2038c07e4f", 0, Reject},
	}

	for i, tc := range cases {
		// use subtests so that we can run all tests despite failures
		t.Run(fmt.Sprintf("case %d", i), func(t *testing.T) {
			progText := fmt.Sprintf("pushbytes %s; pushbytes %s; pushbytes %s; bmodexp; pushbytes %s; ==",
				tc.Base, tc.Exponent, tc.Modulus, tc.Result)
			switch tc.TestOutcome {
			case Accept:
				testAccepts(t, progText, 12)
				testCost(t, progText, tc.LogicCost+5, 12) // 4 pushbytes, and ==
			case Reject:
				testRejects(t, progText, 12)
				// ensure nobody thinks they are testing a cost here
				require.Zero(t, tc.LogicCost)
			case Panic:
				testPanics(t, progText, 12)
				// ensure nobody thinks they are testing a cost here
				require.Zero(t, tc.LogicCost)
			}
		})
	}

}

func TestBytesMath(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	testAccepts(t, "byte 0x01; byte 0x01; b+; byte 0x02; ==", 4)
	testCost(t, "byte 0x01; byte 0x02; b+; byte 0x03; ==", 2+10+2, 6)
	testCost(t, "byte 0x01; byte 0x02; b+; byte 0x03; ==", 2+2+2, 12)
	testAccepts(t, "byte 0x01FF; byte 0x01; b+; byte 0x0200; ==", 4)

	effs := strings.Repeat("ff", 64)
	// 64 byte long inputs are accepted, even if they produce longer outputs
	testAccepts(t, fmt.Sprintf("byte 0x%s; byte 0x10; b+; len; int 65; ==", effs), 4)
	// 4096 byte inputs that sum to 4097 byte outputs panic, no matter the version.
	testPanics(t, notrack(fmt.Sprintf("byte 0x%s; byte 0x10; b+; len; int 4097; ==", strings.Repeat("ff", 4096))), 4)
	// 65 byte inputs are not ok for b+ until v12.
	p := fmt.Sprintf("byte 0x%s00; byte 0x10; b+; len; int 65; ==", effs)
	testPanicRange(t, notrack(p), 4, 11)
	testAcceptRange(t, p, 12, AssemblerMaxVersion)
	testCost(t, p, 2+6+3, 12)

	testAccepts(t, `byte 0x01; byte 0x01; b-; byte ""; ==`, 4)
	testAccepts(t, "byte 0x0200; byte 0x01; b-; byte 0x01FF; ==", 4)
	// returns are smallest possible
	testAccepts(t, "byte 0x0100; byte 0x01; b-; byte 0xFF; ==", 4)
	testPanics(t, "byte 0x01; byte 0x02; b-; int 1; return", 4)

	// 65 byte inputs are not ok for b- until v12.
	p = fmt.Sprintf("byte 0x%s00; byte 0x10; b-; len; int 65; ==", effs)
	testPanicRange(t, notrack(p), 4, 11)
	testAcceptRange(t, p, 12, AssemblerMaxVersion)
	testCost(t, p, 2+6+3, 12)

	testAccepts(t, "byte 0x10; byte 0x10; b*; byte 0x0100; ==", 4)
	testAccepts(t, "byte 0x100000000000; byte 0x00; b*; byte b64(); ==", 4)
	testCost(t, "byte 0x100000000000; byte 0x00; b*; byte b64(); ==", 20+4, 6)
	testCost(t, "byte 0x100000000000; byte 0x2000; b*; byte 0x0200000000000000; ==", 5+4, 12)

	testAccepts(t, "byte 0x01; byte 0x01; b/; byte 0x01; ==", 4)
	testPanics(t, "byte 0x0200; byte b64(); b/; int 1; return", 4)
	testPanics(t, "byte 0x01; byte 0x00; b/; int 1; return", 4)
	p = "int 65; bzero; byte 0x01; b/; byte 0x; =="
	testPanicRange(t, p, 4, 11)
	testAcceptRange(t, p, 12, AssemblerMaxVersion)

	testAccepts(t, "byte 0x10; byte 0x07; b%; byte 0x02; ==; return", 4)
	testPanics(t, "byte 0x01; byte 0x00; b%; int 1; return", 4)
	p = "byte 0x01; int 64; bzero; concat; byte 0x10; b%; byte 0x00; b=="
	testPanicRange(t, p, 4, 11)
	testAcceptRange(t, p, 12, AssemblerMaxVersion)

	// Even 128 byte outputs are ok
	p = fmt.Sprintf("byte 0x%s; byte 0x%s; b*; len; int 128; ==", effs, effs)
	testAccepts(t, p, 4)
	testCost(t, p, 26, 6) // 20 + 6 (5 obvious instructions plus bytecblock)
	assert.Equal(t, 12, mulComplexity(64, 64))
	testCost(t, p, 18, 12) // 12 + 6
	// But not 65 byte inputs (until v12)
	p = fmt.Sprintf("byte 0x%s; byte 0xff; concat; byte 0xff; b*; len; int 66; ==", effs)
	testPanicRange(t, p, 4, 11)
	testAcceptRange(t, p, 12, AssemblerMaxVersion)
	assert.Equal(t, 8, mulComplexity(65, 1))
	testCost(t, p, 16, 12) // 8 + 8 (7 obvious instructions, plus bytecblock)

	testAccepts(t, "byte 0x01; bsqrt; byte 0x01; ==; return", 6)
	testAccepts(t, "byte 0x00; bsqrt; byte 0x; ==; return", 6)
	testAccepts(t, "byte 0x10; bsqrt; byte 0x04; ==; return", 6)
	testAccepts(t, "byte 0x11; bsqrt; byte 0x04; ==; return", 6)
	testAccepts(t, "byte 0xffffff; bsqrt; len; int 2; ==; return", 6)
	// 64 byte long inputs are accepted
	p = fmt.Sprintf("byte 0x%s; bsqrt; len; int 32; ==", effs)
	testAccepts(t, p, 6)
	testCost(t, p, 44, 6)  // 40 + 4
	testCost(t, p, 73, 12) // 69 + 4
	// 65 byte inputs are not ok until v12 (no track allows assembly)
	p = notrack(fmt.Sprintf("byte 0x%s00; bsqrt; len; int 33; ==", effs))
	testPanicRange(t, p, 6, 11)
	testAcceptRange(t, p, 12, AssemblerMaxVersion)
	testCost(t, p, 74, 12) // 70 + 4

	// 128, mostly for cost test
	p = notrack(fmt.Sprintf("byte 0x%s%s; bsqrt; len; int 64; ==", effs, effs))
	testPanicRange(t, p, 6, 11)
	testAcceptRange(t, p, 12, AssemblerMaxVersion)
	testCost(t, p, 145, 12) // 141 + 4
}

func TestMulComplexity(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	a := assert.New(t)
	// test with sizes that are roughly equal
	a.Equal(5, mulComplexity(0, 0))
	a.Equal(5, mulComplexity(6, 7))
	a.Equal(6, mulComplexity(16, 7))
	a.Equal(6, mulComplexity(16, 16))
	a.Equal(7, mulComplexity(32, 16))
	a.Equal(21, mulComplexity(128, 128))
	// demonstrate nice continuity near the changeover at 512
	a.Equal(126, mulComplexity(511, 511))
	a.Equal(130, mulComplexity(512, 512))
	a.Equal(130, mulComplexity(513, 513))
	a.Equal(130, mulComplexity(513, 511))

	// test for bad discontinuities at 512
	for la := range 4096 {
		below := mulComplexity(la, 511)
		above := mulComplexity(la, 512)
		a.GreaterOrEqual(above, below)             // bigger input has bigger cost
		a.GreaterOrEqual(1+la/25, above-below, la) // the cost goes up a "reasonable" amount, compared to length
	}

	// silly exhaustive test. only takes a few seconds
	for la := range 4096 {
		for lb := range 4096 {
			a.Equal(mulComplexity(la, lb), mulComplexity(lb, la))
		}
	}
}

func TestBytesCompare(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	testAccepts(t, "byte 0x10; byte 0x10; b<; !", 4)
	testAccepts(t, "byte 0x10; byte 0x10; b<=", 4)

	p := "byte 0x10; int 65; bzero; b<="
	testPreexist(t, p, 4)
	testPanicRange(t, p, 4, 11)
	testRejectRange(t, p, 12, AssemblerMaxVersion)

	testAccepts(t, "byte 0x10; int 64; bzero; b>", 4)
	p = "byte 0x10; int 65; bzero; b>"
	testPreexist(t, p, 4)
	testPanicRange(t, p, 4, 11)
	testAcceptRange(t, p, 12, AssemblerMaxVersion)
	testAccepts(t, "byte 0x1010; byte 0x10; b<; !", 4)

	testAccepts(t, "byte 0x2000; byte 0x70; b<; !", 4)
	testAccepts(t, "byte 0x7000; byte 0x20; b<; !", 4)

	// All zero input are interesting, because they lead to bytes.Compare being
	// called with nils.  Show that is correct.
	testAccepts(t, "byte 0x10; byte 0x00; b<; !", 4)
	testAccepts(t, "byte 0x10; byte 0x0000; b<; !", 4)
	testAccepts(t, "byte 0x00; byte 0x10; b<", 4)
	testAccepts(t, "byte 0x0000; byte 0x10; b<", 4)
	testAccepts(t, "byte 0x0000; byte 0x00; b<; !", 4)
	testAccepts(t, "byte 0x; byte 0x00; b==", 4)

	testAccepts(t, "byte 0x11; byte 0x10; b>", 4)
	testAccepts(t, "byte 0x11; byte 0x0010; b>", 4)
	testAccepts(t, "byte 0x1010; byte 0x11; b>", 4)

	testAccepts(t, "byte 0x11; byte 0x10; b>=", 4)
	testAccepts(t, "byte 0x11; byte 0x0011; b>=", 4)
	p = "byte 0x10; int 65; bzero; b>="
	testPreexist(t, p, 4)
	testPanicRange(t, p, 4, 11)
	testAcceptRange(t, p, 12, AssemblerMaxVersion)

	testAccepts(t, "byte 0x11; byte 0x11; b==", 4)
	testAccepts(t, "byte 0x0011; byte 0x11; b==", 4)
	testAccepts(t, "byte 0x11; byte 0x00000000000011; b==", 4)
	testAccepts(t, "byte 0x00; int 64; bzero; b==", 4)
	p = "byte 0x00; int 65; bzero; b=="
	testPreexist(t, p, 4)
	testPanicRange(t, p, 4, 11)
	testAcceptRange(t, p, 12, AssemblerMaxVersion)

	testAccepts(t, "byte 0x11; byte 0x00; b!=", 4)
	testAccepts(t, "byte 0x0011; byte 0x1100; b!=", 4)
	testPanics(t, notrack("byte 0x11; int 17; b!="), 4)
	p = "byte 0x10; int 65; bzero; b!="
	testPreexist(t, p, 4)
	testPanicRange(t, p, 4, 11)
	testAcceptRange(t, p, 12, AssemblerMaxVersion)
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
	testPanics(t, notrack("int 4097; bzero; len; int 4097; =="), 4)
}

func TestBytesConversions(t *testing.T) {
	partitiontest.PartitionTest(t)

	t.Parallel()
	testAccepts(t, "byte 0x11; byte 0x10; b+; btoi; int 0x21; ==", 4)
	testAccepts(t, "byte 0x0011; byte 0x10; b+; btoi; int 0x21; ==", 4)
}

func TestPcDetails(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	var tests = []struct {
		source string
		pc     int
		det    string
	}{
		{"int 1; int 2; -", 5, "pushint 1; pushint 2; -"},
		{"int 1; err", 3, "pushint 1; err"},
		{"int 1; dup; int 2; -; +", 6, "dup; pushint 2; -"},
		{"b end; end:", 4, ""},
	}
	for i, test := range tests {
		t.Run(fmt.Sprintf("i=%d", i), func(t *testing.T) {
			t.Parallel()
			ops := testProg(t, test.source, LogicVersion)
			ep, _, _ := makeSampleEnv()
			ep.Trace = &strings.Builder{}

			pass, cx, err := EvalContract(ops.Program, 0, 888, ep)
			require.Error(t, err)
			require.False(t, pass)
			require.NotNil(t, cx) // cx comes back nil if we couldn't even run

			assert.Equal(t, test.pc, cx.pc, ep.Trace.String())

			pc, det := cx.pcDetails()
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
				testProg(t, source, AssemblerMaxVersion, exp(0, "unknown opcode..."))
			} else {
				testAccepts(t, source, fidoVersion)
			}
		} else {
			if LogicVersion < fidoVersion {
				testProg(t, source, AssemblerMaxVersion, exp(0, "unknown opcode..."))
			} else {
				testPanics(t, source, fidoVersion, tc.error)
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
int ` + fmt.Sprintf("%d", testLogicBudget-3-1) + ` // base64_decode cost = 1
==
`
	testAccepts(t, source, fidoVersion)

	source = `
byte "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
base64_decode URLEncoding
pop
global OpcodeBudget
int ` + fmt.Sprintf("%d", testLogicBudget-3-5) + ` // base64_decode cost = 5 (64 bytes -> 1 + 64/16)
==
`
	testAccepts(t, source, fidoVersion)

	source = `
byte "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz01234567"
base64_decode URLEncoding
pop
global OpcodeBudget
int ` + fmt.Sprintf("%d", testLogicBudget-3-5) + ` // base64_decode cost = 5 (60 bytes -> 1 + ceil(60/16))
==
`
	testAccepts(t, source, fidoVersion)

	source = `
byte "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_AA=="
base64_decode URLEncoding
pop
global OpcodeBudget
int ` + fmt.Sprintf("%d", testLogicBudget-3-6) + ` // base64_decode cost = 6 (68 bytes -> 1 + ceil(68/16))
==
`
	testAccepts(t, source, fidoVersion)
}

func TestIsPrimitive(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()
	testCases := []struct {
		text []byte
	}{
		{
			text: []byte(`null`),
		},
		{
			text: []byte(`[1, 2, 3]`),
		},
		{
			text: []byte(`2`),
		},
	}
	for _, s := range testCases {
		isPrimitive, err := isPrimitiveJSON(s.text)
		require.Nil(t, err)
		require.True(t, isPrimitive)
	}

	notPrimitive := []struct {
		text []byte
	}{
		{
			text: []byte(`{"key0": "1","key1": "2", "key2":3}`),
		},
		{
			text: []byte(`{}`),
		},
	}
	for _, s := range notPrimitive {
		primitive, err := isPrimitiveJSON(s.text)
		require.Nil(t, err)
		require.False(t, primitive)
	}
}

func TestProtocolParseDuplicateErrMsg(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()
	text := `{"key0": "algo", "key0": "algo"}`
	var parsed map[string]json.RawMessage
	err := protocol.DecodeJSON([]byte(text), &parsed)
	require.Contains(t, err.Error(), "cannot decode into a non-pointer value")
	require.Error(t, err)
}

func TestOpJSONRef(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	testCases := []struct {
		source             string
		previousVersErrors []expect
	}{
		{
			source: `byte  "{\"key0\": 0,\"key1\": \"algo\",\"key2\":{\"key3\": \"teal\", \"key4\":3}, \"key5\": 18446744073709551615 }";
			byte "key0";
			json_ref JSONUint64;
			int 0;
			==`,
			previousVersErrors: []expect{exp(3, "unknown opcode: json_ref")},
		},
		{
			source: `byte  "{\"key0\": 0,\"key1\": \"algo\",\"key2\":{\"key3\": \"teal\", \"key4\": 3}, \"key5\": 18446744073709551615 }";
			byte "key5";
			json_ref JSONUint64;
			int 18446744073709551615; //max uint64 value
			==`,
			previousVersErrors: []expect{exp(3, "unknown opcode: json_ref")},
		},
		{
			source: `byte  "{\"key0\": 0,\"key1\": \"algo\",\"key2\":{\"key3\": \"teal\", \"key4\": 3}, \"key5\": 18446744073709551615 }";
			byte "key1";
			json_ref JSONString;
			byte "algo";
			==`,
			previousVersErrors: []expect{exp(3, "unknown opcode: json_ref")},
		},
		{
			source: `byte  "{\"key0\": 0,\"key1\": \"\\u0061\\u006C\\u0067\\u006F\",\"key2\":{\"key3\": \"teal\", \"key4\": 3}, \"key5\": 18446744073709551615 }";
			byte "key1";
			json_ref JSONString;
			byte "algo";
			==`,
			previousVersErrors: []expect{exp(3, "unknown opcode: json_ref")},
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
			previousVersErrors: []expect{exp(3, "unknown opcode: json_ref"), exp(5, "unknown opcode: json_ref")},
		},
		{
			source: `byte  "{\"key0\": 0,\"key1\": \"algo\",\"key2\":{\"key3\": \"teal\", \"key4\": {\"key40\": 10}}, \"key5\": 18446744073709551615 }";
			byte "key2";
			json_ref JSONObject;
			byte "key3";
			json_ref JSONString;
			byte "teal"
			==`,
			previousVersErrors: []expect{exp(3, "unknown opcode: json_ref"), exp(5, "unknown opcode: json_ref")},
		},
		{
			source: `byte  "{\"key0\": 0,\"key1\": \"algo\",\"key2\":{\"key3\": \"\\"teal\\"\", \"key4\": {\"key40\": 10}}, \"key5\": 18446744073709551615 }";
			byte "key2";
			json_ref JSONObject;
			byte "key3";
			json_ref JSONString;
			byte ""teal"" // quotes match
			==`,
			previousVersErrors: []expect{exp(3, "unknown opcode: json_ref"), exp(5, "unknown opcode: json_ref")},
		},
		{
			source: `byte  "{\"key0\": 0,\"key1\": \"algo\",\"key2\":{\"key3\": \" teal \", \"key4\": {\"key40\": 10}}, \"key5\": 18446744073709551615 }";
			byte "key2";
			json_ref JSONObject;
			byte "key3";
			json_ref JSONString;
			byte " teal " // spaces match
			==`,
			previousVersErrors: []expect{exp(3, "unknown opcode: json_ref"), exp(5, "unknown opcode: json_ref")},
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
			previousVersErrors: []expect{exp(3, "unknown opcode: json_ref")},
		},
		{
			source: `byte  "{\"rawId\": \"responseId\",\"id\": \"0\",\"response\": {\"attestationObject\": \"based64url_encoded_buffer\",\"clientDataJSON\":  \" based64url_encoded_client_data\"},\"getClientExtensionResults\": {},\"type\": \"public-key\"}";
			byte "response";
			json_ref JSONObject;
			byte "{\"attestationObject\": \"based64url_encoded_buffer\",\"clientDataJSON\":  \" based64url_encoded_client_data\"}" // object as it appeared in input
			==`,
			previousVersErrors: []expect{exp(3, "unknown opcode: json_ref")},
		},
		{
			source: `byte  "{\"rawId\": \"responseId\",\"id\": \"0\",\"response\": {\"attestationObject\": \"based64url_encoded_buffer\",\"clientD\\u0061taJSON\":  \" based64url_encoded_client_data\"},\"getClientExtensionResults\": {},\"type\": \"public-key\"}";
			byte "response";
			json_ref JSONObject;
			byte "{\"attestationObject\": \"based64url_encoded_buffer\",\"clientD\\u0061taJSON\":  \" based64url_encoded_client_data\"}" // object as it appeared in input
			==`,
			previousVersErrors: []expect{exp(3, "unknown opcode: json_ref")},
		},
		{
			source: `byte  "{\"rawId\": \"responseId\",\"id\": \"0\",\"response\": {\"attestationObject\": \"based64url_encoded_buffer\",\"clientDataJSON\":  \" based64url_encoded_client_data\"},\"getClientExtensionResults\": {},\"type\": \"public-key\"}";
			byte "response";
			json_ref JSONObject;
			byte "clientDataJSON";
			json_ref JSONString;
			byte " based64url_encoded_client_data";
			==`,
			previousVersErrors: []expect{exp(3, "unknown opcode: json_ref"), exp(5, "unknown opcode: json_ref")},
		},
		{
			source: `byte  "{\"\\u0072\\u0061\\u0077\\u0049\\u0044\": \"responseId\",\"id\": \"0\",\"response\": {\"attestationObject\": \"based64url_encoded_buffer\",\"clientDataJSON\":  \" based64url_encoded_client_data\"},\"getClientExtensionResults\": {},\"type\": \"public-key\"}";
			byte "rawID";
			json_ref JSONString;
			byte "responseId"
			==`,
			previousVersErrors: []expect{exp(3, "unknown opcode: json_ref")},
		},
		// JavaScript MAX_SAFE_INTEGER
		{
			source: `byte "{\"maxSafeInt\": 9007199254740991}";
			byte "maxSafeInt";
			json_ref JSONUint64;
			int 9007199254740991;
			==`,
			previousVersErrors: []expect{exp(3, "unknown opcode: json_ref")},
		},
		// maximum uint64
		{
			source: `byte "{\"maxUint64\": 18446744073709551615}";
			byte "maxUint64";
			json_ref JSONUint64;
			int 18446744073709551615;
			==`,
			previousVersErrors: []expect{exp(3, "unknown opcode: json_ref")},
		},
		// larger-than-uint64s are allowed if not requested
		{
			source: `byte "{\"maxUint64\": 18446744073709551616, \"smallUint64\": 0}";
			byte "smallUint64";
			json_ref JSONUint64;
			int 0;
			==`,
			previousVersErrors: []expect{exp(3, "unknown opcode: json_ref")},
		},
	}

	for _, s := range testCases {
		for v := uint64(2); v < fidoVersion; v++ {
			expectedErrs := s.previousVersErrors
			if fidoVersion <= AssemblerMaxVersion {
				for i := range expectedErrs {
					if strings.Contains(expectedErrs[i].s, "json_ref") {
						expectedErrs[i].s = fmt.Sprintf("json_ref opcode was introduced in v%d", fidoVersion)
					}
				}
			}
			testProg(t, s.source, v, expectedErrs...)
		}
		if fidoVersion > AssemblerMaxVersion {
			continue
		}
		ops := testProg(t, s.source, AssemblerMaxVersion)

		testLogicBytes(t, ops.Program, defaultSigParams())
	}

	failedCases := []struct {
		source             string
		error              string
		previousVersErrors []expect
	}{
		{
			source:             `byte  "{\"key0\": 1 }"; byte "key0"; json_ref JSONString;`,
			error:              "json: cannot unmarshal number into Go value of type string",
			previousVersErrors: []expect{exp(1, "unknown opcode: json_ref")},
		},
		{
			source:             `byte  "{\"key0\": [1] }"; byte "key0"; json_ref JSONString;`,
			error:              "json: cannot unmarshal array into Go value of type string",
			previousVersErrors: []expect{exp(1, "unknown opcode: json_ref")},
		},
		{
			source:             `byte  "{\"key0\": {\"key1\":1} }"; byte "key0"; json_ref JSONString;`,
			error:              "json: cannot unmarshal object into Go value of type string",
			previousVersErrors: []expect{exp(1, "unknown opcode: json_ref")},
		},
		{
			source:             `byte  "{\"key0\": \"1\" }"; byte "key0"; json_ref JSONUint64;`,
			error:              "json: cannot unmarshal string into Go value of type uint64",
			previousVersErrors: []expect{exp(1, "unknown opcode: json_ref")},
		},
		{
			source:             `byte  "{\"key0\": [\"1\"] }"; byte "key0"; json_ref JSONUint64;`,
			error:              "json: cannot unmarshal array into Go value of type uint64",
			previousVersErrors: []expect{exp(1, "unknown opcode: json_ref")},
		},
		{
			source:             `byte  "{\"key0\": {\"key1\":1} }"; byte "key0"; json_ref JSONUint64;`,
			error:              "json: cannot unmarshal object into Go value of type uint64",
			previousVersErrors: []expect{exp(1, "unknown opcode: json_ref")},
		},
		{
			source:             `byte  "{\"key0\": [1]}"; byte "key0"; json_ref JSONObject;`,
			error:              "json: cannot unmarshal array into Go value of type map[string]json.RawMessage",
			previousVersErrors: []expect{exp(1, "unknown opcode: json_ref")},
		},
		{
			source:             `byte  "{\"key0\": 1}"; byte "key0"; json_ref JSONObject;`,
			error:              "json: cannot unmarshal number into Go value of type map[string]json.RawMessage",
			previousVersErrors: []expect{exp(1, "unknown opcode: json_ref")},
		},
		{
			source:             `byte  "{\"key0\": \"1\"}"; byte "key0"; json_ref JSONObject;`,
			error:              "json: cannot unmarshal string into Go value of type map[string]json.RawMessage",
			previousVersErrors: []expect{exp(1, "unknown opcode: json_ref")},
		},
		{
			source:             `byte  "{\"key0\": 1,\"key1\": \"algo\",\"key2\":{\"key3\": \"teal\", \"key4\": [1,2,3]} }"; byte "key3"; json_ref JSONString;`,
			error:              "key key3 not found in JSON text",
			previousVersErrors: []expect{exp(1, "unknown opcode: json_ref")},
		},
		{
			source: `byte  "{\"key0\": 1,\"key1\": \"algo\",\"key2\":{\"key3\": \"teal\", \"key4\": [1,2,3]}}";
			byte "key2";
			json_ref JSONObject;
			byte "key5";
			json_ref JSONString
			`,
			error:              "key key5 not found in JSON text",
			previousVersErrors: []expect{exp(3, "unknown opcode: json_ref"), exp(5, "unknown opcode: json_ref")},
		},
		{
			source:             `byte  "{\"key0\": -0,\"key1\": 2.5,\"key2\": -3}"; byte "key0"; json_ref JSONUint64;`,
			error:              "json: cannot unmarshal number -0 into Go value of type uint64",
			previousVersErrors: []expect{exp(1, "unknown opcode: json_ref")},
		},
		{
			source:             `byte  "{\"key0\": 1e10,\"key1\": 2.5,\"key2\": -3}"; byte "key0"; json_ref JSONUint64;`,
			error:              "json: cannot unmarshal number 1e10 into Go value of type uint64",
			previousVersErrors: []expect{exp(1, "unknown opcode: json_ref")},
		},
		{
			source:             `byte  "{\"key0\": 0.2e-2,\"key1\": 2.5,\"key2\": -3}"; byte "key0"; json_ref JSONUint64;`,
			error:              "json: cannot unmarshal number 0.2e-2 into Go value of type uint64",
			previousVersErrors: []expect{exp(1, "unknown opcode: json_ref")},
		},
		{
			source:             `byte  "{\"key0\": 1.0,\"key1\": 2.5,\"key2\": -3}"; byte "key0"; json_ref JSONUint64;`,
			error:              "json: cannot unmarshal number 1.0 into Go value of type uint64",
			previousVersErrors: []expect{exp(1, "unknown opcode: json_ref")},
		},
		{
			source:             `byte  "{\"key0\": 1.0,\"key1\": 2.5,\"key2\": -3}"; byte "key1"; json_ref JSONUint64;`,
			error:              "json: cannot unmarshal number 2.5 into Go value of type uint64",
			previousVersErrors: []expect{exp(1, "unknown opcode: json_ref")},
		},
		{
			source:             `byte  "{\"key0\": 1.0,\"key1\": 2.5,\"key2\": -3}"; byte "key2"; json_ref JSONUint64;`,
			error:              "json: cannot unmarshal number -3 into Go value of type uint64",
			previousVersErrors: []expect{exp(1, "unknown opcode: json_ref")},
		},
		{
			source:             `byte  "{\"key0\": 18446744073709551616}"; byte "key0"; json_ref JSONUint64;`,
			error:              "json: cannot unmarshal number 18446744073709551616 into Go value of type uint64",
			previousVersErrors: []expect{exp(1, "unknown opcode: json_ref")},
		},
		{
			source:             `byte  "{\"key0\": 1,}"; byte "key0"; json_ref JSONString;`,
			error:              "error while parsing JSON text, invalid json text",
			previousVersErrors: []expect{exp(1, "unknown opcode: json_ref")},
		},
		{
			source:             `byte  "{\"key0\": 1, \"key0\": \"3\"}"; byte "key0"; json_ref JSONString;`,
			error:              "error while parsing JSON text, invalid json text, duplicate keys not allowed",
			previousVersErrors: []expect{exp(1, "unknown opcode: json_ref")},
		},
		{
			source: `byte  "{\"key0\": 0,\"key1\": \"algo\",\"key2\":{\"key3\": \"teal\", \"key4\": {\"key40\": 10, \"key40\": \"should fail!\"}}}";
			byte "key2";
			json_ref JSONObject;
			byte "key4";
			json_ref JSONObject;
			byte "key40";
			json_ref JSONString
			`,
			error:              "error while parsing JSON text, invalid json text, duplicate keys not allowed",
			previousVersErrors: []expect{exp(3, "unknown opcode: json_ref"), exp(5, "unknown opcode: json_ref"), exp(7, "unknown opcode: json_ref")},
		},
		{
			source: `byte  "[1,2,3]";
			byte "key";
			json_ref JSONUint64
			`,
			error:              "error while parsing JSON text, invalid json text, only json object is allowed",
			previousVersErrors: []expect{exp(3, "unknown opcode: json_ref")},
		},
		{
			source: `byte  "2";
			byte "key";
			json_ref JSONUint64
			`,
			error:              "error while parsing JSON text, invalid json text, only json object is allowed",
			previousVersErrors: []expect{exp(3, "unknown opcode: json_ref")},
		},
		{
			source: `byte  "null";
			byte "key";
			json_ref JSONUint64
			`,
			error:              "error while parsing JSON text, invalid json text, only json object is allowed",
			previousVersErrors: []expect{exp(3, "unknown opcode: json_ref")},
		},
		{
			source: `byte  "true";
			byte "key";
			json_ref JSONUint64
			`,
			error:              "error while parsing JSON text, invalid json text, only json object is allowed",
			previousVersErrors: []expect{exp(3, "unknown opcode: json_ref")},
		},
		{
			source: `byte  "\"sometext\"";
			byte "key";
			json_ref JSONUint64
			`,
			error:              "error while parsing JSON text, invalid json text, only json object is allowed",
			previousVersErrors: []expect{exp(3, "unknown opcode: json_ref")},
		},
		{
			source: `byte "{noquotes: \"shouldn't work\"}";
			byte "noquotes";
			json_ref JSONString;
			byte "shouldn't work";
			==`,
			error:              "error while parsing JSON text, invalid json text",
			previousVersErrors: []expect{exp(3, "unknown opcode: json_ref")},
		},
		// max uint64 + 1 should fail
		{
			source: `byte "{\"tooBig\": 18446744073709551616}";
			byte "tooBig";
			json_ref JSONUint64;
			int 1;
			return`,
			error:              "json: cannot unmarshal number 18446744073709551616 into Go value of type uint64",
			previousVersErrors: []expect{exp(3, "unknown opcode: json_ref")},
		},
	}

	for _, s := range failedCases {
		for v := uint64(2); v < fidoVersion; v++ {
			expectedErrs := s.previousVersErrors
			if fidoVersion <= AssemblerMaxVersion {
				for i := range expectedErrs {
					if strings.Contains(expectedErrs[i].s, "json_ref") {
						expectedErrs[i].s = fmt.Sprintf("json_ref opcode was introduced in v%d", fidoVersion)
					}
				}
			}

			testProg(t, s.source, v, expectedErrs...)
		}
		if fidoVersion > AssemblerMaxVersion {
			continue
		}

		ops := testProg(t, s.source, AssemblerMaxVersion)
		testLogicBytes(t, ops.Program, defaultSigParams(), s.error)
	}

}

func TestTypeComplaints(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	testProg(t, "err; store 0", AssemblerMaxVersion)
	testProg(t, "int 1; return; store 0", AssemblerMaxVersion)
}

func TestSwitchInt(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	// take the 0th label
	testAccepts(t, `
int 0
switch zero one
err
zero: int 1; return
one:  int 0;
`, 8)

	// take the 1th label
	testRejects(t, `
int 1
switch zero one
err
zero: int 1; return
one:  int 0;
`, 8)

	// same, but jumping to end of program
	testAccepts(t, `
int 1; dup
switch zero one
zero: err
one:
`, 8)

	// no match
	testAccepts(t, `
int 2
switch zero one
int 1; return					// falls through to here
zero: int 0; return
one:  int 0; return
`, 8)

	// jump forward and backward
	testAccepts(t, `
int 0
start:
int 1
+
dup
int 1
-
switch start end
err
end:
int 2
==
assert
int 1
`, 8)

	// 0 labels are allowed, but weird!
	testAccepts(t, `
int 0
switch
int 1
`, 8)

	testPanics(t, notrack("switch; int 1"), 8)

	// make the switch the final instruction
	testAccepts(t, `
int 1
int 0
switch done1 done2; done1: ; done2: ;
`, 8)

	// make the switch the final instruction, and don't match
	testAccepts(t, `
int 1
int 88
switch done1 done2; done1: ; done2: ;
`, 8)
}

// TestShortSwitch ensures a clean error, in Check and Eval, when a switch ends early
func TestShortSwitch(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	source := `
	int 1
	int 1
	switch label1 label2
	label1:
	label2:
	`
	ops, err := AssembleStringWithVersion(source, AssemblerMaxVersion)
	require.NoError(t, err)

	// fine as is
	testLogicBytes(t, ops.Program, nil)

	beyond := "switch opcode claims to extend beyond program"

	// bad if a label is gone
	testLogicBytes(t, ops.Program[:len(ops.Program)-2], nil, beyond, beyond)

	// chop off all the labels, but keep the label count
	testLogicBytes(t, ops.Program[:len(ops.Program)-4], nil, beyond, beyond)

	// chop off before the label count
	testLogicBytes(t, ops.Program[:len(ops.Program)-5], nil,
		"bare switch opcode at end of program", "bare switch opcode at end of program")

	// chop off half of a label
	testLogicBytes(t, ops.Program[:len(ops.Program)-1], nil, beyond, beyond)
}

func TestMatch(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	// take the 0th label with int cases
	testAccepts(t, `
int 99
int 100
int 99
match zero one
err
zero: int 1; return
one:  int 0;
`, 8)

	// take the 0th label with bytes cases
	testAccepts(t, `
byte "0"
byte "1"
byte "0"
match zero one
err
zero: int 1; return
one:  int 0;
`, 8)

	// take the 1th label with int cases
	testRejects(t, `
int 99
int 100
int 100
match zero one
err
zero: int 1; return
one:  int 0;
`, 8)

	// take the 1th label with bytes cases
	testRejects(t, `
byte "0"
byte "1"
byte "1"
match zero one
err
zero: int 1; return
one:  int 0;
`, 8)

	// same, but jumping to end of program
	testAccepts(t, `
int 1; int 99; int 100; int 100
match zero one
zero: err
one:
`, 8)

	// no match
	testAccepts(t, `
int 99
int 100
int 101
match zero one
int 1; return // falls through to here
zero: int 0; return
one:  int 0; return
`, 8)

	// jump forward and backward
	testAccepts(t, `
int 99
start:
int 1
+
int 100
int 101
dig 2
match start end
err
end:
int 101
==
assert
int 1
`, 8)

	// 0 labels are allowed, but weird!
	testAccepts(t, `
int 0
match
int 1
`, 8)

	testPanics(t, notrack("match; int 1"), 8)

	// make the match the final instruction
	testAccepts(t, `
int 1
int 100
int 99
int 100
match done1 done2; done1: ; done2: ;
`, 8)

	// make the switch the final instruction, and don't match
	testAccepts(t, `
int 1
int 1
int 2
int 88
match done1 done2; done1: ; done2: ;
`, 8)

	// allow mixed types for match cases
	testAccepts(t, `
int 1
int 100
byte "101"
byte "101"
match done1 done2; done1: ; done2: ;
`, 8)

	testAccepts(t, `
byte "0"
int 1
byte "0"
match zero one
err
zero: int 1; return
one:  int 0;
`, 8)

	testAccepts(t, `
byte "0"
int 1
int 1
match zero one
err
one: int 1; return
zero: int 0;
`, 8)

	testAccepts(t, `
byte "0"
byte "1"
int 1
match zero one
int 1; return
zero: int 0;
one:  int 0;
`, 8)
}

// TestShortMatch ensures a clean error when a match ends early
func TestShortMatch(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	source := `int 1
    int 40
    int 45
    int 40
	match label1 label2
	label1:
    label2:
	`
	ops, err := AssembleStringWithVersion(source, AssemblerMaxVersion)
	require.NoError(t, err)

	// fine as is
	testLogicBytes(t, ops.Program, nil)

	beyond := "match opcode claims to extend beyond program"

	// bad if a label is gone
	testLogicBytes(t, ops.Program[:len(ops.Program)-2], nil, beyond, beyond)

	// chop off all the labels, but keep the label count
	testLogicBytes(t, ops.Program[:len(ops.Program)-4], nil, beyond, beyond)

	// chop off before the label count
	testLogicBytes(t, ops.Program[:len(ops.Program)-5], nil,
		"bare match opcode at end of program", "bare match opcode at end of program")

	// chop off half of a label
	testLogicBytes(t, ops.Program[:len(ops.Program)-1], nil, beyond, beyond)
}

func TestPushConsts(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	testAccepts(t, `
pushints 1 2
int 2
==
assert
int 1
==
assert
int 1
`, 8)

	testAccepts(t, `
pushbytess "1" "2"
byte "2"
==
assert
byte "1"
==
assert
int 1
`, 8)

	valsStr := make([]string, 256)
	for i := range valsStr {
		valsStr[i] = fmt.Sprintf("%d", i)
	}
	source := fmt.Sprintf(`pushints %s`, strings.Join(valsStr, " "))
	testAccepts(t, source+`
popn 255
pop
int 1
`, 8)

	for i := range valsStr {
		valsStr[i] = fmt.Sprintf("\"%d\"", i)
	}
	source = fmt.Sprintf(`pushbytess %s`, strings.Join(valsStr, " "))
	testAccepts(t, source+`
popn 255
pop
int 1
`, 8)
}

func TestNoHeaderLedger(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	nhl := NoHeaderLedger{}
	_, err := nhl.BlockHdr(1)
	require.Error(t, err)
	require.Equal(t, err, fmt.Errorf("no block header access"))
}

func TestMaxTxGroup(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	require.Equal(t, config.MaxTxGroupSize, maxTxGroupSize)
}
