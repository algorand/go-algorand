// Copyright (C) 2019-2024 Algorand, Inc.
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
	"encoding/hex"
	"fmt"
	"strings"
	"testing"

	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/test/partitiontest"
	"github.com/stretchr/testify/require"
)

// This test ensures a program compiled with by pre-AVM v2 go-algorand
// that includes all the opcodes from AVM v1 runs in AVM v2 runModeSignature well
var sourceV1 = `byte 0x41 // A
sha256
byte 0x559aead08264d5795d3909718cdd05abd49572e84fe55590eef31a88a08fdffd
==
byte 0x42
keccak256
byte 0x1f675bff07515f5df96737194ea945c36c41e7b4fcef307b7cd4d0e602a69111
==
&&
byte 0x43
sha512_256
byte 0x34b99f8dde1ba273c0a28cf5b2e4dbe497f8cb2453de0c8ba6d578c9431a62cb
==
&&
arg_0
arg_1
arg_2
ed25519verify
&&
// should be a single 1 on the stack
int 0
+
int 0
-
int 1
/
int 1
*
// should be a single 1 on the stack
int 2
<
int 0
>
int 1
<=
int 1
>=
int 1
&&
int 0
||
int 1
==
int 1
!=
!
// should be a single 1 on the stack
arg_3
len
int 32
==
itob
btoi
% // 1 % 1 = 0
int 1
|
int 1
&
int 0
^
int 0xffffffffffffffff
~
mulw
// should be a two zeros on the stack
==
intc_0
intc_1
==
intc_2
intc_3
==
&&
intc 4
int 1
==
&&
pop  // consume intc_N comparisons and repeat for bytec_N
bytec_0
bytec_1
==
bytec_2
bytec_3
==
&&
bytec 4
byte 0x00
==
&&
pop
// test all txn fields
txn Sender
txn Receiver
!=
txn Fee
txn FirstValid
==
&&
// disabled
// txn FirstValidTime
int 0
txn LastValid
!=
&&
txn Note
txn Lease
!=
&&
txn Amount
txn GroupIndex
!=
&&
txn CloseRemainderTo
txn VotePK
==
&&
txn SelectionPK
txn Type
!=
&&
txn VoteFirst
txn VoteLast
==
&&
txn VoteKeyDilution
txn TypeEnum
!=
&&
txn XferAsset
txn AssetAmount
!=
&&
txn AssetSender
txn AssetReceiver
==
&&
txn AssetCloseTo
txn TxID
==
&&
pop
// repeat for gtxn
gtxn 0 Sender
gtxn 0 Receiver
!=
gtxn 0 Fee
gtxn 0 FirstValid
==
&&
// disabled
// gtxn 0 FirstValidTime
int 0
gtxn 0 LastValid
!=
&&
gtxn 0 Note
gtxn 0 Lease
!=
&&
gtxn 0 Amount
gtxn 0 GroupIndex
!=
&&
gtxn 0 CloseRemainderTo
gtxn 0 VotePK
==
&&
gtxn 0 SelectionPK
gtxn 0 Type
!=
&&
gtxn 0 VoteFirst
gtxn 0 VoteLast
==
&&
gtxn 0 VoteKeyDilution
gtxn 0 TypeEnum
!=
&&
gtxn 0 XferAsset
gtxn 0 AssetAmount
!=
&&
gtxn 0 AssetSender
gtxn 0 AssetReceiver
==
&&
gtxn 0 AssetCloseTo
gtxn 0 TxID
==
&&
pop
// check global (these are set equal in defaultEvalProto())
global MinTxnFee
global MinBalance
==
global MaxTxnLife
global GroupSize
!=
&&
global ZeroAddress
byte 0x0000000000000000000000000000000000000000000000000000000000000000
==
&&
store 0
load 0
&&

// wrap up, should be a two zeros on the stack
bnz ok
err
ok:
int 1
dup
==
`

var programV1 = "01200500010220ffffffffffffffffff012608014120559aead08264d5795d3909718cdd05abd49572e84fe55590eef31a88a08fdffd0142201f675bff07515f5df96737194ea945c36c41e7b4fcef307b7cd4d0e602a6911101432034b99f8dde1ba273c0a28cf5b2e4dbe497f8cb2453de0c8ba6d578c9431a62cb0100200000000000000000000000000000000000000000000000000000000000000000280129122a022b1210270403270512102d2e2f041022082209230a230b240c220d230e230f231022112312231314301525121617182319231a221b21041c1d12222312242512102104231210482829122a2b121027042706121048310031071331013102121022310413103105310613103108311613103109310a1210310b310f1310310c310d1210310e31101310311131121310311331141210311531171210483300003300071333000133000212102233000413103300053300061310330008330016131033000933000a121033000b33000f131033000c33000d121033000e3300101310330011330012131033001333001412103300153300171210483200320112320232041310320327071210350034001040000100234912"

func TestBackwardCompatTEALv1(t *testing.T) {
	partitiontest.PartitionTest(t)

	t.Parallel()
	var s crypto.Seed
	crypto.RandBytes(s[:])
	c := crypto.GenerateSignatureSecrets(s)
	msg := "62fdfc072182654f163f5f0f9a621d729566c74d0aa413bf009c9800418c19cd"
	data, err := hex.DecodeString(msg)
	require.NoError(t, err)
	pk := basics.Address(c.SignatureVerifier)

	program, err := hex.DecodeString(programV1)
	require.NoError(t, err)

	// ensure old program is the same as a new one when assembling without version
	ops, err := AssembleString(sourceV1)
	require.NoError(t, err)
	require.Equal(t, program, ops.Program)
	// ensure the old program is the same as a new one except AVM version byte
	opsV2, err := AssembleStringWithVersion(sourceV1, 2)
	require.NoError(t, err)
	require.Equal(t, program[1:], opsV2.Program[1:])

	sig := c.Sign(Msg{
		ProgramHash: crypto.HashObj(Program(program)),
		Data:        data[:],
	})

	stxn := makeSampleTxn()
	// RekeyTo disallowed on AVM v0/v1
	stxn.Txn.RekeyTo = basics.Address{}
	stxn.Lsig.Logic = program
	stxn.Lsig.Args = [][]byte{data[:], sig[:], pk[:], stxn.Txn.Sender[:], stxn.Txn.Note}

	// ensure v1 program runs well on latest evaluator
	require.Equal(t, uint8(1), program[0])

	maxCost := func(cost uint64) protoOpt {
		return func(p *config.ConsensusParams) {
			p.LogicSigMaxCost = cost
		}
	}

	// Cost should stay exactly 2140 for v1, even as future changes are made
	err = CheckSignature(0, optSigParams(maxCost(2139), stxn))
	require.ErrorContains(t, err, "static cost")
	ep := optSigParams(maxCost(2140), stxn)
	err = CheckSignature(0, ep)
	require.NoError(t, err)

	pass, err := EvalSignature(0, ep)
	if err != nil || !pass {
		t.Log(hex.EncodeToString(program))
		t.Log(ep.Trace.String())
	}
	require.NoError(t, err)
	require.True(t, pass)

	// Costs for v2 programs should be higher because of hash opcode cost changes
	// Eval doesn't fail, but it would be ok (better?) if it did
	testLogicBytes(t, opsV2.Program, optSigParams(maxCost(2307), stxn), "static cost", "")
	testLogicBytes(t, opsV2.Program, optSigParams(maxCost(2308), stxn))

	// ensure v0 program runs well on latest evaluator
	program[0] = 0
	sig = c.Sign(Msg{
		ProgramHash: crypto.HashObj(Program(program)),
		Data:        data[:],
	})
	stxn.Lsig.Logic = program
	stxn.Lsig.Args = [][]byte{data[:], sig[:], pk[:], stxn.Txn.Sender[:], stxn.Txn.Note}

	// Cost remains the same, because v0 does not get dynamic treatment
	testLogicBytes(t, program, optSigParams(maxCost(2139), stxn), "static cost", "")
	testLogicBytes(t, program, optSigParams(maxCost(2140), stxn))

	// But in v4, cost is now dynamic and exactly 1 less than v2/v3,
	// because bnz skips "err". It's caught during Eval
	program[0] = 4
	testLogicBytes(t, program, optSigParams(maxCost(2306), stxn), "dynamic cost")
	testLogicBytes(t, program, optSigParams(maxCost(2307), stxn))
}

// ensure v2 fields error on pre v2 logicsig version
// ensure v2 fields error in v1 program
func TestBackwardCompatGlobalFields(t *testing.T) {
	partitiontest.PartitionTest(t)

	t.Parallel()
	var fields []globalFieldSpec
	for _, fs := range globalFieldSpecs {
		if fs.version > 1 {
			fields = append(fields, fs)
		}
	}
	require.Greater(t, len(fields), 1)

	for _, field := range fields {
		text := fmt.Sprintf("global %s", field.field.String())
		// check assembler fails if version before introduction
		testLine(t, text, assemblerNoVersion, "...was introduced in...")
		for v := uint64(0); v < field.version; v++ {
			testLine(t, text, v, "...was introduced in...")
		}

		ops := testProg(t, text, AssemblerMaxVersion)

		stxn := makeSampleTxn()
		stxn.Txn.RekeyTo = basics.Address{} // would mess up minavmversion
		stxn.Lsig.Logic = ops.Program
		ep := defaultSigParamsWithVersion(1, stxn)
		_, err := EvalSignature(0, ep)
		require.ErrorContains(t, err, "greater than protocol supported version")

		// check opcodes failures
		ep.TxnGroup[0].Lsig.Logic[0] = 1 // set version to 1
		_, err = EvalSignature(0, ep)
		require.ErrorContains(t, err, "invalid global field")

		// check opcodes failures
		ep.TxnGroup[0].Lsig.Logic[0] = 0 // set version to 0
		_, err = EvalSignature(0, ep)
		require.ErrorContains(t, err, "invalid global field")
	}
}

// ensure v2 fields error in v1 program
func TestBackwardCompatTxnFields(t *testing.T) {
	partitiontest.PartitionTest(t)

	t.Parallel()
	var fields []txnFieldSpec
	for _, fs := range txnFieldSpecs {
		if fs.version > 1 {
			fields = append(fields, fs)
		}
	}
	require.Greater(t, len(fields), 1)

	tests := []string{
		"txn %s",
		"gtxn 0 %s",
	}

	for _, fs := range fields {
		field := fs.field.String()
		for i, command := range tests {
			text := fmt.Sprintf(command, field)
			asmError := "...was introduced in ..."
			if fs.array {
				parts := strings.Split(text, " ")
				op := parts[0]
				asmError = fmt.Sprintf("%#v field of %s can only be used with %d immediates", field, op, i+2)
			}
			// check assembler fails in versions before introduction
			testLine(t, text, assemblerNoVersion, asmError)
			for v := uint64(0); v < fs.version; v++ {
				testLine(t, text, v, asmError)
			}

			ops, err := AssembleStringWithVersion(text, AssemblerMaxVersion)
			if fs.array {
				// "txn Accounts" is invalid, so skip evaluation
				require.Error(t, err)
				continue
			} else {
				require.NoError(t, err)
			}

			ep := defaultSigParamsWithVersion(1)
			ep.TxnGroup[0].Lsig.Logic = ops.Program

			// check failure with version check
			_, err = EvalSignature(0, ep)
			require.ErrorContains(t, err, "greater than protocol supported version")

			// check opcodes failures
			ops.Program[0] = 1 // set version to 1
			_, err = EvalSignature(0, ep)
			require.ErrorContains(t, err, "invalid txn field")

			// check opcodes failures
			ops.Program[0] = 0 // set version to 0
			_, err = EvalSignature(0, ep)
			require.ErrorContains(t, err, "invalid txn field")
		}
	}
}

func TestBackwardCompatAssemble(t *testing.T) {
	partitiontest.PartitionTest(t)

	// v1 does not allow branching to the last line
	// v2 makes such programs legal
	t.Parallel()

	// Label is ok, it just can't be branched to
	source := "int 1; done:"
	testProg(t, source, assemblerNoVersion)
	testProg(t, source, 0)
	testProg(t, source, 1)

	// use multiple lines, so that error report is checked better
	source = `int 1;
 int 1;
 bnz done;
 done:
`
	testProg(t, source, assemblerNoVersion, exp(3, "label \"done\" is too far away", 5))
	testProg(t, source, 0, exp(3, "label \"done\" is too far away", 5))
	testProg(t, source, 1, exp(3, "label \"done\" is too far away", 5))

	for v := uint64(2); v <= AssemblerMaxVersion; v++ {
		t.Run(fmt.Sprintf("v=%d", v), func(t *testing.T) {
			t.Parallel()
			testLogic(t, source, v, nil)
		})
	}
}

func TestExplicitConstants(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	require.Equal(t, 4096, maxStringSize, "constant changed, make it version dependent")
	require.Equal(t, 64, maxByteMathSize, "constant changed, move it version dependent")
	require.Equal(t, 1024, maxLogSize, "constant changed, move it version dependent")
	require.Equal(t, 32, maxLogCalls, "constant changed, move it version dependent")
}
