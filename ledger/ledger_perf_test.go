// Copyright (C) 2019-2020 Algorand, Inc.
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

package ledger

import (
	"context"
	"crypto/rand"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/algorand/go-deadlock"
	"github.com/stretchr/testify/require"

	"github.com/algorand/go-algorand/agreement"
	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/bookkeeping"
	"github.com/algorand/go-algorand/data/transactions"
	"github.com/algorand/go-algorand/data/transactions/logic"
	"github.com/algorand/go-algorand/data/transactions/verify"
	"github.com/algorand/go-algorand/logging"
	"github.com/algorand/go-algorand/protocol"
)

type testParams struct {
	testType   string
	name       string
	program    []byte
	schemaSize uint64
	numApps    uint64
	asaAccts   uint64
}

var testCases map[string]testParams
var asaClearStateProgram []byte
var asaAppovalProgram []byte

func makeUnsignedApplicationCallTxPerf(appIdx uint64, params testParams, onCompletion transactions.OnCompletion, round int) transactions.Transaction {
	var tx transactions.Transaction

	tx.Type = protocol.ApplicationCallTx
	tx.ApplicationID = basics.AppIndex(appIdx)
	tx.OnCompletion = onCompletion
	tx.Header.FirstValid = basics.Round(round)
	tx.Header.LastValid = basics.Round(round + 1000)
	tx.Header.Fee = basics.MicroAlgos{Raw: 1000}

	// If creating, set programs
	if appIdx == 0 {
		tx.ApprovalProgram = params.program
		tx.ClearStateProgram = params.program
		tx.GlobalStateSchema = basics.StateSchema{
			NumByteSlice: params.schemaSize,
		}
		tx.LocalStateSchema = basics.StateSchema{
			NumByteSlice: params.schemaSize,
		}
	}

	return tx
}

func makeUnsignedASATx(appIdx uint64, creator basics.Address, round int) transactions.Transaction {
	var tx transactions.Transaction

	tx.Type = protocol.ApplicationCallTx
	tx.ApplicationID = basics.AppIndex(appIdx)
	tx.Header.FirstValid = basics.Round(round)
	tx.Header.LastValid = basics.Round(round + 1000)
	tx.Header.Fee = basics.MicroAlgos{Raw: 1000}

	if appIdx == 0 {
		tx.ApplicationArgs = [][]byte{
			creator[:],
			creator[:],
			creator[:],
			creator[:],
			creator[:],
			[]byte{0, 0, 0, 1, 0, 0, 0, 0},
			[]byte{0, 0, 0, 0, 0, 0, 0, 0},
		}
		tx.OnCompletion = transactions.NoOpOC
		tx.ApprovalProgram = asaAppovalProgram
		tx.ClearStateProgram = asaClearStateProgram
		tx.GlobalStateSchema = basics.StateSchema{
			NumByteSlice: 5,
			NumUint:      4,
		}
		tx.LocalStateSchema = basics.StateSchema{
			NumByteSlice: 0,
			NumUint:      2,
		}
	}
	return tx
}

func makeUnsignedPaymentTx(sender basics.Address, round int) transactions.Transaction {
	return transactions.Transaction{
		Type: protocol.PaymentTx,
		Header: transactions.Header{
			FirstValid: basics.Round(round),
			LastValid:  basics.Round(round + 1000),
			Fee:        basics.MicroAlgos{Raw: 1000},
		},
		PaymentTxnFields: transactions.PaymentTxnFields{
			Receiver: sender,
			Amount:   basics.MicroAlgos{Raw: 1234},
		},
	}
}

type alwaysVerifiedCache struct{}

func (vc *alwaysVerifiedCache) Verified(txn transactions.SignedTxn, params verify.Params) bool {
	return true
}

// UnverifiedTxnGroups returns a list of unverified transaction groups given a payset
func (vc *alwaysVerifiedCache) UnverifiedTxnGroups(txnGroups [][]transactions.SignedTxn, params verify.Params) (signedTxnGroups [][]transactions.SignedTxn) {
	return [][]transactions.SignedTxn{}
}

func benchmarkFullBlocks(params testParams, b *testing.B) {
	// disable deadlock checking code
	deadlockDisable := deadlock.Opts.Disable
	deadlock.Opts.Disable = true
	defer func() {
		deadlock.Opts.Disable = deadlockDisable
	}()

	dbTempDir, err := ioutil.TempDir("", "testdir"+b.Name())
	require.NoError(b, err)
	dbName := fmt.Sprintf("%s.%d", b.Name(), crypto.RandUint64())
	dbPrefix := filepath.Join(dbTempDir, dbName)
	defer os.RemoveAll(dbTempDir)

	genesisInitState := getInitState()

	// Use future protocol
	genesisInitState.Block.BlockHeader.GenesisHash = crypto.Digest{}
	genesisInitState.Block.CurrentProtocol = protocol.ConsensusFuture
	genesisInitState.GenesisHash = crypto.Digest{1}
	genesisInitState.Block.BlockHeader.GenesisHash = crypto.Digest{1}

	creator := basics.Address{}
	_, err = rand.Read(creator[:])
	require.NoError(b, err)
	genesisInitState.Accounts[creator] = basics.MakeAccountData(basics.Offline, basics.MicroAlgos{Raw: 1234567890})

	// Make some accounts to opt into ASA
	var accts []basics.Address
	if params.testType == "asa" {
		for i := uint64(0); i < params.asaAccts; i++ {
			acct := basics.Address{}
			_, err = rand.Read(acct[:])
			require.NoError(b, err)
			genesisInitState.Accounts[acct] = basics.MakeAccountData(basics.Offline, basics.MicroAlgos{Raw: 1234567890})
			accts = append(accts, acct)
		}
	}

	// open first ledger
	const inMem = false // use persistent storage
	cfg := config.GetDefaultLocal()
	cfg.Archival = true
	l0, err := OpenLedger(logging.Base(), dbPrefix, inMem, genesisInitState, cfg)
	require.NoError(b, err)

	// open second ledger
	dbName = fmt.Sprintf("%s.%d.2", b.Name(), crypto.RandUint64())
	dbPrefix = filepath.Join(dbTempDir, dbName)
	l1, err := OpenLedger(logging.Base(), dbPrefix, inMem, genesisInitState, cfg)
	require.NoError(b, err)

	blk := genesisInitState.Block

	numBlocks := b.N
	cert := agreement.Certificate{}
	var blocks []bookkeeping.Block
	var createdAppIdx uint64
	var txPerBlock int
	onCompletion := transactions.OptInOC
	for i := 0; i < numBlocks+2; i++ {
		blk.BlockHeader.Round++
		blk.BlockHeader.TimeStamp += int64(crypto.RandUint64() % 100 * 1000)
		blk.BlockHeader.GenesisID = "x"

		// If this is the zeroth block, add a blank one to both ledgers
		if i == 0 {
			err = l0.AddBlock(blk, cert)
			require.NoError(b, err)
			err = l1.AddBlock(blk, cert)
			require.NoError(b, err)
			continue
		}

		// Construct evaluator for next block
		prev, err := l0.BlockHdr(basics.Round(i))
		require.NoError(b, err)
		newBlk := bookkeeping.MakeBlock(prev)
		eval, err := l0.StartEvaluator(newBlk.BlockHeader, 5000)
		require.NoError(b, err)

		// build a payset
		var j int
		for {
			j++
			// make a transaction of the appropriate type
			var tx transactions.Transaction
			switch params.testType {
			case "pay":
				tx = makeUnsignedPaymentTx(creator, i)
			case "app":
				tx = makeUnsignedApplicationCallTxPerf(createdAppIdx, params, onCompletion, i)
			case "asa":
				tx = makeUnsignedASATx(createdAppIdx, creator, i)
				// If we've created the ASA already, then fill in some spending parameters
				if createdAppIdx != 0 {
					// Creator spends to an opted in acct
					tx.ApplicationArgs = [][]byte{
						[]byte{0, 0, 0, 0, 0, 0, 0, 1},
					}
					tx.Accounts = []basics.Address{
						accts[j%len(accts)],
						basics.Address{},
					}
				}
			default:
				panic("unknown tx type")
			}

			numApps := uint64(1)
			if i == 1 {
				if params.numApps != 0 {
					numApps = params.numApps
				}
			}

			// On first block, create params.numApps apps by adding numApps
			// copies of the tx (with different notes fields). Otheriwse, just
			// add 1.
			for k := uint64(0); k < numApps; k++ {
				tx.Sender = creator
				tx.Note = []byte(fmt.Sprintf("%d,%d,%d", i, j, k))
				tx.GenesisHash = crypto.Digest{1}

				// add tx to block
				var stxn transactions.SignedTxn
				stxn.Txn = tx
				stxn.Sig = crypto.Signature{1}
				err = eval.Transaction(stxn, transactions.ApplyData{})

			}

			// check if block is full
			if err == ErrNoSpace {
				txPerBlock = len(eval.block.Payset)
				break
			} else {
				require.NoError(b, err)
			}

			// First block just creates app + opts in accts if asa test
			if i == 1 {
				onCompletion = transactions.NoOpOC
				createdAppIdx = eval.state.txnCounter()

				// On first block, opt in all accts to asa (accts is empty if not asa test)
				k := 0
				for _, acct := range accts {
					tx = makeUnsignedASATx(createdAppIdx, basics.Address{}, i)
					tx.OnCompletion = transactions.OptInOC
					tx.Sender = acct
					tx.Note = []byte(fmt.Sprintf("%d,%d,%d", i, j, k))
					tx.GenesisHash = crypto.Digest{1}
					k++

					// add tx to block
					var stxn transactions.SignedTxn
					stxn.Txn = tx
					stxn.Sig = crypto.Signature{1}
					err = eval.Transaction(stxn, transactions.ApplyData{})
				}
				break
			}
		}

		lvb, err := eval.GenerateBlock()
		require.NoError(b, err)

		// If this is the app creation block, add to both ledgers
		if i == 1 {
			err = l0.AddBlock(lvb.blk, cert)
			require.NoError(b, err)
			err = l1.AddBlock(lvb.blk, cert)
			require.NoError(b, err)
			continue
		}

		// For all other blocks, add just to the first ledger, and stash
		// away to be replayed in the second ledger while running timer
		err = l0.AddBlock(lvb.blk, cert)
		require.NoError(b, err)

		blocks = append(blocks, lvb.blk)
	}

	b.Logf("built %d blocks, each with %d txns", numBlocks, txPerBlock)

	// eval + add all the (valid) blocks to the second ledger, measuring it this time
	vc := alwaysVerifiedCache{}
	b.ResetTimer()
	for _, blk := range blocks {
		_, err = eval(context.Background(), l1, blk, true, &vc, nil)
		require.NoError(b, err)
		err = l1.AddBlock(blk, cert)
		require.NoError(b, err)
	}
}

func BenchmarkAppLocal1NoDiffs(b *testing.B) {
	benchmarkFullBlocks(testCases["bench-local-1-no-diffs"], b)
}

func BenchmarkAppLocal16NoDiffs(b *testing.B) {
	benchmarkFullBlocks(testCases["bench-local-16-no-diffs"], b)
}

func BenchmarkAppGlobal1NoDiffs(b *testing.B) {
	benchmarkFullBlocks(testCases["bench-global-1-no-diffs"], b)
}

func BenchmarkAppGlobal16NoDiffs(b *testing.B) {
	benchmarkFullBlocks(testCases["bench-global-16-no-diffs"], b)
}

func BenchmarkAppLocal1BigDiffs(b *testing.B) {
	benchmarkFullBlocks(testCases["bench-local-1-big-diffs"], b)
}

func BenchmarkAppLocal16BigDiffs(b *testing.B) {
	benchmarkFullBlocks(testCases["bench-local-16-big-diffs"], b)
}

func BenchmarkAppGlobal1BigDiffs(b *testing.B) {
	benchmarkFullBlocks(testCases["bench-global-1-big-diffs"], b)
}

func BenchmarkAppGlobal16BigDiffs(b *testing.B) {
	benchmarkFullBlocks(testCases["bench-global-16-big-diffs"], b)
}

func BenchmarkAppGlobal64MaxClone(b *testing.B) {
	benchmarkFullBlocks(testCases["bench-global-64-max-clone"], b)
}

func BenchmarkAppInt1(b *testing.B) { benchmarkFullBlocks(testCases["int-1"], b) }

func BenchmarkAppInt1ManyApps(b *testing.B) { benchmarkFullBlocks(testCases["int-1-many-apps"], b) }

func BenchmarkAppBigNoOp(b *testing.B) { benchmarkFullBlocks(testCases["big-noop"], b) }

func BenchmarkAppBigHashes(b *testing.B) { benchmarkFullBlocks(testCases["big-hashes"], b) }

func BenchmarkAppASA(b *testing.B) { benchmarkFullBlocks(testCases["asa"], b) }

func BenchmarkPay(b *testing.B) { benchmarkFullBlocks(testCases["pay"], b) }

func init() {
	testCases = make(map[string]testParams)

	lengths := []int{1, 16}
	diffs := []bool{true, false}
	state := []string{"local", "global"}

	for _, l := range lengths {
		for _, d := range diffs {
			for _, s := range state {
				params := genAppTestParams(l, d, s)
				testCases[params.name] = params
			}
		}
	}

	// Max clone
	params := genAppTestParamsMaxClone(64)
	testCases[params.name] = params

	// Int 1
	ops, err := logic.AssembleStringWithVersion(`int 1`, 2)
	if err != nil {
		panic(err)
	}

	params = testParams{
		testType: "app",
		name:     fmt.Sprintf("int-1"),
		program:  ops.Program,
	}
	testCases[params.name] = params

	// Int 1 many apps
	params = testParams{
		testType: "app",
		name:     fmt.Sprintf("int-1-many-apps"),
		program:  ops.Program,
		numApps:  10,
	}
	testCases[params.name] = params

	// Assemble ASA programs
	ops, err = logic.AssembleStringWithVersion(asaClearAsm, 2)
	if err != nil {
		panic(err)
	}
	asaClearStateProgram = ops.Program

	ops, err = logic.AssembleStringWithVersion(asaAppovalAsm, 2)
	if err != nil {
		panic(err)
	}
	asaAppovalProgram = ops.Program

	// ASAs
	params = testParams{
		testType: "asa",
		name:     "asa",
		asaAccts: 100,
		numApps:  10,
	}
	testCases[params.name] = params

	// Payments
	params = testParams{
		testType: "pay",
		name:     "pay",
	}
	testCases[params.name] = params

	// Big NoOp
	params = testParams{
		testType: "app",
		name:     "big-noop",
		program:  genBigNoOp(696),
	}
	testCases[params.name] = params

	// Big hashes
	params = testParams{
		testType: "app",
		name:     "big-hashes",
		program:  genBigHashes(10, 344),
	}
	testCases[params.name] = params
}

func genBigNoOp(numOps int) []byte {
	var progParts []string
	for i := 0; i < numOps/2; i++ {
		progParts = append(progParts, `int 1`)
		progParts = append(progParts, `pop`)
	}
	progParts = append(progParts, `int 1`)
	progParts = append(progParts, `return`)
	progAsm := strings.Join(progParts, "\n")
	ops, err := logic.AssembleStringWithVersion(progAsm, 2)
	if err != nil {
		panic(err)
	}
	return ops.Program
}

func genBigHashes(numHashes int, numPad int) []byte {
	var progParts []string
	progParts = append(progParts, `byte base64 AA==`)
	for i := 0; i < numHashes; i++ {
		progParts = append(progParts, `sha256`)
	}
	for i := 0; i < numPad/2; i++ {
		progParts = append(progParts, `int 1`)
		progParts = append(progParts, `pop`)
	}
	progParts = append(progParts, `int 1`)
	progParts = append(progParts, `return`)
	progAsm := strings.Join(progParts, "\n")
	ops, err := logic.AssembleStringWithVersion(progAsm, 2)
	if err != nil {
		panic(err)
	}
	return ops.Program
}

func genAppTestParams(numKeys int, bigDiffs bool, stateType string) testParams {
	var deleteBranch string
	var writePrefix, writeBlock, writeSuffix string
	var deletePrefix, deleteBlock, deleteSuffix string

	switch stateType {
	case "local":
		// goto delete if first key exists
		deleteBranch = `
			int 0
			int 0
			int 1
			itob
			app_local_get_ex
			bnz delete
		`

		writePrefix = `
			write:
			int 0
			store 0
		`

		writeBlock = `
			int 0
			load 0
			int 1
			+
			dup
			store 0
			itob
			dup
			app_local_put
		`

		writeSuffix = `
			int 1
			return
		`

		deletePrefix = `
			delete:
			int 0
			store 0
		`

		deleteBlock = `
			int 0
			load 0
			int 1
			+
			dup
			store 0
			itob
			app_local_del
		`

		deleteSuffix = `
			int 1
			return
		`
	case "global":
		// goto delete if first key exists
		deleteBranch = `
			int 0  // current app id
			int 1  // key
			itob
			app_global_get_ex
			bnz delete
		`

		writePrefix = `
			write:
			int 0
		`

		writeBlock = `
			int 1
			+
			dup
			itob
			dup
			app_global_put
		`

		writeSuffix = `
			int 1
			return
		`

		deletePrefix = `
			delete:
			int 0
		`

		deleteBlock = `
			int 1
			+
			dup
			itob
			app_global_del
		`

		deleteSuffix = `
			int 1
			return
		`
	default:
		panic("unknown state type")
	}

	testDiffName := "big-diffs"
	if !bigDiffs {
		deleteBranch = ``
		deletePrefix = ``
		deleteBlock = ``
		deleteSuffix = ``
		testDiffName = "no-diffs"
	}

	// generate assembly
	progParts := []string{"#pragma version 2"}
	progParts = append(progParts, deleteBranch)
	progParts = append(progParts, writePrefix)
	for i := 0; i < numKeys; i++ {
		progParts = append(progParts, writeBlock)
	}
	progParts = append(progParts, writeSuffix)
	progParts = append(progParts, deletePrefix)
	for i := 0; i < numKeys; i++ {
		progParts = append(progParts, deleteBlock)
	}
	progParts = append(progParts, deleteSuffix)
	progAsm := strings.Join(progParts, "\n")

	// assemble
	ops, err := logic.AssembleStringWithVersion(progAsm, 2)
	if err != nil {
		panic(err)
	}

	return testParams{
		testType:   "app",
		name:       fmt.Sprintf("bench-%s-%d-%s", stateType, numKeys, testDiffName),
		schemaSize: uint64(numKeys),
		program:    ops.Program,
	}
}

func genAppTestParamsMaxClone(numKeys int) testParams {
	// goto flip if first key exists
	flipBranch := `
		int 0  // current app id
		int 1  // key
		itob
		app_global_get_ex
		bnz flip
	`

	writePrefix := `
		write:
		int 0
	`

	writeBlock := `
		int 1
		+
		dup
		itob
		dup
		app_global_put
	`

	writeSuffix := `
		int 1
		return
	`

	// flip stored value's low bit
	flipPrefix := `
		flip:
		btoi
		int 1
		^
		itob
		store 0
		int 1
		itob
		load 0
		app_global_put
	`

	flipSuffix := `
		int 1
		return
	`

	testDiffName := "max-clone"

	// generate assembly
	progParts := []string{"#pragma version 2"}
	progParts = append(progParts, flipBranch)
	progParts = append(progParts, writePrefix)
	for i := 0; i < numKeys; i++ {
		progParts = append(progParts, writeBlock)
	}
	progParts = append(progParts, writeSuffix)
	progParts = append(progParts, flipPrefix)
	progParts = append(progParts, flipSuffix)
	progAsm := strings.Join(progParts, "\n")

	// assemble
	ops, err := logic.AssembleStringWithVersion(progAsm, 2)
	if err != nil {
		panic(err)
	}

	return testParams{
		testType:   "app",
		name:       fmt.Sprintf("bench-%s-%d-%s", "global", numKeys, testDiffName),
		schemaSize: uint64(numKeys),
		program:    ops.Program,
	}
}

const asaClearAsm = `#pragma version 2
byte base64 Ymw=
byte base64 Ymw=
app_global_get
int 0
int 0
byte base64 Ymw=
app_local_get_ex
pop
+
app_global_put
int 1
`

const asaAppovalAsm = `#pragma version 2
txn NumAppArgs
int 7
==
bnz if0
txn ApplicationID
int 0
==
!
bnz assert2
err
assert2:
txn NumAccounts
int 0
==
bnz cond4
txn NumAccounts
int 1
==
bnz cond5
txn NumAppArgs
int 2
==
bnz cond6
// transfer asset
txna ApplicationArgs 0
btoi
store 1
load 1
int 0
==
bnz unless7
// cannot modify frozen asset
txn Sender
byte base64 Y3I=
app_global_get
==
bnz if9
int 0
int 0
byte base64 Zno=
app_local_get_ex
pop
int 1
==
int 1
bnz if_end10
if9:
byte base64 Zno=
app_global_get
int 1
==
if_end10:
!
bnz assert8
err
assert8:
txn Sender
byte base64 Y3I=
app_global_get
==
bnz if11
int 0
byte base64 Ymw=
int 0
int 0
byte base64 Ymw=
app_local_get_ex
pop
load 1
-
app_local_put
int 1
bnz if_end12
if11:
byte base64 Ymw=
byte base64 Ymw=
app_global_get
load 1
-
app_global_put
if_end12:
unless7:
load 1
int 0
==
bnz unless13
// cannot modify frozen asset
txna Accounts 1
byte base64 Y3I=
app_global_get
==
bnz if15
int 1
int 0
byte base64 Zno=
app_local_get_ex
pop
int 1
==
int 1
bnz if_end16
if15:
byte base64 Zno=
app_global_get
int 1
==
if_end16:
!
bnz assert14
err
assert14:
txna Accounts 1
byte base64 Y3I=
app_global_get
==
bnz if17
int 1
byte base64 Ymw=
int 1
int 0
byte base64 Ymw=
app_local_get_ex
pop
load 1
+
app_local_put
int 1
bnz if_end18
if17:
byte base64 Ymw=
byte base64 Ymw=
app_global_get
load 1
+
app_global_put
if_end18:
unless13:
txna Accounts 2
global ZeroAddress
==
bnz unless19
int 0
int 0
byte base64 Ymw=
app_local_get_ex
pop
store 2
load 2
int 0
==
bnz unless20
// cannot modify frozen asset
txn Sender
byte base64 Y3I=
app_global_get
==
bnz if22
int 0
int 0
byte base64 Zno=
app_local_get_ex
pop
int 1
==
int 1
bnz if_end23
if22:
byte base64 Zno=
app_global_get
int 1
==
if_end23:
!
bnz assert21
err
assert21:
txn Sender
byte base64 Y3I=
app_global_get
==
bnz if24
int 0
byte base64 Ymw=
int 0
int 0
byte base64 Ymw=
app_local_get_ex
pop
load 2
-
app_local_put
int 1
bnz if_end25
if24:
byte base64 Ymw=
byte base64 Ymw=
app_global_get
load 2
-
app_global_put
if_end25:
unless20:
load 2
int 0
==
bnz unless26
// cannot modify frozen asset
txna Accounts 2
byte base64 Y3I=
app_global_get
==
bnz if28
int 2
int 0
byte base64 Zno=
app_local_get_ex
pop
int 1
==
int 1
bnz if_end29
if28:
byte base64 Zno=
app_global_get
int 1
==
if_end29:
!
bnz assert27
err
assert27:
txna Accounts 2
byte base64 Y3I=
app_global_get
==
bnz if30
int 2
byte base64 Ymw=
int 2
int 0
byte base64 Ymw=
app_local_get_ex
pop
load 2
+
app_local_put
int 1
bnz if_end31
if30:
byte base64 Ymw=
byte base64 Ymw=
app_global_get
load 2
+
app_global_put
if_end31:
unless26:
unless19:
txn NumAppArgs
int 1
==
txn NumAccounts
int 2
==
&&
txn OnCompletion
int 0
==
bnz if32
txn OnCompletion
int 2
==
int 0
int 0
byte base64 Ymw=
app_local_get_ex
pop
int 0
==
&&
txna Accounts 2
global ZeroAddress
==
!
&&
int 1
bnz if_end33
if32:
txna Accounts 2
global ZeroAddress
==
if_end33:
&&
int 1
bnz cond_end3
cond6:
// clawback asset
txna ApplicationArgs 0
btoi
store 0
txna Accounts 1
byte base64 Y3I=
app_global_get
==
bnz if34
int 1
byte base64 Ymw=
int 1
int 0
byte base64 Ymw=
app_local_get_ex
pop
load 0
-
app_local_put
int 1
bnz if_end35
if34:
byte base64 Ymw=
byte base64 Ymw=
app_global_get
load 0
-
app_global_put
if_end35:
txna Accounts 2
byte base64 Y3I=
app_global_get
==
bnz if36
int 2
byte base64 Ymw=
int 2
int 0
byte base64 Ymw=
app_local_get_ex
pop
load 0
+
app_local_put
int 1
bnz if_end37
if36:
byte base64 Ymw=
byte base64 Ymw=
app_global_get
load 0
+
app_global_put
if_end37:
txn NumAccounts
int 2
==
txn OnCompletion
int 0
==
&&
txn Sender
byte base64 Y2w=
app_global_get
==
&&
int 1
bnz cond_end3
cond5:
// freeze asset holding
txna Accounts 1
byte base64 Y3I=
app_global_get
==
bnz if38
int 1
byte base64 Zno=
txna ApplicationArgs 0
btoi
app_local_put
int 1
bnz if_end39
if38:
byte base64 Zno=
txna ApplicationArgs 0
btoi
app_global_put
if_end39:
txn NumAppArgs
int 1
==
txn OnCompletion
int 0
==
&&
txn Sender
byte base64 ZnI=
app_global_get
==
&&
int 1
bnz cond_end3
cond4:
// asset deletion or opt-in
txn OnCompletion
int 1
==
!
bnz when40
// opting in to implicit zero bl
int 0
byte base64 Zno=
byte base64 ZGY=
app_global_get
app_local_put
when40:
txn NumAppArgs
int 0
==
txn OnCompletion
int 5
==
txn Sender
byte base64 bW4=
app_global_get
==
&&
byte base64 dHQ=
app_global_get
byte base64 Ymw=
app_global_get
==
&&
txn OnCompletion
int 1
==
txn Sender
byte base64 Y3I=
app_global_get
==
!
&&
||
&&
cond_end3:
int 1
bnz if_end1
if0:
// asset configuration
txn ApplicationID
int 0
==
bnz if41
txn Sender
byte base64 bW4=
app_global_get
==
txna ApplicationArgs 0
global ZeroAddress
==
byte base64 bW4=
app_global_get
global ZeroAddress
==
!
||
&&
txna ApplicationArgs 1
global ZeroAddress
==
byte base64 cnY=
app_global_get
global ZeroAddress
==
!
||
&&
txna ApplicationArgs 2
global ZeroAddress
==
byte base64 ZnI=
app_global_get
global ZeroAddress
==
!
||
&&
txna ApplicationArgs 3
global ZeroAddress
==
byte base64 Y2w=
app_global_get
global ZeroAddress
==
!
||
&&
bnz assert43
err
assert43:
int 1
bnz if_end42
if41:
byte base64 Y3I=
txna ApplicationArgs 4
app_global_put
byte base64 dHQ=
txna ApplicationArgs 5
btoi
app_global_put
byte base64 Ymw=
txna ApplicationArgs 5
btoi
app_global_put
byte base64 ZGY=
txna ApplicationArgs 6
btoi
app_global_put
if_end42:
byte base64 bW4=
txna ApplicationArgs 0
app_global_put
byte base64 cnY=
txna ApplicationArgs 1
app_global_put
byte base64 ZnI=
txna ApplicationArgs 2
app_global_put
byte base64 Y2w=
txna ApplicationArgs 3
app_global_put
txn NumAccounts
int 0
==
txn OnCompletion
int 0
==
&&
txna ApplicationArgs 0
len
int 32
==
&&
txna ApplicationArgs 1
len
int 32
==
&&
txna ApplicationArgs 2
len
int 32
==
&&
txna ApplicationArgs 3
len
int 32
==
&&
if_end1:
`
