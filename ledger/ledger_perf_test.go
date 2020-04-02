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
	txType     string
	name       string
	program    string
	schemaSize uint64
}

var testCases map[string]testParams

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

func benchmarkFullBlocks(params testParams, b *testing.B) {
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

	// open first ledger
	const inMem = false // use persistent storage
	const archival = true
	l0, err := OpenLedger(logging.Base(), dbPrefix, inMem, genesisInitState, archival)
	require.NoError(b, err)

	// open second ledger
	dbName = fmt.Sprintf("%s.%d.2", b.Name(), crypto.RandUint64())
	dbPrefix = filepath.Join(dbTempDir, dbName)
	l1, err := OpenLedger(logging.Base(), dbPrefix, inMem, genesisInitState, archival)
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

		// If this is the first block, add a blank one to both ledgers
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
		eval, err := l0.StartEvaluator(newBlk.BlockHeader)
		require.NoError(b, err)

		// build a payset
		var j int
		for {
			j++
			// make a transaction of the appropriate type
			var tx transactions.Transaction
			switch params.txType {
			case "pay":
				tx = makeUnsignedPaymentTx(creator, i)
			case "app":
				tx = makeUnsignedApplicationCallTxPerf(createdAppIdx, params, onCompletion, i)
			default:
				panic("unknown tx type")
			}

			tx.Sender = creator
			tx.Note = []byte(fmt.Sprintf("%d,%d", i, j))
			tx.GenesisHash = crypto.Digest{1}

			// add tx to block
			var stxn transactions.SignedTxn
			stxn.Txn = tx
			err = eval.Transaction(stxn, transactions.ApplyData{})

			// check if block is full
			if err == ErrNoSpace {
				txPerBlock = len(eval.block.Payset)
				break
			} else {
				require.NoError(b, err)
			}

			// First block just creates app
			if i == 1 {
				onCompletion = transactions.NoOpOC
				createdAppIdx = eval.state.txnCounter()
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
		_, err = l1.eval(context.Background(), blk, true, &vc, nil)
		require.NoError(b, err)
		err = l1.AddBlock(blk, cert)
		require.NoError(b, err)
	}
}

func BenchmarkAppLocal1NoDiffs(b *testing.B) {
	benchmarkFullBlocks(testCases["bench-local-1-no-diffs"], b)
}
func BenchmarkAppLocal250NoDiffs(b *testing.B) {
	benchmarkFullBlocks(testCases["bench-local-250-no-diffs"], b)
}
func BenchmarkAppLocal750NoDiffs(b *testing.B) {
	benchmarkFullBlocks(testCases["bench-local-750-no-diffs"], b)
}

func BenchmarkAppGlobal1NoDiffs(b *testing.B) {
	benchmarkFullBlocks(testCases["bench-global-1-no-diffs"], b)
}
func BenchmarkAppGlobal250NoDiffs(b *testing.B) {
	benchmarkFullBlocks(testCases["bench-global-250-no-diffs"], b)
}
func BenchmarkAppGlobal750NoDiffs(b *testing.B) {
	benchmarkFullBlocks(testCases["bench-global-750-no-diffs"], b)
}

func BenchmarkAppLocal1BigDiffs(b *testing.B) {
	benchmarkFullBlocks(testCases["bench-local-1-big-diffs"], b)
}
func BenchmarkAppLocal250BigDiffs(b *testing.B) {
	benchmarkFullBlocks(testCases["bench-local-250-big-diffs"], b)
}
func BenchmarkAppLocal750BigDiffs(b *testing.B) {
	benchmarkFullBlocks(testCases["bench-local-750-big-diffs"], b)
}

func BenchmarkAppGlobal1BigDiffs(b *testing.B) {
	benchmarkFullBlocks(testCases["bench-global-1-big-diffs"], b)
}
func BenchmarkAppGlobal250BigDiffs(b *testing.B) {
	benchmarkFullBlocks(testCases["bench-global-250-big-diffs"], b)
}
func BenchmarkAppGlobal750BigDiffs(b *testing.B) {
	benchmarkFullBlocks(testCases["bench-global-750-big-diffs"], b)
}

func BenchmarkAppInt1(b *testing.B) { benchmarkFullBlocks(testCases["int-1"], b) }

func BenchmarkPay(b *testing.B) { benchmarkFullBlocks(testCases["pay"], b) }

func init() {
	testCases = make(map[string]testParams)

	// Disable deadlock checking library
	deadlock.Opts.Disable = true

	// No diffs
	params := genAppTestParams(1, false, "local")
	testCases[params.name] = params

	params = genAppTestParams(250, false, "local")
	testCases[params.name] = params

	params = genAppTestParams(750, false, "local")
	testCases[params.name] = params

	params = genAppTestParams(1, false, "global")
	testCases[params.name] = params

	params = genAppTestParams(250, false, "global")
	testCases[params.name] = params

	params = genAppTestParams(750, false, "global")
	testCases[params.name] = params

	// Big diffs
	params = genAppTestParams(1, true, "local")
	testCases[params.name] = params

	params = genAppTestParams(250, true, "local")
	testCases[params.name] = params

	params = genAppTestParams(750, true, "local")
	testCases[params.name] = params

	params = genAppTestParams(1, true, "global")
	testCases[params.name] = params

	params = genAppTestParams(250, true, "global")
	testCases[params.name] = params

	params = genAppTestParams(750, true, "global")
	testCases[params.name] = params

	// Int 1
	progBytes, err := logic.AssembleString(`int 1`)
	if err != nil {
		panic(err)
	}

	params = testParams{
		txType:  "app",
		name:    fmt.Sprintf("int-1"),
		program: string(progBytes),
	}
	testCases[params.name] = params

	// Payments
	params = testParams{
		txType: "pay",
		name:   "pay",
	}
	testCases[params.name] = params
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
			app_local_get
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
			int 1
			itob
			app_global_get
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
	var progParts []string
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
	progBytes, err := logic.AssembleString(progAsm)
	if err != nil {
		panic(err)
	}

	return testParams{
		txType:     "app",
		name:       fmt.Sprintf("bench-%s-%d-%s", stateType, numKeys, testDiffName),
		schemaSize: uint64(numKeys),
		program:    string(progBytes),
	}
}
