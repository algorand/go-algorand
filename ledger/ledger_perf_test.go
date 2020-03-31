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

const heavyWriteCount = 768

var testprogheavy string
var testproglight string

func makeUnsignedApplicationCallTxPerf(appIdx uint64, load string, onCompletion transactions.OnCompletion, round int) (tx transactions.Transaction, err error) {
	tx.Type = protocol.ApplicationCallTx
	tx.ApplicationID = basics.AppIndex(appIdx)
	tx.OnCompletion = onCompletion
	tx.Header.FirstValid = basics.Round(round)
	tx.Header.LastValid = basics.Round(round + 1000)
	tx.Header.Fee = basics.MicroAlgos{Raw: 1000}

	// If creating, set programs
	if appIdx == 0 {
		testprog := testproglight
		var schemaamt uint64
		if load == "appheavy" {
			testprog = testprogheavy
			schemaamt = heavyWriteCount
		}
		tx.ApprovalProgram = testprog
		tx.ClearStateProgram = testprog
		tx.GlobalStateSchema = basics.StateSchema{
			NumByteSlice: schemaamt,
		}
		tx.LocalStateSchema = basics.StateSchema{
			NumByteSlice: schemaamt,
		}
	}

	return tx, nil
}

type alwaysVerifiedCache struct{}

func (vc *alwaysVerifiedCache) Verified(txn transactions.SignedTxn, params verify.Params) bool {
	return true
}

func makeUnsignedPayment(sender basics.Address, round int) transactions.Transaction {
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

func benchmarkFullAppBlocks(txtype string, b *testing.B) {
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
		var j uint64
		for {
			j++
			// make a transaction that will create an application or call it
			var tx transactions.Transaction
			tx, err = makeUnsignedApplicationCallTxPerf(createdAppIdx, txtype, onCompletion, i)
			require.NoError(b, err)
			tx.Sender = creator
			tx.Note = []byte(fmt.Sprintf("%d,%d", i, j))
			tx.GenesisHash = crypto.Digest{1}

			// add tx to block
			var stxn transactions.SignedTxn
			stxn.Txn = tx
			err = eval.Transaction(stxn, transactions.ApplyData{})

			// check if block is full
			if err == ErrNoSpace {
				b.Logf("made full block with %d txns", j)
				break
			} else {
				require.NoError(b, err)
			}

			// First block just creates app, don't fill it up
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

		err = l0.AddBlock(lvb.blk, cert)
		require.NoError(b, err)

		blocks = append(blocks, lvb.blk)
	}

	b.Logf("built %d blocks", numBlocks)

	// eval + add all the (valid) blocks to the second ledger, timing it
	vc := alwaysVerifiedCache{}
	b.ResetTimer()
	for _, blk := range blocks {
		_, err = l1.eval(context.Background(), blk, true, &vc, nil)
		require.NoError(b, err)
		err = l1.AddBlock(blk, cert)
		require.NoError(b, err)
	}
}

func benchmarkBlockEvalPerf(txtype string, txPerBlock int, b *testing.B) {
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

	// We will delete apps, generating 2x as many transactions
	if txtype == "appheavy" || txtype == "applight" {
		txPerBlock = txPerBlock / 2
	}

	// give creators money for min balance
	var creators []basics.Address
	numCreators := txPerBlock
	for i := 0; i < numCreators; i++ {
		creator := basics.Address{}
		_, err = rand.Read(creator[:])
		require.NoError(b, err)
		creators = append(creators, creator)
		genesisInitState.Accounts[creator] = basics.MakeAccountData(basics.Offline, basics.MicroAlgos{Raw: 1234567890})
	}

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

	// init both ledgers, and build all the blocks in the first ledger
	numBlocks := b.N
	cert := agreement.Certificate{}
	var blocks []bookkeeping.Block
	for i := 0; i < numBlocks; i++ {
		blk.BlockHeader.Round++
		blk.BlockHeader.TimeStamp += int64(crypto.RandUint64() % 100 * 1000)
		blk.BlockHeader.GenesisID = "x"

		if i == 0 {
			err = l0.AddBlock(blk, cert)
			require.NoError(b, err)

			err = l1.AddBlock(blk, cert)
			require.NoError(b, err)
			continue
		}

		prev, err := l0.BlockHdr(basics.Round(i))
		require.NoError(b, err)

		newBlk := bookkeeping.MakeBlock(prev)
		eval, err := l0.StartEvaluator(newBlk.BlockHeader)
		require.NoError(b, err)

		// build a payset
		for j := 0; j < txPerBlock; j++ {
			// make a transaction that will create an asset or application
			var tx transactions.Transaction

			if txtype == "appheavy" || txtype == "applight" {
				tx, err = makeUnsignedApplicationCallTxPerf(0, txtype, transactions.OptInOC, i)
			} else if txtype == "asset" {
				creatorEncoded := creators[j].String()
				tx, err = makeUnsignedAssetCreateTx(basics.Round(i), basics.Round(i)+1000, 100, false, creatorEncoded, creatorEncoded, creatorEncoded, creatorEncoded, "m", "m", "", nil)
			} else if txtype == "pay" {
				tx = makeUnsignedPayment(creators[j], i)
			} else {
				b.Error("unknown tx type")
			}
			require.NoError(b, err)
			tx.Sender = creators[j]
			tx.Note = []byte(fmt.Sprintf("%d,%d", i, j))
			tx.GenesisHash = crypto.Digest{1}

			var stxn transactions.SignedTxn
			stxn.Txn = tx

			err = eval.Transaction(stxn, transactions.ApplyData{})
			require.NoError(b, err)

			// Delete the newly created app
			if txtype == "appheavy" || txtype == "applight" {
				createdAppID := eval.state.txnCounter()
				tx, err = makeUnsignedApplicationCallTxPerf(createdAppID, txtype, transactions.DeleteApplicationOC, i)
				require.NoError(b, err)
				tx.Sender = creators[j]
				tx.Note = []byte(fmt.Sprintf("%d,%d", i, j))
				tx.GenesisHash = crypto.Digest{1}

				var stxn transactions.SignedTxn
				stxn.Txn = tx

				err = eval.Transaction(stxn, transactions.ApplyData{})
				require.NoError(b, err)
			}
		}

		lvb, err := eval.GenerateBlock()
		require.NoError(b, err)

		err = l0.AddBlock(lvb.blk, cert)
		require.NoError(b, err)

		blocks = append(blocks, lvb.blk)
	}

	b.Logf("built %d blocks, %d transactions", numBlocks, txPerBlock)

	// eval + add all the (valid) blocks to the second ledger, timing it
	vc := alwaysVerifiedCache{}
	b.ResetTimer()
	for _, blk := range blocks {
		_, err = l1.eval(context.Background(), blk, true, &vc, nil)
		require.NoError(b, err)
		err = l1.AddBlock(blk, cert)
		require.NoError(b, err)
	}
}

func BenchmarkPaymentEvalPerf100(b *testing.B)  { benchmarkBlockEvalPerf("pay", 100, b) }
func BenchmarkPaymentEvalPerf500(b *testing.B)  { benchmarkBlockEvalPerf("pay", 500, b) }
func BenchmarkPaymentEvalPerf1000(b *testing.B) { benchmarkBlockEvalPerf("pay", 1000, b) }
func BenchmarkPaymentEvalPerf1500(b *testing.B) { benchmarkBlockEvalPerf("pay", 1500, b) }
func BenchmarkPaymentEvalPerf5000(b *testing.B) { benchmarkBlockEvalPerf("pay", 5000, b) }

func BenchmarkAssetEvalPerf100(b *testing.B)  { benchmarkBlockEvalPerf("asset", 100, b) }
func BenchmarkAssetEvalPerf500(b *testing.B)  { benchmarkBlockEvalPerf("asset", 500, b) }
func BenchmarkAssetEvalPerf1000(b *testing.B) { benchmarkBlockEvalPerf("asset", 1000, b) }
func BenchmarkAssetEvalPerf1500(b *testing.B) { benchmarkBlockEvalPerf("asset", 1500, b) }
func BenchmarkAssetEvalPerf2000(b *testing.B) { benchmarkBlockEvalPerf("asset", 2000, b) }

func BenchmarkAppLightEvalPerf100(b *testing.B)  { benchmarkBlockEvalPerf("applight", 100, b) }
func BenchmarkAppLightEvalPerf500(b *testing.B)  { benchmarkBlockEvalPerf("applight", 500, b) }
func BenchmarkAppLightEvalPerf1000(b *testing.B) { benchmarkBlockEvalPerf("applight", 1000, b) }
func BenchmarkAppLightEvalPerf1500(b *testing.B) { benchmarkBlockEvalPerf("applight", 1500, b) }
func BenchmarkAppLightEvalPerf2000(b *testing.B) { benchmarkBlockEvalPerf("applight", 2000, b) }

func BenchmarkAppHeavyEvalPerf100(b *testing.B)  { benchmarkBlockEvalPerf("appheavy", 100, b) }
func BenchmarkAppHeavyEvalPerf500(b *testing.B)  { benchmarkBlockEvalPerf("appheavy", 500, b) }
func BenchmarkAppHeavyEvalPerf1000(b *testing.B) { benchmarkBlockEvalPerf("appheavy", 1000, b) }
func BenchmarkAppHeavyEvalPerf1500(b *testing.B) { benchmarkBlockEvalPerf("appheavy", 1500, b) }
func BenchmarkAppHeavyEvalPerf2000(b *testing.B) { benchmarkBlockEvalPerf("appheavy", 2000, b) }

func BenchmarkAppFullHeavy(b *testing.B) { benchmarkFullAppBlocks("appheavy", b) }
func BenchmarkAppFullLight(b *testing.B) { benchmarkFullAppBlocks("applight", b) }

func init() {
	heavyPrefix := `
		int 1
		itob
		app_global_get
		bnz delete
	`

	heavyWritePrefix := `
		write:
		int 0
	`

	heavyBlockWrite := `
		int 1
		+
		dup
		itob
		dup
		app_global_put
	`

	heavyWriteSuffix := `
		pop
		int 1
		return
	`

	heavyDeletePrefix := `
		delete:
		int 0
	`

	heavyBlockDelete := `
		int 1
		+
		dup
		itob
		app_global_del
	`

	heavyDeleteSuffix := `
		pop
		int 1
		return
	`

	var heavyProgParts []string
	heavyProgParts = append(heavyProgParts, heavyPrefix)
	heavyProgParts = append(heavyProgParts, heavyWritePrefix)
	for i := 0; i < heavyWriteCount; i++ {
		heavyProgParts = append(heavyProgParts, heavyBlockWrite)
	}
	heavyProgParts = append(heavyProgParts, heavyWriteSuffix)
	heavyProgParts = append(heavyProgParts, heavyDeletePrefix)
	for i := 0; i < heavyWriteCount; i++ {
		heavyProgParts = append(heavyProgParts, heavyBlockDelete)
	}
	heavyProgParts = append(heavyProgParts, heavyDeleteSuffix)

	testasm := strings.Join(heavyProgParts, "\n")

	heavyBytes, err := logic.AssembleString(testasm)
	if err != nil {
		panic(err)
	}
	testprogheavy = string(heavyBytes)

	testasm = `int 1`
	lightBytes, err := logic.AssembleString(testasm)
	if err != nil {
		panic(err)
	}
	testproglight = string(lightBytes)
}
