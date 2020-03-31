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
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/algorand/go-algorand/agreement"
	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/bookkeeping"
	"github.com/algorand/go-algorand/data/transactions"
	"github.com/algorand/go-algorand/data/transactions/verify"
	//"github.com/algorand/go-algorand/data/transactions/logic"
	"github.com/algorand/go-algorand/logging"
	"github.com/algorand/go-algorand/protocol"
)

var testprog string

/*func makeUnsignedApplicationCallTxPerf(appIdx uint64, onCompletion transactions.OnCompletion) (tx transactions.Transaction, err error) {
	tx.Type = protocol.ApplicationCallTx
	tx.ApplicationID = basics.AppIndex(appIdx)
	tx.OnCompletion = onCompletion

	// If creating, set programs
	if appIdx == 0 {
		tx.ApprovalProgram = string(testprog)
		tx.ClearStateProgram = string(testprog)
		tx.GlobalStateSchema = basics.StateSchema{
			NumByteSlice: 50,
		}
		tx.LocalStateSchema = basics.StateSchema{
			NumByteSlice: 50,
		}
	}

	return tx, nil
}*/

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

func benchmarkBlockEvalPerf(txtype string, txPerBlockAndNumCreators int, b *testing.B) {
	// Start in archival mode, add 2K blocks with asset + app txns
	// restart, ensure all assets are there in index unless they were
	// deleted

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

	// give creators money for min balance
	var creators []basics.Address
	for i := 0; i < txPerBlockAndNumCreators; i++ {
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
		for j := 0; j < txPerBlockAndNumCreators; j++ {
			// make a transaction that will create an asset or application
			var tx transactions.Transaction

			/*if txtype == "app" {
				tx, err = makeUnsignedApplicationCallTxPerf(0, transactions.OptInOC)
			} else*/
			if txtype == "asset" {
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
		}

		lvb, err := eval.GenerateBlock()
		require.NoError(b, err)

		err = l0.AddBlock(lvb.blk, cert)
		require.NoError(b, err)

		blocks = append(blocks, lvb.blk)
	}

	b.Logf("built %d blocks, %d transactions", numBlocks, txPerBlockAndNumCreators)

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

/*
func BenchmarkAppEvalPerf100(b *testing.B)  { benchmarkBlockEvalPerf("app", 100, b) }
func BenchmarkAppEvalPerf500(b *testing.B)  { benchmarkBlockEvalPerf("app", 500, b) }
func BenchmarkAppEvalPerf1000(b *testing.B) { benchmarkBlockEvalPerf("app", 1000, b) }
func BenchmarkAppEvalPerf1500(b *testing.B) { benchmarkBlockEvalPerf("app", 1500, b) }
func BenchmarkAppEvalPerf2000(b *testing.B) { benchmarkBlockEvalPerf("app", 2000, b) }

func init() {
	testasm := `
byte base64 MA==
byte base64 YmFy
app_global_put


byte base64 MQ==
byte base64 YmFy
app_global_put


byte base64 Mg==
byte base64 YmFy
app_global_put


byte base64 Mw==
byte base64 YmFy
app_global_put


byte base64 NA==
byte base64 YmFy
app_global_put


byte base64 NQ==
byte base64 YmFy
app_global_put


byte base64 Ng==
byte base64 YmFy
app_global_put


byte base64 Nw==
byte base64 YmFy
app_global_put


byte base64 OA==
byte base64 YmFy
app_global_put


byte base64 OQ==
byte base64 YmFy
app_global_put


byte base64 MTA=
byte base64 YmFy
app_global_put


byte base64 MTE=
byte base64 YmFy
app_global_put


byte base64 MTI=
byte base64 YmFy
app_global_put


byte base64 MTM=
byte base64 YmFy
app_global_put


byte base64 MTQ=
byte base64 YmFy
app_global_put


byte base64 MTU=
byte base64 YmFy
app_global_put


byte base64 MTY=
byte base64 YmFy
app_global_put


byte base64 MTc=
byte base64 YmFy
app_global_put


byte base64 MTg=
byte base64 YmFy
app_global_put


byte base64 MTk=
byte base64 YmFy
app_global_put


byte base64 MjA=
byte base64 YmFy
app_global_put


byte base64 MjE=
byte base64 YmFy
app_global_put


byte base64 MjI=
byte base64 YmFy
app_global_put


byte base64 MjM=
byte base64 YmFy
app_global_put


byte base64 MjQ=
byte base64 YmFy
app_global_put


byte base64 MjU=
byte base64 YmFy
app_global_put


byte base64 MjY=
byte base64 YmFy
app_global_put


byte base64 Mjc=
byte base64 YmFy
app_global_put


byte base64 Mjg=
byte base64 YmFy
app_global_put


byte base64 Mjk=
byte base64 YmFy
app_global_put


byte base64 MzA=
byte base64 YmFy
app_global_put


byte base64 MzE=
byte base64 YmFy
app_global_put


byte base64 MzI=
byte base64 YmFy
app_global_put


byte base64 MzM=
byte base64 YmFy
app_global_put


byte base64 MzQ=
byte base64 YmFy
app_global_put


byte base64 MzU=
byte base64 YmFy
app_global_put


byte base64 MzY=
byte base64 YmFy
app_global_put


byte base64 Mzc=
byte base64 YmFy
app_global_put


byte base64 Mzg=
byte base64 YmFy
app_global_put


byte base64 Mzk=
byte base64 YmFy
app_global_put


byte base64 NDA=
byte base64 YmFy
app_global_put


byte base64 NDE=
byte base64 YmFy
app_global_put


byte base64 NDI=
byte base64 YmFy
app_global_put


byte base64 NDM=
byte base64 YmFy
app_global_put


byte base64 NDQ=
byte base64 YmFy
app_global_put


byte base64 NDU=
byte base64 YmFy
app_global_put


byte base64 NDY=
byte base64 YmFy
app_global_put


byte base64 NDc=
byte base64 YmFy
app_global_put


byte base64 NDg=
byte base64 YmFy
app_global_put


byte base64 NDk=
byte base64 YmFy
app_global_put

int 0
byte base64 MA==
byte base64 YmFy
app_local_put


int 0
byte base64 MQ==
byte base64 YmFy
app_local_put


int 0
byte base64 Mg==
byte base64 YmFy
app_local_put


int 0
byte base64 Mw==
byte base64 YmFy
app_local_put


int 0
byte base64 NA==
byte base64 YmFy
app_local_put


int 0
byte base64 NQ==
byte base64 YmFy
app_local_put


int 0
byte base64 Ng==
byte base64 YmFy
app_local_put


int 0
byte base64 Nw==
byte base64 YmFy
app_local_put


int 0
byte base64 OA==
byte base64 YmFy
app_local_put


int 0
byte base64 OQ==
byte base64 YmFy
app_local_put


int 0
byte base64 MTA=
byte base64 YmFy
app_local_put


int 0
byte base64 MTE=
byte base64 YmFy
app_local_put


int 0
byte base64 MTI=
byte base64 YmFy
app_local_put


int 0
byte base64 MTM=
byte base64 YmFy
app_local_put


int 0
byte base64 MTQ=
byte base64 YmFy
app_local_put


int 0
byte base64 MTU=
byte base64 YmFy
app_local_put


int 0
byte base64 MTY=
byte base64 YmFy
app_local_put


int 0
byte base64 MTc=
byte base64 YmFy
app_local_put


int 0
byte base64 MTg=
byte base64 YmFy
app_local_put


int 0
byte base64 MTk=
byte base64 YmFy
app_local_put


int 0
byte base64 MjA=
byte base64 YmFy
app_local_put


int 0
byte base64 MjE=
byte base64 YmFy
app_local_put


int 0
byte base64 MjI=
byte base64 YmFy
app_local_put


int 0
byte base64 MjM=
byte base64 YmFy
app_local_put


int 0
byte base64 MjQ=
byte base64 YmFy
app_local_put


int 0
byte base64 MjU=
byte base64 YmFy
app_local_put


int 0
byte base64 MjY=
byte base64 YmFy
app_local_put


int 0
byte base64 Mjc=
byte base64 YmFy
app_local_put


int 0
byte base64 Mjg=
byte base64 YmFy
app_local_put


int 0
byte base64 Mjk=
byte base64 YmFy
app_local_put


int 0
byte base64 MzA=
byte base64 YmFy
app_local_put


int 0
byte base64 MzE=
byte base64 YmFy
app_local_put


int 0
byte base64 MzI=
byte base64 YmFy
app_local_put


int 0
byte base64 MzM=
byte base64 YmFy
app_local_put


int 0
byte base64 MzQ=
byte base64 YmFy
app_local_put


int 0
byte base64 MzU=
byte base64 YmFy
app_local_put


int 0
byte base64 MzY=
byte base64 YmFy
app_local_put


int 0
byte base64 Mzc=
byte base64 YmFy
app_local_put


int 0
byte base64 Mzg=
byte base64 YmFy
app_local_put


int 0
byte base64 Mzk=
byte base64 YmFy
app_local_put


int 0
byte base64 NDA=
byte base64 YmFy
app_local_put


int 0
byte base64 NDE=
byte base64 YmFy
app_local_put


int 0
byte base64 NDI=
byte base64 YmFy
app_local_put


int 0
byte base64 NDM=
byte base64 YmFy
app_local_put


int 0
byte base64 NDQ=
byte base64 YmFy
app_local_put


int 0
byte base64 NDU=
byte base64 YmFy
app_local_put


int 0
byte base64 NDY=
byte base64 YmFy
app_local_put


int 0
byte base64 NDc=
byte base64 YmFy
app_local_put


int 0
byte base64 NDg=
byte base64 YmFy
app_local_put


int 0
byte base64 NDk=
byte base64 YmFy
app_local_put

int 1
`
	// testasm = `int 1`
	testprogBytes, err := logic.AssembleString(testasm)
	if err != nil {
		panic(err)
	}
	testprog = string(testprogBytes)
}*/
