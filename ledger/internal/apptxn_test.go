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

package internal_test

import (
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
	"github.com/algorand/go-algorand/data/transactions/logic"
	"github.com/algorand/go-algorand/data/txntest"
	"github.com/algorand/go-algorand/ledger"
	"github.com/algorand/go-algorand/ledger/ledgercore"
	ledgertesting "github.com/algorand/go-algorand/ledger/testing"
	"github.com/algorand/go-algorand/logging"
	"github.com/algorand/go-algorand/protocol"
	"github.com/algorand/go-algorand/test/partitiontest"
)

// main wraps up some TEAL source in a header and footer so that it is
// an app that does nothing at create time, but otherwise runs source,
// then approves, if the source avoids panicing and leaves the stack
// empty.
func main(source string) string {
	return strings.Replace(fmt.Sprintf(`txn ApplicationID
            bz end
            %s
       end: int 1`, source), ";", "\n", -1)
}

// TestPayAction ensures a pay in teal affects balances
func TestPayAction(t *testing.T) {
	partitiontest.PartitionTest(t)

	genesisInitState, addrs, _ := ledgertesting.Genesis(10)

	l, err := ledger.OpenLedger(logging.TestingLog(t), "", true, genesisInitState, config.GetDefaultLocal())
	require.NoError(t, err)
	defer l.Close()

	create := txntest.Txn{
		Type:   "appl",
		Sender: addrs[0],
		ApprovalProgram: main(`
         itxn_begin
         int pay
         itxn_field TypeEnum
         int 5000
         itxn_field Amount
         txn Accounts 1
         itxn_field Receiver
         itxn_submit
`),
	}

	ai := basics.AppIndex(1)
	fund := txntest.Txn{
		Type:     "pay",
		Sender:   addrs[0],
		Receiver: ai.Address(),
		Amount:   200000, // account min balance, plus fees
	}

	payout1 := txntest.Txn{
		Type:          "appl",
		Sender:        addrs[1],
		ApplicationID: ai,
		Accounts:      []basics.Address{addrs[1]}, // pay self
	}

	eval := nextBlock(t, l)
	txns(t, l, eval, &create, &fund, &payout1)
	vb := endBlock(t, l, eval)

	// AD contains expected appIndex
	require.Equal(t, ai, vb.Block().Payset[0].ApplyData.ApplicationID)

	ad0 := micros(t, l, addrs[0])
	ad1 := micros(t, l, addrs[1])
	app := micros(t, l, ai.Address())

	genAccounts := genesisInitState.Accounts
	// create(1000) and fund(1000 + 200000)
	require.Equal(t, uint64(202000), genAccounts[addrs[0]].MicroAlgos.Raw-ad0)
	// paid 5000, but 1000 fee
	require.Equal(t, uint64(4000), ad1-genAccounts[addrs[1]].MicroAlgos.Raw)
	// app still has 194000 (paid out 5000, and paid fee to do it)
	require.Equal(t, uint64(194000), app)

	// Build up Residue in RewardsState so it's ready to pay
	for i := 1; i < 10; i++ {
		eval = nextBlock(t, l)
		endBlock(t, l, eval)
	}

	eval = nextBlock(t, l)
	payout2 := txntest.Txn{
		Type:          "appl",
		Sender:        addrs[1],
		ApplicationID: ai,
		Accounts:      []basics.Address{addrs[2]}, // pay other
	}
	txn(t, l, eval, &payout2)
	// confirm that modifiedAccounts can see account in inner txn
	vb = endBlock(t, l, eval)

	deltas := vb.Delta()
	require.Contains(t, deltas.Accts.ModifiedAccounts(), addrs[2])

	payInBlock := vb.Block().Payset[0]
	rewards := payInBlock.ApplyData.SenderRewards.Raw
	require.Greater(t, rewards, uint64(2000)) // some biggish number
	inners := payInBlock.ApplyData.EvalDelta.InnerTxns
	require.Len(t, inners, 1)

	// addr[2] is going to get the same rewards as addr[1], who
	// originally sent the top-level txn.  Both had their algo balance
	// touched and has very nearly the same balance.
	require.Equal(t, rewards, inners[0].ReceiverRewards.Raw)
	// app gets none, because it has less than 1A
	require.Equal(t, uint64(0), inners[0].SenderRewards.Raw)

	ad1 = micros(t, l, addrs[1])
	ad2 := micros(t, l, addrs[2])
	app = micros(t, l, ai.Address())

	// paid 5000, in first payout (only), but paid 1000 fee in each payout txn
	require.Equal(t, rewards+3000, ad1-genAccounts[addrs[1]].MicroAlgos.Raw)
	// app still has 188000 (paid out 10000, and paid 2k fees to do it)
	// no rewards because owns less than an algo
	require.Equal(t, uint64(200000)-10000-2000, app)

	// paid 5000 by payout2, never paid any fees, got same rewards
	require.Equal(t, rewards+uint64(5000), ad2-genAccounts[addrs[2]].MicroAlgos.Raw)

	// Now fund the app account much more, so we can confirm it gets rewards.
	tenkalgos := txntest.Txn{
		Type:     "pay",
		Sender:   addrs[0],
		Receiver: ai.Address(),
		Amount:   10 * 1000 * 1000000, // account min balance, plus fees
	}
	eval = nextBlock(t, l)
	txn(t, l, eval, &tenkalgos)
	endBlock(t, l, eval)
	beforepay := micros(t, l, ai.Address())

	// Build up Residue in RewardsState so it's ready to pay again
	for i := 1; i < 10; i++ {
		eval = nextBlock(t, l)
		endBlock(t, l, eval)
	}
	eval = nextBlock(t, l)
	txn(t, l, eval, payout2.Noted("2"))
	vb = endBlock(t, l, eval)

	afterpay := micros(t, l, ai.Address())

	payInBlock = vb.Block().Payset[0]
	inners = payInBlock.ApplyData.EvalDelta.InnerTxns
	require.Len(t, inners, 1)

	appreward := inners[0].SenderRewards.Raw
	require.Greater(t, appreward, uint64(1000))

	require.Equal(t, beforepay+appreward-5000-1000, afterpay)
}

// TestAxferAction ensures axfers in teal have the intended effects
func TestAxferAction(t *testing.T) {
	partitiontest.PartitionTest(t)

	genesisInitState, addrs, _ := ledgertesting.Genesis(10)

	l, err := ledger.OpenLedger(logging.TestingLog(t), "", true, genesisInitState, config.GetDefaultLocal())
	require.NoError(t, err)
	defer l.Close()

	asa := txntest.Txn{
		Type:   "acfg",
		Sender: addrs[0],
		AssetParams: basics.AssetParams{
			Total:     1000000,
			Decimals:  3,
			UnitName:  "oz",
			AssetName: "Gold",
			URL:       "https://gold.rush/",
		},
	}

	app := txntest.Txn{
		Type:   "appl",
		Sender: addrs[0],
		ApprovalProgram: main(`
         itxn_begin
         int axfer
         itxn_field TypeEnum
         txn Assets 0
         itxn_field XferAsset

         txn ApplicationArgs 0
         byte "optin"
         ==
         bz withdraw
         // let AssetAmount default to 0
         global CurrentApplicationAddress
         itxn_field AssetReceiver
         b submit
withdraw:
         txn ApplicationArgs 0
         byte "close"
         ==
         bz noclose
         txn Accounts 1
         itxn_field AssetCloseTo
         b skipamount
noclose: int 10000
         itxn_field AssetAmount
skipamount:
         txn Accounts 1
         itxn_field AssetReceiver
submit:  itxn_submit
`),
	}

	eval := nextBlock(t, l)
	txns(t, l, eval, &asa, &app)
	vb := endBlock(t, l, eval)

	asaIndex := basics.AssetIndex(1)
	require.Equal(t, asaIndex, vb.Block().Payset[0].ApplyData.ConfigAsset)
	appIndex := basics.AppIndex(2)
	require.Equal(t, appIndex, vb.Block().Payset[1].ApplyData.ApplicationID)

	fund := txntest.Txn{
		Type:     "pay",
		Sender:   addrs[0],
		Receiver: appIndex.Address(),
		Amount:   300000, // account min balance, optin min balance, plus fees
		// stay under 1M, to avoid rewards complications
	}

	eval = nextBlock(t, l)
	txn(t, l, eval, &fund)
	endBlock(t, l, eval)

	fundgold := txntest.Txn{
		Type:          "axfer",
		Sender:        addrs[0],
		XferAsset:     asaIndex,
		AssetReceiver: appIndex.Address(),
		AssetAmount:   20000,
	}

	// Fail, because app account is not opted in.
	eval = nextBlock(t, l)
	txn(t, l, eval, &fundgold, fmt.Sprintf("asset %d missing", asaIndex))
	endBlock(t, l, eval)

	amount, in := holding(t, l, appIndex.Address(), asaIndex)
	require.False(t, in)
	require.Equal(t, amount, uint64(0))

	optin := txntest.Txn{
		Type:            "appl",
		ApplicationID:   appIndex,
		Sender:          addrs[0],
		ApplicationArgs: [][]byte{[]byte("optin")},
		ForeignAssets:   []basics.AssetIndex{asaIndex},
	}

	// Tell the app to opt itself in.
	eval = nextBlock(t, l)
	txn(t, l, eval, &optin)
	endBlock(t, l, eval)

	amount, in = holding(t, l, appIndex.Address(), asaIndex)
	require.True(t, in)
	require.Equal(t, amount, uint64(0))

	// Now, suceed, because opted in.
	eval = nextBlock(t, l)
	txn(t, l, eval, &fundgold)
	endBlock(t, l, eval)

	amount, in = holding(t, l, appIndex.Address(), asaIndex)
	require.True(t, in)
	require.Equal(t, amount, uint64(20000))

	withdraw := txntest.Txn{
		Type:            "appl",
		ApplicationID:   appIndex,
		Sender:          addrs[0],
		ApplicationArgs: [][]byte{[]byte("withdraw")},
		ForeignAssets:   []basics.AssetIndex{asaIndex},
		Accounts:        []basics.Address{addrs[0]},
	}
	eval = nextBlock(t, l)
	txn(t, l, eval, &withdraw)
	endBlock(t, l, eval)

	amount, in = holding(t, l, appIndex.Address(), asaIndex)
	require.True(t, in)
	require.Equal(t, amount, uint64(10000))

	eval = nextBlock(t, l)
	txn(t, l, eval, withdraw.Noted("2"))
	endBlock(t, l, eval)

	amount, in = holding(t, l, appIndex.Address(), asaIndex)
	require.True(t, in) // Zero left, but still opted in
	require.Equal(t, amount, uint64(0))

	eval = nextBlock(t, l)
	txn(t, l, eval, withdraw.Noted("3"), "underflow on subtracting")
	endBlock(t, l, eval)

	amount, in = holding(t, l, appIndex.Address(), asaIndex)
	require.True(t, in) // Zero left, but still opted in
	require.Equal(t, amount, uint64(0))

	close := txntest.Txn{
		Type:            "appl",
		ApplicationID:   appIndex,
		Sender:          addrs[0],
		ApplicationArgs: [][]byte{[]byte("close")},
		ForeignAssets:   []basics.AssetIndex{asaIndex},
		Accounts:        []basics.Address{addrs[0]},
	}

	eval = nextBlock(t, l)
	txn(t, l, eval, &close)
	endBlock(t, l, eval)

	amount, in = holding(t, l, appIndex.Address(), asaIndex)
	require.False(t, in) // Zero left, not opted in
	require.Equal(t, amount, uint64(0))

	// Now, fail again, opted out
	eval = nextBlock(t, l)
	txn(t, l, eval, fundgold.Noted("2"), fmt.Sprintf("asset %d missing", asaIndex))
	endBlock(t, l, eval)

	// Do it all again, so we can test closeTo when we have a non-zero balance
	// Tell the app to opt itself in.
	eval = nextBlock(t, l)
	txns(t, l, eval, optin.Noted("a"), fundgold.Noted("a"))
	endBlock(t, l, eval)

	amount, _ = holding(t, l, appIndex.Address(), asaIndex)
	require.Equal(t, uint64(20000), amount)
	left, _ := holding(t, l, addrs[0], asaIndex)

	eval = nextBlock(t, l)
	txn(t, l, eval, close.Noted("a"))
	endBlock(t, l, eval)

	amount, _ = holding(t, l, appIndex.Address(), asaIndex)
	require.Equal(t, uint64(0), amount)
	back, _ := holding(t, l, addrs[0], asaIndex)
	require.Equal(t, uint64(20000), back-left)
}

func newTestLedger(t testing.TB, balances bookkeeping.GenesisBalances) *ledger.Ledger {
	return newTestLedgerWithConsensusVersion(t, balances, protocol.ConsensusFuture)
}

func newTestLedgerWithConsensusVersion(t testing.TB, balances bookkeeping.GenesisBalances, cv protocol.ConsensusVersion) *ledger.Ledger {
	var genHash crypto.Digest
	crypto.RandBytes(genHash[:])
	return newTestLedgerFull(t, balances, cv, genHash)
}

func newTestLedgerFull(t testing.TB, balances bookkeeping.GenesisBalances, cv protocol.ConsensusVersion, genHash crypto.Digest) *ledger.Ledger {
	genBlock, err := bookkeeping.MakeGenesisBlock(cv, balances, "test", genHash)
	require.NoError(t, err)
	require.False(t, genBlock.FeeSink.IsZero())
	require.False(t, genBlock.RewardsPool.IsZero())
	dbName := fmt.Sprintf("%s.%d", t.Name(), crypto.RandUint64())
	cfg := config.GetDefaultLocal()
	cfg.Archival = true
	l, err := ledger.OpenLedger(logging.Base(), dbName, true, ledgercore.InitState{
		Block:       genBlock,
		Accounts:    balances.Balances,
		GenesisHash: genHash,
	}, cfg)
	require.NoError(t, err)
	return l
}

// TestClawbackAction ensures an app address can act as clawback address.
func TestClawbackAction(t *testing.T) {
	partitiontest.PartitionTest(t)

	genBalances, addrs, _ := ledgertesting.NewTestGenesis()
	l := newTestLedger(t, genBalances)
	defer l.Close()

	asaIndex := basics.AssetIndex(1)
	appIndex := basics.AppIndex(2)

	asa := txntest.Txn{
		Type:   "acfg",
		Sender: addrs[0],
		AssetParams: basics.AssetParams{
			Total:     1000000,
			Decimals:  3,
			UnitName:  "oz",
			AssetName: "Gold",
			URL:       "https://gold.rush/",
			Clawback:  appIndex.Address(),
		},
	}

	app := txntest.Txn{
		Type:   "appl",
		Sender: addrs[0],
		ApprovalProgram: main(`
         itxn_begin

         int axfer
         itxn_field TypeEnum

         txn Assets 0
         itxn_field XferAsset

         txn Accounts 1
         itxn_field AssetSender

         txn Accounts 2
         itxn_field AssetReceiver

         int 1000
         itxn_field AssetAmount

         itxn_submit
`),
	}

	optin := txntest.Txn{
		Type:          "axfer",
		Sender:        addrs[1],
		AssetReceiver: addrs[1],
		XferAsset:     asaIndex,
	}
	eval := nextBlock(t, l)
	txns(t, l, eval, &asa, &app, &optin)
	vb := endBlock(t, l, eval)

	require.Equal(t, asaIndex, vb.Block().Payset[0].ApplyData.ConfigAsset)
	require.Equal(t, appIndex, vb.Block().Payset[1].ApplyData.ApplicationID)

	bystander := addrs[2] // Has no authority of its own
	overpay := txntest.Txn{
		Type:     "pay",
		Sender:   bystander,
		Receiver: bystander,
		Fee:      2000, // Overpay fee so that app account can be unfunded
	}
	clawmove := txntest.Txn{
		Type:          "appl",
		Sender:        bystander,
		ApplicationID: appIndex,
		ForeignAssets: []basics.AssetIndex{asaIndex},
		Accounts:      []basics.Address{addrs[0], addrs[1]},
	}
	eval = nextBlock(t, l)
	err := txgroup(t, l, eval, &overpay, &clawmove)
	require.NoError(t, err)
	endBlock(t, l, eval)

	amount, _ := holding(t, l, addrs[1], asaIndex)
	require.Equal(t, amount, uint64(1000))
}

// TestRekeyAction ensures an app can transact for a rekeyed account
func TestRekeyAction(t *testing.T) {
	partitiontest.PartitionTest(t)

	genBalances, addrs, _ := ledgertesting.NewTestGenesis()
	l := newTestLedger(t, genBalances)
	defer l.Close()

	appIndex := basics.AppIndex(1)
	ezpayer := txntest.Txn{
		Type:   "appl",
		Sender: addrs[5],
		ApprovalProgram: main(`
         itxn_begin
         int pay
         itxn_field TypeEnum
         int 5000
         itxn_field Amount
         txn Accounts 1
         itxn_field Sender
         txn Accounts 2
         itxn_field Receiver
         txn NumAccounts
         int 3
         ==
         bz skipclose
         txn Accounts 3
         itxn_field CloseRemainderTo
skipclose:
         itxn_submit
`),
	}

	rekey := txntest.Txn{
		Type:     "pay",
		Sender:   addrs[0],
		Receiver: addrs[0],
		RekeyTo:  appIndex.Address(),
	}

	eval := nextBlock(t, l)
	txns(t, l, eval, &ezpayer, &rekey)
	endBlock(t, l, eval)

	useacct := txntest.Txn{
		Type:          "appl",
		Sender:        addrs[1],
		ApplicationID: appIndex,
		Accounts:      []basics.Address{addrs[0], addrs[2]}, // pay 2 from 0 (which was rekeyed)
	}
	eval = nextBlock(t, l)
	txn(t, l, eval, &useacct)
	endBlock(t, l, eval)

	// App was never funded (didn't spend from it's own acct)
	require.Equal(t, uint64(0), micros(t, l, basics.AppIndex(1).Address()))
	// addrs[2] got paid
	require.Equal(t, uint64(5000), micros(t, l, addrs[2])-micros(t, l, addrs[6]))
	// addrs[0] paid 5k + rekey fee + inner txn fee
	require.Equal(t, uint64(7000), micros(t, l, addrs[6])-micros(t, l, addrs[0]))

	baduse := txntest.Txn{
		Type:          "appl",
		Sender:        addrs[1],
		ApplicationID: appIndex,
		Accounts:      []basics.Address{addrs[2], addrs[0]}, // pay 0 from 2
	}
	eval = nextBlock(t, l)
	txn(t, l, eval, &baduse, "unauthorized")
	endBlock(t, l, eval)

	// Now, we close addrs[0], which wipes its rekey status.  Reopen
	// it, and make sure the app can't spend.

	close := txntest.Txn{
		Type:          "appl",
		Sender:        addrs[1],
		ApplicationID: appIndex,
		Accounts:      []basics.Address{addrs[0], addrs[2], addrs[3]}, // close to 3
	}
	eval = nextBlock(t, l)
	txn(t, l, eval, &close)
	endBlock(t, l, eval)

	require.Equal(t, uint64(0), micros(t, l, addrs[0]))

	payback := txntest.Txn{
		Type:     "pay",
		Sender:   addrs[3],
		Receiver: addrs[0],
		Amount:   10_000_000,
	}
	eval = nextBlock(t, l)
	txn(t, l, eval, &payback)
	endBlock(t, l, eval)

	require.Equal(t, uint64(10_000_000), micros(t, l, addrs[0]))

	eval = nextBlock(t, l)
	txn(t, l, eval, useacct.Noted("2"), "unauthorized")
	endBlock(t, l, eval)
}

// TestRekeyActionCloseAccount ensures closing and reopening a rekeyed account in a single app call
// properly removes the app as an authorizer for the account
func TestRekeyActionCloseAccount(t *testing.T) {
	partitiontest.PartitionTest(t)

	genBalances, addrs, _ := ledgertesting.NewTestGenesis()
	l := newTestLedger(t, genBalances)
	defer l.Close()

	appIndex := basics.AppIndex(1)
	create := txntest.Txn{
		Type:   "appl",
		Sender: addrs[5],
		ApprovalProgram: main(`
         // close account 1
         itxn_begin
         int pay
         itxn_field TypeEnum
         txn Accounts 1
         itxn_field Sender
         txn Accounts 2
         itxn_field CloseRemainderTo
         itxn_submit

         // reopen account 1
         itxn_begin
         int pay
         itxn_field TypeEnum
         int 5000
         itxn_field Amount
         txn Accounts 1
         itxn_field Receiver
         itxn_submit
         // send from account 1 again (should fail because closing an account erases rekeying)
         itxn_begin
         int pay
         itxn_field TypeEnum
         int 1
         itxn_field Amount
         txn Accounts 1
         itxn_field Sender
         txn Accounts 2
         itxn_field Receiver
         itxn_submit
`),
	}

	rekey := txntest.Txn{
		Type:     "pay",
		Sender:   addrs[0],
		Receiver: addrs[0],
		RekeyTo:  appIndex.Address(),
	}

	fund := txntest.Txn{
		Type:     "pay",
		Sender:   addrs[1],
		Receiver: appIndex.Address(),
		Amount:   1_000_000,
	}

	eval := nextBlock(t, l)
	txns(t, l, eval, &create, &rekey, &fund)
	endBlock(t, l, eval)

	useacct := txntest.Txn{
		Type:          "appl",
		Sender:        addrs[1],
		ApplicationID: appIndex,
		Accounts:      []basics.Address{addrs[0], addrs[2]},
	}
	eval = nextBlock(t, l)
	txn(t, l, eval, &useacct, "unauthorized")
	endBlock(t, l, eval)
}

// TestDuplicatePayAction shows two pays with same parameters can be done as inner tarnsactions
func TestDuplicatePayAction(t *testing.T) {
	partitiontest.PartitionTest(t)

	genBalances, addrs, _ := ledgertesting.NewTestGenesis()
	l := newTestLedger(t, genBalances)
	defer l.Close()

	appIndex := basics.AppIndex(1)
	create := txntest.Txn{
		Type:   "appl",
		Sender: addrs[0],
		ApprovalProgram: main(`
         itxn_begin
         int pay
         itxn_field TypeEnum
         int 5000
         itxn_field Amount
         txn Accounts 1
         itxn_field Receiver
         itxn_submit
         itxn_begin
         int pay
         itxn_field TypeEnum
         int 5000
         itxn_field Amount
         txn Accounts 1
         itxn_field Receiver
         itxn_submit
`),
	}

	fund := txntest.Txn{
		Type:     "pay",
		Sender:   addrs[0],
		Receiver: appIndex.Address(),
		Amount:   200000, // account min balance, plus fees
	}

	paytwice := txntest.Txn{
		Type:          "appl",
		Sender:        addrs[1],
		ApplicationID: appIndex,
		Accounts:      []basics.Address{addrs[1]}, // pay self
	}

	eval := nextBlock(t, l)
	txns(t, l, eval, &create, &fund, &paytwice, create.Noted("in same block"))
	vb := endBlock(t, l, eval)

	require.Equal(t, appIndex, vb.Block().Payset[0].ApplyData.ApplicationID)
	require.Equal(t, 4, len(vb.Block().Payset))
	// create=1, fund=2, payTwice=3,4,5
	require.Equal(t, basics.AppIndex(6), vb.Block().Payset[3].ApplyData.ApplicationID)

	ad0 := micros(t, l, addrs[0])
	ad1 := micros(t, l, addrs[1])
	app := micros(t, l, appIndex.Address())

	// create(1000) and fund(1000 + 200000), extra create (1000)
	require.Equal(t, 203000, int(genBalances.Balances[addrs[0]].MicroAlgos.Raw-ad0))
	// paid 10000, but 1000 fee on tx
	require.Equal(t, 9000, int(ad1-genBalances.Balances[addrs[1]].MicroAlgos.Raw))
	// app still has 188000 (paid out 10000, and paid 2 x fee to do it)
	require.Equal(t, 188000, int(app))

	// Now create another app, and see if it gets the index we expect.
	eval = nextBlock(t, l)
	txns(t, l, eval, create.Noted("again"))
	vb = endBlock(t, l, eval)

	// create=1, fund=2, payTwice=3,4,5, insameblock=6
	require.Equal(t, basics.AppIndex(7), vb.Block().Payset[0].ApplyData.ApplicationID)
}

// TestInnerTxCount ensures that inner transactions increment the TxnCounter
func TestInnerTxnCount(t *testing.T) {
	partitiontest.PartitionTest(t)

	genBalances, addrs, _ := ledgertesting.NewTestGenesis()
	l := newTestLedger(t, genBalances)
	defer l.Close()

	create := txntest.Txn{
		Type:   "appl",
		Sender: addrs[0],
		ApprovalProgram: main(`
         itxn_begin
         int pay
         itxn_field TypeEnum
         int 5000
         itxn_field Amount
         txn Accounts 1
         itxn_field Receiver
         itxn_submit
`),
	}

	fund := txntest.Txn{
		Type:     "pay",
		Sender:   addrs[0],
		Receiver: basics.AppIndex(1).Address(),
		Amount:   200000, // account min balance, plus fees
	}

	payout1 := txntest.Txn{
		Type:          "appl",
		Sender:        addrs[1],
		ApplicationID: basics.AppIndex(1),
		Accounts:      []basics.Address{addrs[1]}, // pay self
	}

	eval := nextBlock(t, l)
	txns(t, l, eval, &create, &fund)
	vb := endBlock(t, l, eval)
	require.Equal(t, 2, int(vb.Block().TxnCounter))

	eval = nextBlock(t, l)
	txns(t, l, eval, &payout1)
	vb = endBlock(t, l, eval)
	require.Equal(t, 4, int(vb.Block().TxnCounter))
}

// TestAcfgAction ensures assets can be created and configured in teal
func TestAcfgAction(t *testing.T) {
	partitiontest.PartitionTest(t)

	genBalances, addrs, _ := ledgertesting.NewTestGenesis()
	l := newTestLedger(t, genBalances)
	defer l.Close()

	appIndex := basics.AppIndex(1)
	app := txntest.Txn{
		Type:   "appl",
		Sender: addrs[0],
		ApprovalProgram: main(`
         itxn_begin
         int acfg
         itxn_field TypeEnum

         txn ApplicationArgs 0
         byte "create"
         ==
         bz manager
		 int 1000000
		 itxn_field ConfigAssetTotal
		 int 3
		 itxn_field ConfigAssetDecimals
		 byte "oz"
		 itxn_field ConfigAssetUnitName
		 byte "Gold"
		 itxn_field ConfigAssetName
		 byte "https://gold.rush/"
		 itxn_field ConfigAssetURL

         global CurrentApplicationAddress
         dup
         dup2
         itxn_field ConfigAssetManager
         itxn_field ConfigAssetReserve
         itxn_field ConfigAssetFreeze
         itxn_field ConfigAssetClawback
         b submit
manager:
         // Put the current values in the itxn
         txn Assets 0
         asset_params_get AssetManager
         assert // exists
		 itxn_field ConfigAssetManager

         txn Assets 0
         asset_params_get AssetReserve
         assert // exists
		 itxn_field ConfigAssetReserve

         txn Assets 0
         asset_params_get AssetFreeze
         assert // exists
		 itxn_field ConfigAssetFreeze

         txn Assets 0
         asset_params_get AssetClawback
         assert // exists
		 itxn_field ConfigAssetClawback


         txn ApplicationArgs 0
         byte "manager"
         ==
         bz reserve
         txn Assets 0
         itxn_field ConfigAsset
         txn ApplicationArgs 1
		 itxn_field ConfigAssetManager
         b submit
reserve:
         txn ApplicationArgs 0
         byte "reserve"
         ==
         bz freeze
         txn Assets 0
         itxn_field ConfigAsset
         txn ApplicationArgs 1
		 itxn_field ConfigAssetReserve
         b submit
freeze:
         txn ApplicationArgs 0
         byte "freeze"
         ==
         bz clawback
         txn Assets 0
         itxn_field ConfigAsset
         txn ApplicationArgs 1
		 itxn_field ConfigAssetFreeze
         b submit
clawback:
         txn ApplicationArgs 0
         byte "clawback"
         ==
         bz error
         txn Assets 0
         itxn_field ConfigAsset
         txn ApplicationArgs 1
		 itxn_field ConfigAssetClawback
         b submit
error:   err
submit:  itxn_submit
`),
	}

	fund := txntest.Txn{
		Type:     "pay",
		Sender:   addrs[0],
		Receiver: appIndex.Address(),
		Amount:   200_000, // exactly account min balance + one asset
	}

	eval := nextBlock(t, l)
	txns(t, l, eval, &app, &fund)
	endBlock(t, l, eval)

	createAsa := txntest.Txn{
		Type:            "appl",
		Sender:          addrs[1],
		ApplicationID:   appIndex,
		ApplicationArgs: [][]byte{[]byte("create")},
	}

	eval = nextBlock(t, l)
	// Can't create an asset if you have exactly 200,000 and need to pay fee
	txn(t, l, eval, &createAsa, "balance 199000 below min 200000")
	// fund it some more and try again
	txns(t, l, eval, fund.Noted("more!"), &createAsa)
	vb := endBlock(t, l, eval)

	asaIndex := vb.Block().Payset[1].EvalDelta.InnerTxns[0].ConfigAsset
	require.Equal(t, basics.AssetIndex(5), asaIndex)

	asaParams, err := asaParams(t, l, basics.AssetIndex(5))
	require.NoError(t, err)

	require.Equal(t, 1_000_000, int(asaParams.Total))
	require.Equal(t, 3, int(asaParams.Decimals))
	require.Equal(t, "oz", asaParams.UnitName)
	require.Equal(t, "Gold", asaParams.AssetName)
	require.Equal(t, "https://gold.rush/", asaParams.URL)

	require.Equal(t, appIndex.Address(), asaParams.Manager)

	for _, a := range []string{"reserve", "freeze", "clawback", "manager"} {
		check := txntest.Txn{
			Type:            "appl",
			Sender:          addrs[1],
			ApplicationID:   appIndex,
			ApplicationArgs: [][]byte{[]byte(a), []byte("junkjunkjunkjunkjunkjunkjunkjunk")},
			ForeignAssets:   []basics.AssetIndex{asaIndex},
		}
		eval = nextBlock(t, l)
		t.Log(a)
		txn(t, l, eval, &check)
		endBlock(t, l, eval)
	}
	// Not the manager anymore so this won't work
	nodice := txntest.Txn{
		Type:            "appl",
		Sender:          addrs[1],
		ApplicationID:   appIndex,
		ApplicationArgs: [][]byte{[]byte("freeze"), []byte("junkjunkjunkjunkjunkjunkjunkjunk")},
		ForeignAssets:   []basics.AssetIndex{asaIndex},
	}
	eval = nextBlock(t, l)
	txn(t, l, eval, &nodice, "this transaction should be issued by the manager")
	endBlock(t, l, eval)

}

// TestAsaDuringInit ensures an ASA can be made while initilizing an
// app.  In practice, this is impossible, because you would not be
// able to prefund the account - you don't know the app id.  But here
// we can know, so it helps exercise txncounter changes.
func TestAsaDuringInit(t *testing.T) {
	partitiontest.PartitionTest(t)

	genBalances, addrs, _ := ledgertesting.NewTestGenesis()
	l := newTestLedger(t, genBalances)
	defer l.Close()

	appIndex := basics.AppIndex(2)
	prefund := txntest.Txn{
		Type:     "pay",
		Sender:   addrs[0],
		Receiver: appIndex.Address(),
		Amount:   300000, // plenty for min balances, fees
	}

	app := txntest.Txn{
		Type:   "appl",
		Sender: addrs[0],
		ApprovalProgram: `
         itxn_begin
         int acfg
         itxn_field TypeEnum
		 int 1000000
		 itxn_field ConfigAssetTotal
		 byte "oz"
		 itxn_field ConfigAssetUnitName
		 byte "Gold"
		 itxn_field ConfigAssetName
         itxn_submit
         itxn CreatedAssetID
         int 3
         ==
         assert
         itxn CreatedApplicationID
         int 0
         ==
         assert
         itxn NumLogs
         int 0
         ==
`,
	}

	eval := nextBlock(t, l)
	txns(t, l, eval, &prefund, &app)
	vb := endBlock(t, l, eval)

	require.Equal(t, appIndex, vb.Block().Payset[1].ApplicationID)

	asaIndex := vb.Block().Payset[1].EvalDelta.InnerTxns[0].ConfigAsset
	require.Equal(t, basics.AssetIndex(3), asaIndex)
}

func TestRekey(t *testing.T) {
	partitiontest.PartitionTest(t)

	genBalances, addrs, _ := ledgertesting.NewTestGenesis()
	l := newTestLedger(t, genBalances)
	defer l.Close()

	app := txntest.Txn{
		Type:   "appl",
		Sender: addrs[0],
		ApprovalProgram: main(`
  itxn_begin
   int pay
   itxn_field TypeEnum
   int 1
   itxn_field Amount
   global CurrentApplicationAddress
   itxn_field Receiver
   int 31
   bzero
   byte 0x01
   concat
   itxn_field RekeyTo
  itxn_submit
`),
	}

	eval := nextBlock(t, l)
	txns(t, l, eval, &app)
	vb := endBlock(t, l, eval)
	appIndex := vb.Block().Payset[0].ApplicationID
	require.Equal(t, basics.AppIndex(1), appIndex)

	fund := txntest.Txn{
		Type:     "pay",
		Sender:   addrs[0],
		Receiver: appIndex.Address(),
		Amount:   1_000_000,
	}
	rekey := txntest.Txn{
		Type:          "appl",
		Sender:        addrs[1],
		ApplicationID: appIndex,
	}
	eval = nextBlock(t, l)
	txns(t, l, eval, &fund, &rekey)
	txn(t, l, eval, rekey.Noted("2"), "unauthorized")
	endBlock(t, l, eval)

}

func TestNote(t *testing.T) {
	partitiontest.PartitionTest(t)

	genBalances, addrs, _ := ledgertesting.NewTestGenesis()
	l := newTestLedger(t, genBalances)
	defer l.Close()

	app := txntest.Txn{
		Type:   "appl",
		Sender: addrs[0],
		ApprovalProgram: main(`
  itxn_begin
   int pay
   itxn_field TypeEnum
   int 0
   itxn_field Amount
   global CurrentApplicationAddress
   itxn_field Receiver
   byte "abcdefghijklmnopqrstuvwxyz01234567890"
   itxn_field Note
  itxn_submit
`),
	}

	eval := nextBlock(t, l)
	txns(t, l, eval, &app)
	vb := endBlock(t, l, eval)
	appIndex := vb.Block().Payset[0].ApplicationID
	require.Equal(t, basics.AppIndex(1), appIndex)

	fund := txntest.Txn{
		Type:     "pay",
		Sender:   addrs[0],
		Receiver: appIndex.Address(),
		Amount:   1_000_000,
	}
	note := txntest.Txn{
		Type:          "appl",
		Sender:        addrs[1],
		ApplicationID: appIndex,
	}
	eval = nextBlock(t, l)
	txns(t, l, eval, &fund, &note)
	vb = endBlock(t, l, eval)
	alphabet := vb.Block().Payset[1].EvalDelta.InnerTxns[0].Txn.Note
	require.Equal(t, "abcdefghijklmnopqrstuvwxyz01234567890", string(alphabet))
}

func TestKeyreg(t *testing.T) {
	partitiontest.PartitionTest(t)

	genBalances, addrs, _ := ledgertesting.NewTestGenesis()
	l := newTestLedger(t, genBalances)
	defer l.Close()

	app := txntest.Txn{
		Type:   "appl",
		Sender: addrs[0],
		ApprovalProgram: main(`
  txn ApplicationArgs 0
  byte "pay"
  ==
  bz nonpart
  itxn_begin
   int pay
   itxn_field TypeEnum
   int 1
   itxn_field Amount
   txn Sender
   itxn_field Receiver
  itxn_submit
  int 1
  return
nonpart:
  itxn_begin
   int keyreg
   itxn_field TypeEnum
   int 1
   itxn_field Nonparticipation
  itxn_submit
`),
	}

	// Create the app
	eval := nextBlock(t, l)
	txns(t, l, eval, &app)
	vb := endBlock(t, l, eval)
	appIndex := vb.Block().Payset[0].ApplicationID
	require.Equal(t, basics.AppIndex(1), appIndex)

	// Give the app a lot of money
	fund := txntest.Txn{
		Type:     "pay",
		Sender:   addrs[0],
		Receiver: appIndex.Address(),
		Amount:   1_000_000_000,
	}
	eval = nextBlock(t, l)
	txn(t, l, eval, &fund)
	endBlock(t, l, eval)

	require.Equal(t, 1_000_000_000, int(micros(t, l, appIndex.Address())))

	// Build up Residue in RewardsState so it's ready to pay
	for i := 1; i < 10; i++ {
		eval := nextBlock(t, l)
		endBlock(t, l, eval)
	}

	// pay a little
	pay := txntest.Txn{
		Type:            "appl",
		Sender:          addrs[0],
		ApplicationID:   appIndex,
		ApplicationArgs: [][]byte{[]byte("pay")},
	}
	eval = nextBlock(t, l)
	txn(t, l, eval, &pay)
	endBlock(t, l, eval)
	// 2000 was earned in rewards (- 1000 fee, -1 pay)
	require.Equal(t, 1_000_000_999, int(micros(t, l, appIndex.Address())))

	// Go nonpart
	nonpart := txntest.Txn{
		Type:            "appl",
		Sender:          addrs[0],
		ApplicationID:   appIndex,
		ApplicationArgs: [][]byte{[]byte("nonpart")},
	}
	eval = nextBlock(t, l)
	txn(t, l, eval, &nonpart)
	endBlock(t, l, eval)
	require.Equal(t, 999_999_999, int(micros(t, l, appIndex.Address())))

	// Build up Residue in RewardsState so it's ready to pay AGAIN
	// But expect no rewards
	for i := 1; i < 100; i++ {
		eval := nextBlock(t, l)
		endBlock(t, l, eval)
	}
	eval = nextBlock(t, l)
	txn(t, l, eval, pay.Noted("again"))
	txn(t, l, eval, nonpart.Noted("again"), "cannot change online/offline")
	endBlock(t, l, eval)
	// Paid fee + 1.  Did not get rewards
	require.Equal(t, 999_998_998, int(micros(t, l, appIndex.Address())))
}

func TestInnerAppCall(t *testing.T) {
	partitiontest.PartitionTest(t)

	genBalances, addrs, _ := ledgertesting.NewTestGenesis()
	l := newTestLedger(t, genBalances)
	defer l.Close()

	app0 := txntest.Txn{
		Type:   "appl",
		Sender: addrs[0],
		ApprovalProgram: main(`
  itxn_begin
   int pay
   itxn_field TypeEnum
   int 1
   itxn_field Amount
   txn Sender
   itxn_field Receiver
  itxn_submit
`),
	}
	eval := nextBlock(t, l)
	txn(t, l, eval, &app0)
	vb := endBlock(t, l, eval)
	index0 := vb.Block().Payset[0].ApplicationID

	app1 := txntest.Txn{
		Type:   "appl",
		Sender: addrs[1],
		ApprovalProgram: main(`
  itxn_begin
   int appl
   itxn_field TypeEnum
   txn Applications 1
   itxn_field ApplicationID
  itxn_submit
`),
	}

	eval = nextBlock(t, l)
	txns(t, l, eval, &app1)
	vb = endBlock(t, l, eval)
	index1 := vb.Block().Payset[0].ApplicationID

	fund0 := txntest.Txn{
		Type:     "pay",
		Sender:   addrs[0],
		Receiver: index0.Address(),
		Amount:   1_000_000_000,
	}
	fund1 := fund0
	fund1.Receiver = index1.Address()

	call1 := txntest.Txn{
		Type:          "appl",
		Sender:        addrs[2],
		ApplicationID: index1,
		ForeignApps:   []basics.AppIndex{index0},
	}
	eval = nextBlock(t, l)
	txns(t, l, eval, &fund0, &fund1, &call1)
	endBlock(t, l, eval)

}

// TestInnerAppManipulate ensures that apps called from inner transactions make
// the changes expected when invoked.
func TestInnerAppManipulate(t *testing.T) {
	partitiontest.PartitionTest(t)

	genBalances, addrs, _ := ledgertesting.NewTestGenesis()
	l := newTestLedger(t, genBalances)
	defer l.Close()

	calleeIndex := basics.AppIndex(1)
	callee := txntest.Txn{
		Type:   "appl",
		Sender: addrs[0],
		// This app set a global key arg[1] to arg[2] or get arg[1] and log it
		ApprovalProgram: main(`
 txn ApplicationArgs 0
 byte "set"
 ==
 bz next1
 txn ApplicationArgs 1
 txn ApplicationArgs 2
 app_global_put
 b end
next1:
 txn ApplicationArgs 0
 byte "get"
 ==
 bz next2
 txn ApplicationArgs 1
 app_global_get
 log							// Fails if key didn't exist, b/c TOS = 0
 b end
next2:
 err
`),
		GlobalStateSchema: basics.StateSchema{
			NumByteSlice: 1,
		},
	}
	fund := txntest.Txn{
		Type:     "pay",
		Sender:   addrs[0],
		Receiver: calleeIndex.Address(),
		Amount:   1_000_000,
	}
	eval := nextBlock(t, l)
	txns(t, l, eval, &callee, &fund)
	vb := endBlock(t, l, eval)
	require.Equal(t, calleeIndex, vb.Block().Payset[0].ApplicationID)

	callerIndex := basics.AppIndex(3)
	caller := txntest.Txn{
		Type:   "appl",
		Sender: addrs[0],
		ApprovalProgram: main(`
 itxn_begin
   int appl
   itxn_field TypeEnum
   txn Applications 1
   itxn_field ApplicationID
   byte "set"
   itxn_field ApplicationArgs
   byte "X"
   itxn_field ApplicationArgs
   byte "A"
   itxn_field ApplicationArgs
  itxn_submit
  itxn NumLogs
  int 0
  ==
  assert
  b end
`),
	}
	fund.Receiver = callerIndex.Address()

	eval = nextBlock(t, l)
	txns(t, l, eval, &caller, &fund)
	vb = endBlock(t, l, eval)
	require.Equal(t, callerIndex, vb.Block().Payset[0].ApplicationID)

	call := txntest.Txn{
		Type:          "appl",
		Sender:        addrs[0],
		ApplicationID: callerIndex,
		ForeignApps:   []basics.AppIndex{calleeIndex},
	}
	eval = nextBlock(t, l)
	txns(t, l, eval, &call)
	vb = endBlock(t, l, eval)
	tib := vb.Block().Payset[0]
	// No changes in the top-level EvalDelta
	require.Empty(t, tib.EvalDelta.GlobalDelta)
	require.Empty(t, tib.EvalDelta.LocalDeltas)

	inner := tib.EvalDelta.InnerTxns[0]
	require.Empty(t, inner.EvalDelta.LocalDeltas)

	require.Len(t, inner.EvalDelta.GlobalDelta, 1)
	require.Equal(t, basics.ValueDelta{
		Action: basics.SetBytesAction,
		Bytes:  "A",
	}, inner.EvalDelta.GlobalDelta["X"])
}

// TestCreateAndUse checks that an ASA can be created in an early tx, and then
// used in a later app call tx (in the same group).  This was not allowed until
// teal 6 (v31), because of the strict adherence to the foreign-arrays rules.
func TestCreateAndUse(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	genBalances, addrs, _ := ledgertesting.NewTestGenesis()
	// At 30 the asset reference is illegal, then from v31 it works.
	testConsensusRange(t, 30, 0, func(t *testing.T, ver int) {
		dl := NewDoubleLedger(t, genBalances, consensusByNumber[ver])
		defer dl.Close()

		createapp := txntest.Txn{
			Type:   "appl",
			Sender: addrs[0],
			ApprovalProgram: main(`
         itxn_begin
         int axfer; itxn_field TypeEnum
         int 0;     itxn_field Amount
         gaid 0;    itxn_field XferAsset
         global CurrentApplicationAddress;  itxn_field Sender
         global CurrentApplicationAddress;  itxn_field AssetReceiver
         itxn_submit
`),
		}
		appIndex := basics.AppIndex(1)

		fund := txntest.Txn{
			Type:     "pay",
			Sender:   addrs[0],
			Receiver: appIndex.Address(),
			Amount:   1_000_000,
		}

		createasa := txntest.Txn{
			Type:   "acfg",
			Sender: addrs[0],
			AssetParams: basics.AssetParams{
				Total:     1000000,
				Decimals:  3,
				UnitName:  "oz",
				AssetName: "Gold",
				URL:       "https://gold.rush/",
			},
		}
		asaIndex := basics.AssetIndex(3)

		use := txntest.Txn{
			Type:          "appl",
			Sender:        addrs[0],
			ApplicationID: basics.AppIndex(1),
			// The point of this test is to show the following (psychic) setting is unnecessary.
			//ForeignAssets: []basics.AssetIndex{asaIndex},
		}

		dl.beginBlock()
		dl.txn(&createapp)
		dl.txn(&fund)
		if ver == 30 {
			dl.txgroup("invalid Asset reference", &createasa, &use)
			dl.endBlock()
			return
		}
		// v31 onward, create & use works
		dl.txgroup("", &createasa, &use)
		vb := dl.endBlock()

		require.Equal(t, appIndex, vb.Block().Payset[0].ApplyData.ApplicationID)
		require.Equal(t, asaIndex, vb.Block().Payset[2].ApplyData.ConfigAsset)
	})
}

func TestGtxnEffects(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	genBalances, addrs, _ := ledgertesting.NewTestGenesis()
	// At 30 `gtxn CreatedAssetId is illegal, then from v31 it works.
	testConsensusRange(t, 30, 0, func(t *testing.T, ver int) {
		dl := NewDoubleLedger(t, genBalances, consensusByNumber[ver])
		defer dl.Close()

		createapp := txntest.Txn{
			Type:   "appl",
			Sender: addrs[0],
			ApprovalProgram: main(`
         gtxn 0 CreatedAssetID
         int 3
         ==
         assert`),
		}
		appIndex := basics.AppIndex(1)

		fund := txntest.Txn{
			Type:     "pay",
			Sender:   addrs[0],
			Receiver: appIndex.Address(),
			Amount:   1_000_000,
		}

		dl.beginBlock()
		dl.txns(&createapp, &fund)

		createasa := txntest.Txn{
			Type:   "acfg",
			Sender: addrs[0],
			AssetParams: basics.AssetParams{
				Total:     1000000,
				Decimals:  3,
				UnitName:  "oz",
				AssetName: "Gold",
				URL:       "https://gold.rush/",
			},
		}
		asaIndex := basics.AssetIndex(3)

		see := txntest.Txn{
			Type:          "appl",
			Sender:        addrs[0],
			ApplicationID: basics.AppIndex(1),
		}

		if ver == 30 {
			dl.txgroup("Unable to obtain effects from top-level transactions", &createasa, &see)
			dl.endBlock()
			return
		}
		dl.txgroup("", &createasa, &see)
		vb := dl.endBlock()

		require.Equal(t, appIndex, vb.Block().Payset[0].ApplyData.ApplicationID)
		require.Equal(t, asaIndex, vb.Block().Payset[2].ApplyData.ConfigAsset)
	})
}

func TestBasicReentry(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	genBalances, addrs, _ := ledgertesting.NewTestGenesis()
	testConsensusRange(t, 31, 0, func(t *testing.T, ver int) {
		dl := NewDoubleLedger(t, genBalances, consensusByNumber[ver])
		defer dl.Close()

		app0 := txntest.Txn{
			Type:   "appl",
			Sender: addrs[0],
			ApprovalProgram: main(`
  itxn_begin
   int appl
   itxn_field TypeEnum
   txn Applications 1
   itxn_field ApplicationID
  itxn_submit`),
		}
		vb := dl.fullBlock(&app0)
		index0 := vb.Block().Payset[0].ApplicationID

		call1 := txntest.Txn{
			Type:          "appl",
			Sender:        addrs[2],
			ApplicationID: index0,
			ForeignApps:   []basics.AppIndex{index0},
		}
		dl.txn(&call1, "self-call")
	})
}

func TestIndirectReentry(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	genBalances, addrs, _ := ledgertesting.NewTestGenesis()
	l := newTestLedger(t, genBalances)
	defer l.Close()

	app0 := txntest.Txn{
		Type:   "appl",
		Sender: addrs[0],
		ApprovalProgram: main(`
  itxn_begin
   int appl
   itxn_field TypeEnum
   txn Applications 1
   itxn_field ApplicationID
   txn Applications 2
   itxn_field Applications
  itxn_submit
`),
	}
	eval := nextBlock(t, l)
	txn(t, l, eval, &app0)
	vb := endBlock(t, l, eval)
	index0 := vb.Block().Payset[0].ApplicationID

	fund := txntest.Txn{
		Type:     "pay",
		Sender:   addrs[0],
		Receiver: index0.Address(),
		Amount:   1_000_000,
	}

	app1 := txntest.Txn{
		Type:   "appl",
		Sender: addrs[0],
		ApprovalProgram: main(`
  itxn_begin
   int appl
   itxn_field TypeEnum
   txn Applications 1
   itxn_field ApplicationID
  itxn_submit
`),
	}
	eval = nextBlock(t, l)
	txns(t, l, eval, &app1, &fund)
	vb = endBlock(t, l, eval)
	index1 := vb.Block().Payset[0].ApplicationID

	call1 := txntest.Txn{
		Type:          "appl",
		Sender:        addrs[0],
		ApplicationID: index0,
		ForeignApps:   []basics.AppIndex{index1, index0},
	}
	eval = nextBlock(t, l)
	txn(t, l, eval, &call1, "attempt to re-enter")
	endBlock(t, l, eval)
}

// TestValidAppReentry tests a valid form of reentry (which may not be the correct word here).
// When A calls B then returns to A then A calls C which calls B, the execution
// should not produce an error because B doesn't occur in the call stack twice.
func TestValidAppReentry(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	genBalances, addrs, _ := ledgertesting.NewTestGenesis()
	l := newTestLedger(t, genBalances)
	defer l.Close()

	app0 := txntest.Txn{
		Type:   "appl",
		Sender: addrs[0],
		ApprovalProgram: main(`
  itxn_begin
   int appl
   itxn_field TypeEnum
   txn Applications 2
   itxn_field ApplicationID
  itxn_submit

  itxn_begin
   int appl
   itxn_field TypeEnum
   txn Applications 1
   itxn_field ApplicationID
   txn Applications 2
   itxn_field Applications
  itxn_submit
`),
	}
	eval := nextBlock(t, l)
	txn(t, l, eval, &app0)
	vb := endBlock(t, l, eval)
	index0 := vb.Block().Payset[0].ApplicationID

	fund0 := txntest.Txn{
		Type:     "pay",
		Sender:   addrs[0],
		Receiver: index0.Address(),
		Amount:   1_000_000,
	}

	app1 := txntest.Txn{
		Type:   "appl",
		Sender: addrs[0],
		ApprovalProgram: main(`
  int 3
  int 3
  ==
  assert
`),
	}
	eval = nextBlock(t, l)
	txns(t, l, eval, &app1, &fund0)
	vb = endBlock(t, l, eval)
	index1 := vb.Block().Payset[0].ApplicationID

	app2 := txntest.Txn{
		Type:   "appl",
		Sender: addrs[0],
		ApprovalProgram: main(`
  itxn_begin
   int appl
   itxn_field TypeEnum
   txn Applications 1
   itxn_field ApplicationID
  itxn_submit
`),
	}
	eval = nextBlock(t, l)
	txn(t, l, eval, &app2)
	vb = endBlock(t, l, eval)
	index2 := vb.Block().Payset[0].ApplicationID

	fund2 := txntest.Txn{
		Type:     "pay",
		Sender:   addrs[0],
		Receiver: index2.Address(),
		Amount:   1_000_000,
	}

	eval = nextBlock(t, l)
	txn(t, l, eval, &fund2)
	_ = endBlock(t, l, eval)

	call1 := txntest.Txn{
		Type:          "appl",
		Sender:        addrs[0],
		ApplicationID: index0,
		ForeignApps:   []basics.AppIndex{index2, index1, index0},
	}
	eval = nextBlock(t, l)
	txn(t, l, eval, &call1)
	endBlock(t, l, eval)
}

func TestMaxInnerTxForSingleAppCall(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	genBalances, addrs, _ := ledgertesting.NewTestGenesis()
	// v31 = inner appl
	testConsensusRange(t, 31, 0, func(t *testing.T, ver int) {
		dl := NewDoubleLedger(t, genBalances, consensusByNumber[ver])
		defer dl.Close()

		program := `
txn ApplicationArgs 0
btoi
store 0
int 1
loop:
itxn_begin
  int appl
  itxn_field TypeEnum
  txn Applications 1
  itxn_field ApplicationID
itxn_submit
int 1
+
dup
load 0
<=
bnz loop
load 0
int 1
+
==
assert
`

		app0 := txntest.Txn{
			Type:            "appl",
			Sender:          addrs[0],
			ApprovalProgram: main(program),
		}
		vb := dl.fullBlock(&app0)
		index0 := vb.Block().Payset[0].ApplicationID

		fund0 := txntest.Txn{
			Type:     "pay",
			Sender:   addrs[0],
			Receiver: index0.Address(),
			Amount:   1_000_000,
		}

		app1 := txntest.Txn{
			Type:   "appl",
			Sender: addrs[0],
			ApprovalProgram: main(`
  int 3
  int 3
  ==
  assert
`),
		}

		vb = dl.fullBlock(&app1, &fund0)
		index1 := vb.Block().Payset[0].ApplicationID

		callTxGroup := make([]*txntest.Txn, 16)
		callTxGroup[0] = &txntest.Txn{
			Type:            "appl",
			Sender:          addrs[0],
			ApplicationID:   index0,
			ForeignApps:     []basics.AppIndex{index1},
			ApplicationArgs: [][]byte{{1, 0}}, // 256 inner calls
		}
		for i := 1; i < 16; i++ {
			callTxGroup[i] = &txntest.Txn{
				Type:          "appl",
				Sender:        addrs[0],
				ApplicationID: index1,
				Note:          []byte{byte(i)},
			}
		}
		dl.txgroup("", callTxGroup...)

		// Can't do it twice in a single group
		dl.txgroup("too many inner", callTxGroup[0], callTxGroup[0].Noted("another"))

		// Don't need all those extra top-levels to be allowed to do 256 in tx0
		callTxGroup[0].Group = crypto.Digest{}
		dl.fullBlock(callTxGroup[0])

		// Can't do 257 txns
		callTxGroup[0].ApplicationArgs[0][1] = 1
		dl.txn(callTxGroup[0], "too many inner")
	})
}

func TestAbortWhenInnerAppCallFails(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	genBalances, addrs, _ := ledgertesting.NewTestGenesis()
	l := newTestLedger(t, genBalances)
	defer l.Close()

	app0 := txntest.Txn{
		Type:   "appl",
		Sender: addrs[0],
		ApprovalProgram: main(`
itxn_begin
  int appl
  itxn_field TypeEnum
  txn Applications 1
  itxn_field ApplicationID
itxn_submit
int 1
int 1
==
assert
`),
	}
	eval := nextBlock(t, l)
	txn(t, l, eval, &app0)
	vb := endBlock(t, l, eval)
	index0 := vb.Block().Payset[0].ApplicationID

	fund0 := txntest.Txn{
		Type:     "pay",
		Sender:   addrs[0],
		Receiver: index0.Address(),
		Amount:   1_000_000,
	}

	app1 := txntest.Txn{
		Type:   "appl",
		Sender: addrs[0],
		ApprovalProgram: main(`
  int 3
  int 2
  ==
  assert
`),
	}
	eval = nextBlock(t, l)
	txns(t, l, eval, &app1, &fund0)
	vb = endBlock(t, l, eval)
	index1 := vb.Block().Payset[0].ApplicationID

	callTx := txntest.Txn{
		Type:          "appl",
		Sender:        addrs[0],
		ApplicationID: index0,
		ForeignApps:   []basics.AppIndex{index1},
	}

	eval = nextBlock(t, l)
	txn(t, l, eval, &callTx, "logic eval error")
	endBlock(t, l, eval)
}

// TestInnerAppVersionCalling ensure that inner app calls must be the >=v6 apps
func TestInnerAppVersionCalling(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	genBalances, addrs, _ := ledgertesting.NewTestGenesis()

	// 31 allowed inner appls. vFuture enables proto.AllowV4InnerAppls (presumed v33, below)
	testConsensusRange(t, 31, 0, func(t *testing.T, ver int) {
		dl := NewDoubleLedger(t, genBalances, consensusByNumber[ver])
		defer dl.Close()

		three, err := logic.AssembleStringWithVersion("int 1", 3)
		require.NoError(t, err)
		five, err := logic.AssembleStringWithVersion("int 1", 5)
		require.NoError(t, err)
		six, err := logic.AssembleStringWithVersion("int 1", 6)
		require.NoError(t, err)

		create5 := txntest.Txn{
			Type:              "appl",
			Sender:            addrs[0],
			ApprovalProgram:   five.Program,
			ClearStateProgram: five.Program,
		}

		create6 := txntest.Txn{
			Type:              "appl",
			Sender:            addrs[0],
			ApprovalProgram:   six.Program,
			ClearStateProgram: six.Program,
		}

		create5with3 := txntest.Txn{
			Type:              "appl",
			Sender:            addrs[0],
			ApprovalProgram:   five.Program,
			ClearStateProgram: three.Program,
		}

		vb := dl.fullBlock(&create5, &create6, &create5with3)
		v5id := vb.Block().Payset[0].ApplicationID
		v6id := vb.Block().Payset[1].ApplicationID
		v5withv3csp := vb.Block().Payset[2].ApplicationID

		call := txntest.Txn{
			Type:   "appl",
			Sender: addrs[0],
			// don't use main. do the test at creation time
			ApprovalProgram: `
itxn_begin
	int appl
	itxn_field TypeEnum
	txn Applications 1
	itxn_field ApplicationID
itxn_submit`,
			ForeignApps: []basics.AppIndex{v5id},
		}

		// optin is the same as call, except also sets OnCompletion to optin
		optin := txntest.Txn{
			Type:   "appl",
			Sender: addrs[0],
			// don't use main. do the test at creation time
			ApprovalProgram: `
itxn_begin
	int appl
	itxn_field TypeEnum
	txn Applications 1
	itxn_field ApplicationID
    int OptIn
    itxn_field OnCompletion
itxn_submit`,
			ForeignApps: []basics.AppIndex{v5id},
		}

		// createAndOptin tries to create and optin to args[0], args[1] programs
		createAndOptin := txntest.Txn{
			Type:   "appl",
			Sender: addrs[0],
			// don't use main. do the test at creation time
			ApprovalProgram: `
itxn_begin
	int appl
	itxn_field TypeEnum
	txn ApplicationArgs 0
    itxn_field ApprovalProgram
	txn ApplicationArgs 1
    itxn_field ClearStateProgram
    int OptIn
    itxn_field OnCompletion
itxn_submit`,
		}

		if ver <= 32 {
			dl.txn(&call, "inner app call with version v5 < v6")
			call.ForeignApps[0] = v6id
			dl.txn(&call, "overspend") // it tried to execute, but test doesn't bother funding

			// Can't create a v3 app from inside an app, because that is calling
			createAndOptin.ApplicationArgs = [][]byte{three.Program, three.Program}
			dl.txn(&createAndOptin, "inner app call with version v3 < v6")

			// nor v5 in proto ver 32
			createAndOptin.ApplicationArgs = [][]byte{five.Program, five.Program}
			dl.txn(&createAndOptin, "inner app call with version v5 < v6")

			// 6 is good
			createAndOptin.ApplicationArgs = [][]byte{six.Program, six.Program}
			dl.txn(&createAndOptin, "overspend") // passed the checks, but is an overspend
		} else {
			// after 32 proto.AllowV4InnerAppls should be in effect, so calls and optins to v5 are ok
			dl.txn(&call, "overspend")         // it tried to execute, but test doesn't bother funding
			dl.txn(&optin, "overspend")        // it tried to execute, but test doesn't bother funding
			optin.ForeignApps[0] = v5withv3csp // but we can't optin to a v5 if it has an old csp
			dl.txn(&optin, "CSP v3 < v4")      // it tried to execute, but test doesn't bother funding

			// Can't create a v3 app from inside an app, because that is calling
			createAndOptin.ApplicationArgs = [][]byte{three.Program, five.Program}
			dl.txn(&createAndOptin, "inner app call with version v3 < v4")
			// Can't create and optin to a v5/v3 app from inside an app
			createAndOptin.ApplicationArgs = [][]byte{five.Program, three.Program}
			dl.txn(&createAndOptin, "inner app call opt-in with CSP v3 < v4")

			createAndOptin.ApplicationArgs = [][]byte{five.Program, five.Program}
			dl.txn(&createAndOptin, "overspend") // passed the checks, but is an overspend
		}
	})

}

func TestAppVersionMatching(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	genBalances, addrs, _ := ledgertesting.NewTestGenesis()
	l := newTestLedger(t, genBalances)
	defer l.Close()

	four, err := logic.AssembleStringWithVersion("int 1", 4)
	require.NoError(t, err)
	five, err := logic.AssembleStringWithVersion("int 1", 5)
	require.NoError(t, err)
	six, err := logic.AssembleStringWithVersion("int 1", 6)
	require.NoError(t, err)

	create := txntest.Txn{
		Type:              "appl",
		Sender:            addrs[0],
		ApprovalProgram:   five.Program,
		ClearStateProgram: five.Program,
	}

	eval := nextBlock(t, l)
	txn(t, l, eval, &create)
	endBlock(t, l, eval)

	create.ClearStateProgram = six.Program

	eval = nextBlock(t, l)
	txn(t, l, eval, &create, "version mismatch")
	endBlock(t, l, eval)

	create.ApprovalProgram = six.Program

	eval = nextBlock(t, l)
	txn(t, l, eval, &create)
	endBlock(t, l, eval)

	create.ClearStateProgram = four.Program

	eval = nextBlock(t, l)
	txn(t, l, eval, &create, "version mismatch")
	endBlock(t, l, eval)

	// four doesn't match five, but it doesn't have to
	create.ApprovalProgram = five.Program

	eval = nextBlock(t, l)
	txn(t, l, eval, &create)
	endBlock(t, l, eval)
}

func TestAppDowngrade(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	four, err := logic.AssembleStringWithVersion("int 1", 4)
	require.NoError(t, err)
	five, err := logic.AssembleStringWithVersion("int 1", 5)
	require.NoError(t, err)
	six, err := logic.AssembleStringWithVersion("int 1", 6)
	require.NoError(t, err)

	genBalances, addrs, _ := ledgertesting.NewTestGenesis()
	testConsensusRange(t, 31, 0, func(t *testing.T, ver int) {
		dl := NewDoubleLedger(t, genBalances, consensusByNumber[ver])
		defer dl.Close()

		create := txntest.Txn{
			Type:              "appl",
			Sender:            addrs[0],
			ApprovalProgram:   four.Program,
			ClearStateProgram: four.Program,
		}

		vb := dl.fullBlock(&create)
		app := vb.Block().Payset[0].ApplicationID

		update := txntest.Txn{
			Type:              "appl",
			ApplicationID:     app,
			OnCompletion:      transactions.UpdateApplicationOC,
			Sender:            addrs[0],
			ApprovalProgram:   four.Program,
			ClearStateProgram: four.Program,
		}

		// No change - legal
		dl.fullBlock(&update)

		// Upgrade just the approval. Sure (because under 6, no need to match)
		update.ApprovalProgram = five.Program
		dl.fullBlock(&update)

		// Upgrade just the clear state. Now they match
		update.ClearStateProgram = five.Program
		dl.fullBlock(&update)

		// Downgrade (allowed for pre 6 programs until AllowV4InnerAppls)
		update.ClearStateProgram = four.Program
		if ver <= 32 {
			dl.fullBlock(update.Noted("actually a repeat of first upgrade"))
		} else {
			dl.txn(update.Noted("actually a repeat of first upgrade"), "clearstate program version downgrade")
		}

		// Try to upgrade (at 6, must match)
		update.ApprovalProgram = six.Program
		dl.txn(&update, "version mismatch")

		// Do both
		update.ClearStateProgram = six.Program
		dl.fullBlock(&update)

		// Try to downgrade. Fails because it was 6.
		update.ApprovalProgram = five.Program
		update.ClearStateProgram = five.Program
		dl.txn(update.Noted("repeat of 3rd update"), "downgrade")
	})
}

func TestCreatedAppsAreAvailable(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	genBalances, addrs, _ := ledgertesting.NewTestGenesis()
	l := newTestLedger(t, genBalances)
	defer l.Close()

	ops, err := logic.AssembleStringWithVersion("int 1\nint 1\nassert", logic.AssemblerMaxVersion)
	require.NoError(t, err)
	program := "byte 0x" + hex.EncodeToString(ops.Program)

	createapp := txntest.Txn{
		Type:   "appl",
		Sender: addrs[0],
		ApprovalProgram: main(`
		itxn_begin
		int appl;    itxn_field TypeEnum
		` + program + `; itxn_field ApprovalProgram
		` + program + `; itxn_field ClearStateProgram
		int 1;       itxn_field GlobalNumUint
		int 2;       itxn_field LocalNumByteSlice
		int 3;       itxn_field LocalNumUint
		itxn_submit`),
	}

	eval := nextBlock(t, l)
	txn(t, l, eval, &createapp)
	vb := endBlock(t, l, eval)
	index0 := vb.Block().Payset[0].ApplicationID

	fund0 := txntest.Txn{
		Type:     "pay",
		Sender:   addrs[0],
		Receiver: index0.Address(),
		Amount:   1_000_000,
	}

	eval = nextBlock(t, l)
	txn(t, l, eval, &fund0)
	endBlock(t, l, eval)

	callTx := txntest.Txn{
		Type:          "appl",
		Sender:        addrs[0],
		ApplicationID: index0,
		ForeignApps:   []basics.AppIndex{},
	}

	eval = nextBlock(t, l)
	txn(t, l, eval, &callTx)
	endBlock(t, l, eval)
	index1 := basics.AppIndex(1)

	callTx = txntest.Txn{
		Type:          "appl",
		Sender:        addrs[0],
		ApplicationID: index1,
		ForeignApps:   []basics.AppIndex{},
	}

	eval = nextBlock(t, l)
	txn(t, l, eval, &callTx)
	endBlock(t, l, eval)
}

func TestInvalidAppsNotAccessible(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	genBalances, addrs, _ := ledgertesting.NewTestGenesis()
	l := newTestLedger(t, genBalances)
	defer l.Close()

	app0 := txntest.Txn{
		Type:   "appl",
		Sender: addrs[0],
		ApprovalProgram: main(`
itxn_begin
	int appl
	itxn_field TypeEnum
	int 2
	itxn_field ApplicationID
itxn_submit`),
	}
	eval := nextBlock(t, l)
	txn(t, l, eval, &app0)
	vb := endBlock(t, l, eval)
	index0 := vb.Block().Payset[0].ApplicationID

	fund0 := txntest.Txn{
		Type:     "pay",
		Sender:   addrs[0],
		Receiver: index0.Address(),
		Amount:   1_000_000,
	}

	app1 := txntest.Txn{
		Type:   "appl",
		Sender: addrs[0],
		ApprovalProgram: main(`
int 2
int 2
==
assert
`),
	}
	eval = nextBlock(t, l)
	txns(t, l, eval, &app1, &fund0)
	endBlock(t, l, eval)

	callTx := txntest.Txn{
		Type:          "appl",
		Sender:        addrs[0],
		ApplicationID: index0,
		ForeignApps:   []basics.AppIndex{},
	}

	eval = nextBlock(t, l)
	txn(t, l, eval, &callTx, "invalid App reference 2")
	endBlock(t, l, eval)
}

func TestInvalidAssetsNotAccessible(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	genBalances, addrs, _ := ledgertesting.NewTestGenesis()
	l := newTestLedger(t, genBalances)
	defer l.Close()

	createapp := txntest.Txn{
		Type:   "appl",
		Sender: addrs[0],
		ApprovalProgram: main(`
			itxn_begin
			int axfer; itxn_field TypeEnum
			int 0;     itxn_field Amount
			int 3;    itxn_field XferAsset
			global CurrentApplicationAddress;  itxn_field Sender
			global CurrentApplicationAddress;  itxn_field AssetReceiver
			itxn_submit
`),
	}
	appIndex := basics.AppIndex(1)

	fund := txntest.Txn{
		Type:     "pay",
		Sender:   addrs[0],
		Receiver: appIndex.Address(),
		Amount:   1_000_000,
	}

	createasa := txntest.Txn{
		Type:   "acfg",
		Sender: addrs[0],
		AssetParams: basics.AssetParams{
			Total:     1000000,
			Decimals:  3,
			UnitName:  "oz",
			AssetName: "Gold",
			URL:       "https://gold.rush/",
		},
	}

	eval := nextBlock(t, l)
	txns(t, l, eval, &createapp, &fund, &createasa)
	endBlock(t, l, eval)

	use := txntest.Txn{
		Type:          "appl",
		Sender:        addrs[0],
		ApplicationID: basics.AppIndex(1),
	}

	eval = nextBlock(t, l)
	txn(t, l, eval, &use, "invalid Asset reference 3")
	endBlock(t, l, eval)
}

func executeMegaContract(b *testing.B) {
	genBalances, addrs, _ := ledgertesting.NewTestGenesis()

	vTest := config.Consensus[protocol.ConsensusFuture]
	vTest.MaxAppProgramCost = 20000
	var cv protocol.ConsensusVersion = "temp test"
	config.Consensus[cv] = vTest

	l := newTestLedgerWithConsensusVersion(b, genBalances, cv)
	defer l.Close()
	defer delete(config.Consensus, cv)

	// app must use maximum memory then recursively create a new app with the same approval program.
	// recursion is terminated when a depth of 256 is reached
	// fill scratch space
	// fill stack
	depth := 255
	createapp := txntest.Txn{
		Type:   "appl",
		Sender: addrs[0],
		ApprovalProgram: `
		int 0
		loop:
		dup
		int 4096
		bzero
		stores
		int 1
		+
		dup
		int 256
		<
		bnz loop
		pop
		int 0
		loop2:
		int 4096
		bzero
		swap
		int 1
		+
		dup
		int 994
		<=
		bnz loop2
		txna ApplicationArgs 0
		btoi
		int 1
		-
		dup
		int 0
		<=
		bnz done
		itxn_begin
		itob
		itxn_field ApplicationArgs
		int appl
		itxn_field TypeEnum
		txn ApprovalProgram
		itxn_field ApprovalProgram
		txn ClearStateProgram
		itxn_field ClearStateProgram
		itxn_submit
		done:
		int 1
		return`,
		ApplicationArgs:   [][]byte{{byte(depth)}},
		ExtraProgramPages: 3,
	}

	funds := make([]*txntest.Txn, 256)
	for i := 257; i <= 2*256; i++ {
		funds[i-257] = &txntest.Txn{
			Type:     "pay",
			Sender:   addrs[0],
			Receiver: basics.AppIndex(i).Address(),
			Amount:   1_000_000,
		}
	}

	eval := nextBlock(b, l)
	txns(b, l, eval, funds...)
	endBlock(b, l, eval)

	app1 := txntest.Txn{
		Type:            "appl",
		Sender:          addrs[0],
		ApprovalProgram: `int 1`,
	}

	eval = nextBlock(b, l)
	err := txgroup(b, l, eval, &createapp, &app1, &app1, &app1, &app1, &app1, &app1)
	require.NoError(b, err)
	endBlock(b, l, eval)
}

func BenchmarkMaximumCallStackDepth(b *testing.B) {
	for i := 0; i < b.N; i++ {
		executeMegaContract(b)
	}
}

// TestInnerClearState ensures inner ClearState performs close out properly, even if rejects.
func TestInnerClearState(t *testing.T) {
	partitiontest.PartitionTest(t)

	genBalances, addrs, _ := ledgertesting.NewTestGenesis()
	l := newTestLedger(t, genBalances)
	defer l.Close()

	// inner will be an app that we opt into, then clearstate
	// note that clearstate rejects
	inner := txntest.Txn{
		Type:              "appl",
		Sender:            addrs[0],
		ApprovalProgram:   "int 1",
		ClearStateProgram: "int 0",
		LocalStateSchema: basics.StateSchema{
			NumUint:      2,
			NumByteSlice: 2,
		},
	}

	eval := nextBlock(t, l)
	txn(t, l, eval, &inner)
	vb := endBlock(t, l, eval)
	innerId := vb.Block().Payset[0].ApplicationID

	// Outer is a simple app that will invoke the given app (in ForeignApps[0])
	// with the given OnCompletion (in ApplicationArgs[0]).  Goal is to use it
	// to opt into, and the clear state, on the inner app.
	outer := txntest.Txn{
		Type:   "appl",
		Sender: addrs[0],
		ApprovalProgram: main(`
itxn_begin
 int appl
 itxn_field TypeEnum
 txn Applications 1
 itxn_field ApplicationID
 txn ApplicationArgs 0
 btoi
 itxn_field OnCompletion
itxn_submit
`),
		ForeignApps: []basics.AppIndex{innerId},
	}

	eval = nextBlock(t, l)
	txn(t, l, eval, &outer)
	vb = endBlock(t, l, eval)
	outerId := vb.Block().Payset[0].ApplicationID

	fund := txntest.Txn{
		Type:     "pay",
		Sender:   addrs[0],
		Receiver: outerId.Address(),
		Amount:   1_000_000,
	}

	call := txntest.Txn{
		Type:            "appl",
		Sender:          addrs[0],
		ApplicationID:   outerId,
		ApplicationArgs: [][]byte{{byte(transactions.OptInOC)}},
		ForeignApps:     []basics.AppIndex{innerId},
	}
	eval = nextBlock(t, l)
	txns(t, l, eval, &fund, &call)
	endBlock(t, l, eval)

	outerAcct := lookup(t, l, outerId.Address())
	require.Len(t, outerAcct.AppLocalStates, 1)
	require.Equal(t, outerAcct.TotalAppSchema, basics.StateSchema{
		NumUint:      2,
		NumByteSlice: 2,
	})

	call.ApplicationArgs = [][]byte{{byte(transactions.ClearStateOC)}}
	eval = nextBlock(t, l)
	txn(t, l, eval, &call)
	endBlock(t, l, eval)

	outerAcct = lookup(t, l, outerId.Address())
	require.Empty(t, outerAcct.AppLocalStates)
	require.Empty(t, outerAcct.TotalAppSchema)

}

// TestInnerClearStateBadCallee ensures that inner clear state programs are not
// allowed to use more than 700 (MaxAppProgramCost)
func TestInnerClearStateBadCallee(t *testing.T) {
	partitiontest.PartitionTest(t)

	genBalances, addrs, _ := ledgertesting.NewTestGenesis()
	l := newTestLedger(t, genBalances)
	defer l.Close()

	// badCallee tries to run down your budget, so an inner clear must be
	// protected from exhaustion
	badCallee := txntest.Txn{
		Type:            "appl",
		Sender:          addrs[0],
		ApprovalProgram: "int 1",
		ClearStateProgram: `top:
int 1
pop
b top
`,
	}

	eval := nextBlock(t, l)
	txn(t, l, eval, &badCallee)
	vb := endBlock(t, l, eval)
	badId := vb.Block().Payset[0].ApplicationID

	// Outer is a simple app that will invoke the given app (in ForeignApps[0])
	// with the given OnCompletion (in ApplicationArgs[0]).  Goal is to use it
	// to opt into, and then clear state,  the bad app
	outer := txntest.Txn{
		Type:   "appl",
		Sender: addrs[0],
		ApprovalProgram: main(`
itxn_begin
 int appl
 itxn_field TypeEnum
 txn Applications 1
 itxn_field ApplicationID
 txn ApplicationArgs 0
 btoi
 itxn_field OnCompletion
 global OpcodeBudget
 store 0
itxn_submit
global OpcodeBudget
store 1

txn ApplicationArgs 0
btoi
int ClearState
!=
bnz skip						// Don't do budget checking during optin
 load 0
 load 1
 int 3							// OpcodeBudget lines were 3 instructions apart
 +								// ClearState got 700 added to budget, tried to take all,
 ==								// but ended up just using that 700
 assert
skip:
`),
		ForeignApps: []basics.AppIndex{badId},
	}

	eval = nextBlock(t, l)
	txn(t, l, eval, &outer)
	vb = endBlock(t, l, eval)
	outerId := vb.Block().Payset[0].ApplicationID

	fund := txntest.Txn{
		Type:     "pay",
		Sender:   addrs[0],
		Receiver: outerId.Address(),
		Amount:   1_000_000,
	}

	call := txntest.Txn{
		Type:            "appl",
		Sender:          addrs[0],
		ApplicationID:   outerId,
		ApplicationArgs: [][]byte{{byte(transactions.OptInOC)}},
		ForeignApps:     []basics.AppIndex{badId},
	}
	eval = nextBlock(t, l)
	txns(t, l, eval, &fund, &call)
	endBlock(t, l, eval)

	outerAcct := lookup(t, l, outerId.Address())
	require.Len(t, outerAcct.AppLocalStates, 1)

	// When doing a clear state, `call` checks that budget wasn't stolen
	call.ApplicationArgs = [][]byte{{byte(transactions.ClearStateOC)}}
	eval = nextBlock(t, l)
	txn(t, l, eval, &call)
	endBlock(t, l, eval)

	// Clearstate took effect, despite failure from infinite loop
	outerAcct = lookup(t, l, outerId.Address())
	require.Empty(t, outerAcct.AppLocalStates)
}

// TestInnerClearStateBadCaller ensures that inner clear state programs cannot
// be called with less than 700 (MaxAppProgramCost)) OpcodeBudget.
func TestInnerClearStateBadCaller(t *testing.T) {
	partitiontest.PartitionTest(t)

	genBalances, addrs, _ := ledgertesting.NewTestGenesis()
	l := newTestLedger(t, genBalances)
	defer l.Close()

	inner := txntest.Txn{
		Type:            "appl",
		Sender:          addrs[0],
		ApprovalProgram: "int 1",
		ClearStateProgram: `global OpcodeBudget
itob
log
int 1`,
		LocalStateSchema: basics.StateSchema{
			NumUint:      1,
			NumByteSlice: 2,
		},
	}

	// waster allows tries to get the budget down below 100 before returning
	waster := txntest.Txn{
		Type:   "appl",
		Sender: addrs[0],
		ApprovalProgram: main(`
global OpcodeBudget
itob
log
top:
global OpcodeBudget
int 100
<
bnz done
 byte "junk"
 sha256
 pop
 b top
done:
global OpcodeBudget
itob
log
`),
		LocalStateSchema: basics.StateSchema{
			NumUint:      3,
			NumByteSlice: 4,
		},
	}

	eval := nextBlock(t, l)
	txns(t, l, eval, &inner, &waster)
	vb := endBlock(t, l, eval)
	innerId := vb.Block().Payset[0].ApplicationID
	wasterId := vb.Block().Payset[1].ApplicationID

	// Grouper is a simple app that will invoke the given apps (in
	// ForeignApps[0,1]) as a group, with the given OnCompletion (in
	// ApplicationArgs[0]).
	grouper := txntest.Txn{
		Type:   "appl",
		Sender: addrs[0],
		ApprovalProgram: main(`
itxn_begin
 int appl
 itxn_field TypeEnum
 txn Applications 1
 itxn_field ApplicationID
 txn ApplicationArgs 0
 btoi
 itxn_field OnCompletion
itxn_next
 int appl
 itxn_field TypeEnum
 txn Applications 2
 itxn_field ApplicationID
 txn ApplicationArgs 1
 btoi
 itxn_field OnCompletion
itxn_submit
`),
	}

	eval = nextBlock(t, l)
	txn(t, l, eval, &grouper)
	vb = endBlock(t, l, eval)
	grouperId := vb.Block().Payset[0].ApplicationID

	fund := txntest.Txn{
		Type:     "pay",
		Sender:   addrs[0],
		Receiver: grouperId.Address(),
		Amount:   1_000_000,
	}

	call := txntest.Txn{
		Type:            "appl",
		Sender:          addrs[0],
		ApplicationID:   grouperId,
		ApplicationArgs: [][]byte{{byte(transactions.OptInOC)}, {byte(transactions.OptInOC)}},
		ForeignApps:     []basics.AppIndex{wasterId, innerId},
	}
	eval = nextBlock(t, l)
	txns(t, l, eval, &fund, &call)
	endBlock(t, l, eval)

	gAcct := lookup(t, l, grouperId.Address())
	require.Len(t, gAcct.AppLocalStates, 2)

	call.ApplicationArgs = [][]byte{{byte(transactions.CloseOutOC)}, {byte(transactions.ClearStateOC)}}
	eval = nextBlock(t, l)
	txn(t, l, eval, &call, "ClearState execution with low OpcodeBudget")
	vb = endBlock(t, l, eval)
	require.Len(t, vb.Block().Payset, 0)

	// Clearstate did not take effect, since the caller tried to shortchange the CSP
	gAcct = lookup(t, l, grouperId.Address())
	require.Len(t, gAcct.AppLocalStates, 2)
}

// TestClearStateInnerPay ensures that ClearState programs can run inner txns in
// v30, but not in vFuture. (Test should add v31 after it exists.)
func TestClearStateInnerPay(t *testing.T) {
	partitiontest.PartitionTest(t)

	tests := []struct {
		consensus protocol.ConsensusVersion
		approval  string
	}{
		{protocol.ConsensusFuture, "int 1"},
		{protocol.ConsensusV30, "int 1"},
		{protocol.ConsensusFuture, "int 0"},
		{protocol.ConsensusV30, "int 0"},
	}

	for i, test := range tests {
		t.Run(fmt.Sprintf("i=%d", i), func(t *testing.T) {

			genBalances, addrs, _ := ledgertesting.NewTestGenesis()
			l := newTestLedgerWithConsensusVersion(t, genBalances, test.consensus)
			defer l.Close()

			app0 := txntest.Txn{
				Type:   "appl",
				Sender: addrs[0],
				ApprovalProgram: main(`
itxn_begin
	int pay
	itxn_field TypeEnum
	int 3000
	itxn_field Amount
    txn Sender
    itxn_field Receiver
itxn_submit`),
				ClearStateProgram: `
itxn_begin
	int pay
	itxn_field TypeEnum
	int 2000
	itxn_field Amount
    txn Sender
    itxn_field Receiver
itxn_submit
` + test.approval,
			}
			eval := nextBlock(t, l)
			txn(t, l, eval, &app0)
			vb := endBlock(t, l, eval)
			index0 := vb.Block().Payset[0].ApplicationID

			fund0 := txntest.Txn{
				Type:     "pay",
				Sender:   addrs[0],
				Receiver: index0.Address(),
				Amount:   1_000_000,
			}

			optin := txntest.Txn{
				Type:          "appl",
				Sender:        addrs[1],
				ApplicationID: index0,
				OnCompletion:  transactions.OptInOC,
			}

			eval = nextBlock(t, l)
			txns(t, l, eval, &fund0, &optin)
			vb = endBlock(t, l, eval)

			// Check that addrs[1] got paid during optin, and pay txn is in block
			ad1 := micros(t, l, addrs[1])

			// paid 3000, but 1000 fee, 2000 bump
			require.Equal(t, uint64(2000), ad1-genBalances.Balances[addrs[1]].MicroAlgos.Raw)
			// InnerTxn in block ([1] position, because followed fund0)
			require.Len(t, vb.Block().Payset[1].EvalDelta.InnerTxns, 1)
			require.Equal(t, vb.Block().Payset[1].EvalDelta.InnerTxns[0].Txn.Amount.Raw, uint64(3000))

			clear := txntest.Txn{
				Type:          "appl",
				Sender:        addrs[1],
				ApplicationID: index0,
				OnCompletion:  transactions.ClearStateOC,
			}

			eval = nextBlock(t, l)
			txns(t, l, eval, &clear)
			vb = endBlock(t, l, eval)

			// Check if addrs[1] got paid during clear, and pay txn is in block
			ad1 = micros(t, l, addrs[1])

			// The pay only happens if the clear state approves (and it was legal back in V30)
			if test.approval == "int 1" && test.consensus == protocol.ConsensusV30 {
				// had 2000 bump, now paid 2k, charge 1k, left with 3k total bump
				require.Equal(t, uint64(3000), ad1-genBalances.Balances[addrs[1]].MicroAlgos.Raw)
				// InnerTxn in block
				require.Equal(t, vb.Block().Payset[0].Txn.ApplicationID, index0)
				require.Equal(t, vb.Block().Payset[0].Txn.OnCompletion, transactions.ClearStateOC)
				require.Len(t, vb.Block().Payset[0].EvalDelta.InnerTxns, 1)
				require.Equal(t, vb.Block().Payset[0].EvalDelta.InnerTxns[0].Txn.Amount.Raw, uint64(2000))
			} else {
				// Only the fee is paid because pay is "erased", so goes from 2k down to 1k
				require.Equal(t, uint64(1000), ad1-genBalances.Balances[addrs[1]].MicroAlgos.Raw)
				// no InnerTxn in block
				require.Equal(t, vb.Block().Payset[0].Txn.ApplicationID, index0)
				require.Equal(t, vb.Block().Payset[0].Txn.OnCompletion, transactions.ClearStateOC)
				require.Len(t, vb.Block().Payset[0].EvalDelta.InnerTxns, 0)
			}
		})
	}
}

// TestGlobalChangesAcrossApps ensures that state changes are seen by other app
// calls when using inners.
func TestGlobalChangesAcrossApps(t *testing.T) {
	partitiontest.PartitionTest(t)

	genBalances, addrs, _ := ledgertesting.NewTestGenesis()
	l := newTestLedger(t, genBalances)
	defer l.Close()

	appA := txntest.Txn{
		Type:   "appl",
		Sender: addrs[0],
		ApprovalProgram: main(`
            // Call B : No arguments means: set your global "X" to "ABC"
			itxn_begin
			int appl;               itxn_field TypeEnum
			txn Applications 1;     itxn_field ApplicationID
			itxn_submit

            // Call C : Checks that B's global X is ABC
			itxn_begin
			int appl;               itxn_field TypeEnum
			txn Applications 2;     itxn_field ApplicationID
            txn Applications 1;     itxn_field Applications // Pass on access to B
			itxn_submit

            // Call B again:  1 arg means it checks if X == ABC
			itxn_begin
			int appl;               itxn_field TypeEnum
			txn Applications 1;     itxn_field ApplicationID
            byte "check, please";   itxn_field ApplicationArgs
			itxn_submit

            // Check B's state for X
            txn Applications 1
            byte "X"
            app_global_get_ex
            assert
            byte "ABC"
            ==
            assert
`),
	}

	appB := txntest.Txn{
		Type:   "appl",
		Sender: addrs[0],
		ApprovalProgram: main(`
  txn NumAppArgs
  bnz check						// 1 arg means check
  // set
  byte "X"
  byte "ABC"
  app_global_put
  b end
check:
  byte "X"
  app_global_get
  byte "ABC"
  ==
  assert
  b end
`),
		GlobalStateSchema: basics.StateSchema{
			NumByteSlice: 1,
		},
	}

	appC := txntest.Txn{
		Type:   "appl",
		Sender: addrs[0],
		ApprovalProgram: main(`
  txn Applications 1
  byte "X"
  app_global_get_ex
  assert
  byte "ABC"
  ==
  assert
`),
	}

	eval := nextBlock(t, l)
	txns(t, l, eval, &appA, &appB, &appC)
	vb := endBlock(t, l, eval)
	indexA := vb.Block().Payset[0].ApplicationID
	indexB := vb.Block().Payset[1].ApplicationID
	indexC := vb.Block().Payset[2].ApplicationID

	fundA := txntest.Txn{
		Type:     "pay",
		Sender:   addrs[0],
		Receiver: indexA.Address(),
		Amount:   1_000_000,
	}

	callA := txntest.Txn{
		Type:          "appl",
		Sender:        addrs[0],
		ApplicationID: indexA,
		ForeignApps:   []basics.AppIndex{indexB, indexC},
	}

	eval = nextBlock(t, l)
	txns(t, l, eval, &fundA, &callA)
	endBlock(t, l, eval)
}

// TestLocalChangesAcrossApps ensures that state changes are seen by other app
// calls when using inners.
func TestLocalChangesAcrossApps(t *testing.T) {
	partitiontest.PartitionTest(t)

	genBalances, addrs, _ := ledgertesting.NewTestGenesis()
	l := newTestLedger(t, genBalances)
	defer l.Close()

	appA := txntest.Txn{
		Type:   "appl",
		Sender: addrs[0],
		ApprovalProgram: main(`
            // Call B : No arguments means: set caller's local "X" to "ABC"
			itxn_begin
			int appl;               itxn_field TypeEnum
			txn Applications 1;     itxn_field ApplicationID
            int OptIn;              itxn_field OnCompletion
			itxn_submit

            // Call C : Checks that caller's local X for app B is ABC
			itxn_begin
			int appl;               itxn_field TypeEnum
			txn Applications 2;     itxn_field ApplicationID
            txn Applications 1;     itxn_field Applications // Pass on access to B
			itxn_submit

            // Call B again:  1 arg means it checks if caller's local X == ABC
			itxn_begin
			int appl;               itxn_field TypeEnum
			txn Applications 1;     itxn_field ApplicationID
            byte "check, please";   itxn_field ApplicationArgs
			itxn_submit

            // Check self local state for B
            global CurrentApplicationAddress
            txn Applications 1
            byte "X"
            app_local_get_ex
            assert
            byte "ABC"
            ==
            assert
`),
	}

	appB := txntest.Txn{
		Type:   "appl",
		Sender: addrs[0],
		ApprovalProgram: main(`
  txn NumAppArgs
  bnz check						// 1 arg means check
  // set
  txn Sender
  byte "X"
  byte "ABC"
  app_local_put
  b end
check:
  txn Sender
  byte "X"
  app_local_get
  byte "ABC"
  ==
  assert
  b end
`),
		LocalStateSchema: basics.StateSchema{
			NumByteSlice: 1,
		},
	}

	appC := txntest.Txn{
		Type:   "appl",
		Sender: addrs[0],
		ApprovalProgram: main(`
  txn Sender
  txn Applications 1
  byte "X"
  app_local_get_ex
  assert
  byte "ABC"
  ==
  assert
`),
	}

	eval := nextBlock(t, l)
	txns(t, l, eval, &appA, &appB, &appC)
	vb := endBlock(t, l, eval)
	indexA := vb.Block().Payset[0].ApplicationID
	indexB := vb.Block().Payset[1].ApplicationID
	indexC := vb.Block().Payset[2].ApplicationID

	fundA := txntest.Txn{
		Type:     "pay",
		Sender:   addrs[0],
		Receiver: indexA.Address(),
		Amount:   1_000_000,
	}

	callA := txntest.Txn{
		Type:          "appl",
		Sender:        addrs[0],
		ApplicationID: indexA,
		ForeignApps:   []basics.AppIndex{indexB, indexC},
	}

	eval = nextBlock(t, l)
	txns(t, l, eval, &fundA, &callA)
	endBlock(t, l, eval)
}

func TestForeignAppAccountsAccessible(t *testing.T) {
	partitiontest.PartitionTest(t)

	genBalances, addrs, _ := ledgertesting.NewTestGenesis()
	testConsensusRange(t, 32, 0, func(t *testing.T, ver int) {
		dl := NewDoubleLedger(t, genBalances, consensusByNumber[ver])
		defer dl.Close()

		appA := txntest.Txn{
			Type:   "appl",
			Sender: addrs[0],
		}

		appB := txntest.Txn{
			Type:   "appl",
			Sender: addrs[0],
			ApprovalProgram: main(`
itxn_begin
	int pay;                itxn_field TypeEnum
	int 100;     		    itxn_field Amount
	txn Applications 1
	app_params_get AppAddress
	assert
	itxn_field Receiver
itxn_submit
`),
		}

		vb := dl.fullBlock(&appA, &appB)
		index0 := vb.Block().Payset[0].ApplicationID
		index1 := vb.Block().Payset[1].ApplicationID

		fund1 := txntest.Txn{
			Type:     "pay",
			Sender:   addrs[0],
			Receiver: index1.Address(),
			Amount:   1_000_000_000,
		}
		fund0 := fund1
		fund0.Receiver = index0.Address()

		callTx := txntest.Txn{
			Type:          "appl",
			Sender:        addrs[2],
			ApplicationID: index1,
			ForeignApps:   []basics.AppIndex{index0},
		}

		dl.beginBlock()
		if ver <= 32 {
			dl.txgroup("invalid Account reference", &fund0, &fund1, &callTx)
			dl.endBlock()
			return
		}

		dl.txgroup("", &fund0, &fund1, &callTx)
		vb = dl.endBlock()

		require.Equal(t, index0.Address(), vb.Block().Payset[2].EvalDelta.InnerTxns[0].Txn.Receiver)
		require.Equal(t, uint64(100), vb.Block().Payset[2].EvalDelta.InnerTxns[0].Txn.Amount.Raw)
	})
}

// While accounts of foreign apps are available in most contexts, they still
// cannot be used as mutable references; ie the accounts cannot be used by
// opcodes that modify local storage.
func TestForeignAppAccountsImmutable(t *testing.T) {
	partitiontest.PartitionTest(t)

	genBalances, addrs, _ := ledgertesting.NewTestGenesis()
	testConsensusRange(t, 32, 0, func(t *testing.T, ver int) {
		dl := NewDoubleLedger(t, genBalances, consensusByNumber[ver])
		defer dl.Close()

		appA := txntest.Txn{
			Type:   "appl",
			Sender: addrs[0],
		}

		appB := txntest.Txn{
			Type:   "appl",
			Sender: addrs[0],
			ApprovalProgram: main(`
txn Applications 1
app_params_get AppAddress
byte "X"
byte "ABC"
app_local_put
int 1
`),
		}

		vb := dl.fullBlock(&appA, &appB)
		index0 := vb.Block().Payset[0].ApplicationID
		index1 := vb.Block().Payset[1].ApplicationID

		fund1 := txntest.Txn{
			Type:     "pay",
			Sender:   addrs[0],
			Receiver: index1.Address(),
			Amount:   1_000_000_000,
		}
		fund0 := fund1
		fund0.Receiver = index0.Address()

		callTx := txntest.Txn{
			Type:          "appl",
			Sender:        addrs[2],
			ApplicationID: index1,
			ForeignApps:   []basics.AppIndex{index0},
		}

		dl.beginBlock()
		dl.txgroup("invalid Account reference", &fund0, &fund1, &callTx)
		dl.endBlock()
	})
}

// In the case where the foreign app account is also provided in the
// transaction's account field, mutable references should be allowed.
func TestForeignAppAccountsMutable(t *testing.T) {
	partitiontest.PartitionTest(t)

	genBalances, addrs, _ := ledgertesting.NewTestGenesis()
	testConsensusRange(t, 32, 0, func(t *testing.T, ver int) {
		dl := NewDoubleLedger(t, genBalances, consensusByNumber[ver])
		defer dl.Close()

		appA := txntest.Txn{
			Type:   "appl",
			Sender: addrs[0],
			ApprovalProgram: main(`
itxn_begin
	int appl
	itxn_field TypeEnum
	txn Applications 1
	itxn_field ApplicationID
	int OptIn
	itxn_field OnCompletion
itxn_submit
`),
		}

		appB := txntest.Txn{
			Type:   "appl",
			Sender: addrs[0],
			ApprovalProgram: main(`
txn OnCompletion
int OptIn
==
bnz done
txn Applications 1
app_params_get AppAddress
assert
byte "X"
byte "Y"
app_local_put
done:
`),
			LocalStateSchema: basics.StateSchema{
				NumByteSlice: 1,
			},
		}

		vb := dl.fullBlock(&appA, &appB)
		index0 := vb.Block().Payset[0].ApplicationID
		index1 := vb.Block().Payset[1].ApplicationID

		fund1 := txntest.Txn{
			Type:     "pay",
			Sender:   addrs[0],
			Receiver: index1.Address(),
			Amount:   1_000_000_000,
		}
		fund0 := fund1
		fund0.Receiver = index0.Address()
		fund1.Receiver = index1.Address()

		callA := txntest.Txn{
			Type:          "appl",
			Sender:        addrs[2],
			ApplicationID: index0,
			ForeignApps:   []basics.AppIndex{index1},
		}

		callB := txntest.Txn{
			Type:          "appl",
			Sender:        addrs[2],
			ApplicationID: index1,
			ForeignApps:   []basics.AppIndex{index0},
			Accounts:      []basics.Address{index0.Address()},
		}

		vb = dl.fullBlock(&fund0, &fund1, &callA, &callB)

		require.Equal(t, "Y", vb.Block().Payset[3].EvalDelta.LocalDeltas[1]["X"].Bytes)
	})
}
