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

package internal_test

import (
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/bookkeeping"
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

	eval := nextBlock(t, l, true, nil)
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
		eval = nextBlock(t, l, true, nil)
		endBlock(t, l, eval)
	}

	eval = nextBlock(t, l, true, nil)
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
	eval = nextBlock(t, l, true, nil)
	txn(t, l, eval, &tenkalgos)
	endBlock(t, l, eval)
	beforepay := micros(t, l, ai.Address())

	// Build up Residue in RewardsState so it's ready to pay again
	for i := 1; i < 10; i++ {
		eval = nextBlock(t, l, true, nil)
		endBlock(t, l, eval)
	}
	eval = nextBlock(t, l, true, nil)
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

	eval := nextBlock(t, l, true, nil)
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

	eval = nextBlock(t, l, true, nil)
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
	eval = nextBlock(t, l, true, nil)
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
	eval = nextBlock(t, l, true, nil)
	txn(t, l, eval, &optin)
	endBlock(t, l, eval)

	amount, in = holding(t, l, appIndex.Address(), asaIndex)
	require.True(t, in)
	require.Equal(t, amount, uint64(0))

	// Now, suceed, because opted in.
	eval = nextBlock(t, l, true, nil)
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
	eval = nextBlock(t, l, true, nil)
	txn(t, l, eval, &withdraw)
	endBlock(t, l, eval)

	amount, in = holding(t, l, appIndex.Address(), asaIndex)
	require.True(t, in)
	require.Equal(t, amount, uint64(10000))

	eval = nextBlock(t, l, true, nil)
	txn(t, l, eval, withdraw.Noted("2"))
	endBlock(t, l, eval)

	amount, in = holding(t, l, appIndex.Address(), asaIndex)
	require.True(t, in) // Zero left, but still opted in
	require.Equal(t, amount, uint64(0))

	eval = nextBlock(t, l, true, nil)
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

	eval = nextBlock(t, l, true, nil)
	txn(t, l, eval, &close)
	endBlock(t, l, eval)

	amount, in = holding(t, l, appIndex.Address(), asaIndex)
	require.False(t, in) // Zero left, not opted in
	require.Equal(t, amount, uint64(0))

	// Now, fail again, opted out
	eval = nextBlock(t, l, true, nil)
	txn(t, l, eval, fundgold.Noted("2"), fmt.Sprintf("asset %d missing", asaIndex))
	endBlock(t, l, eval)

	// Do it all again, so we can test closeTo when we have a non-zero balance
	// Tell the app to opt itself in.
	eval = nextBlock(t, l, true, nil)
	txns(t, l, eval, optin.Noted("a"), fundgold.Noted("a"))
	endBlock(t, l, eval)

	amount, _ = holding(t, l, appIndex.Address(), asaIndex)
	require.Equal(t, uint64(20000), amount)
	left, _ := holding(t, l, addrs[0], asaIndex)

	eval = nextBlock(t, l, true, nil)
	txn(t, l, eval, close.Noted("a"))
	endBlock(t, l, eval)

	amount, _ = holding(t, l, appIndex.Address(), asaIndex)
	require.Equal(t, uint64(0), amount)
	back, _ := holding(t, l, addrs[0], asaIndex)
	require.Equal(t, uint64(20000), back-left)
}

func newTestLedger(t testing.TB, balances bookkeeping.GenesisBalances) *ledger.Ledger {
	var genHash crypto.Digest
	crypto.RandBytes(genHash[:])
	genBlock, err := bookkeeping.MakeGenesisBlock(protocol.ConsensusFuture, balances, "test", genHash)
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
	eval := nextBlock(t, l, true, nil)
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
	eval = nextBlock(t, l, true, nil)
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

	eval := nextBlock(t, l, true, nil)
	txns(t, l, eval, &ezpayer, &rekey)
	endBlock(t, l, eval)

	useacct := txntest.Txn{
		Type:          "appl",
		Sender:        addrs[1],
		ApplicationID: appIndex,
		Accounts:      []basics.Address{addrs[0], addrs[2]}, // pay 2 from 0 (which was rekeyed)
	}
	eval = nextBlock(t, l, true, nil)
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
	eval = nextBlock(t, l, true, nil)
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
	eval = nextBlock(t, l, true, nil)
	txn(t, l, eval, &close)
	endBlock(t, l, eval)

	require.Equal(t, uint64(0), micros(t, l, addrs[0]))

	payback := txntest.Txn{
		Type:     "pay",
		Sender:   addrs[3],
		Receiver: addrs[0],
		Amount:   10_000_000,
	}
	eval = nextBlock(t, l, true, nil)
	txn(t, l, eval, &payback)
	endBlock(t, l, eval)

	require.Equal(t, uint64(10_000_000), micros(t, l, addrs[0]))

	eval = nextBlock(t, l, true, nil)
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

	eval := nextBlock(t, l, true, nil)
	txns(t, l, eval, &create, &rekey, &fund)
	endBlock(t, l, eval)

	useacct := txntest.Txn{
		Type:          "appl",
		Sender:        addrs[1],
		ApplicationID: appIndex,
		Accounts:      []basics.Address{addrs[0], addrs[2]},
	}
	eval = nextBlock(t, l, true, nil)
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

	eval := nextBlock(t, l, true, nil)
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
	eval = nextBlock(t, l, true, nil)
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

	eval := nextBlock(t, l, true, nil)
	txns(t, l, eval, &create, &fund)
	vb := endBlock(t, l, eval)
	require.Equal(t, 2, int(vb.Block().TxnCounter))

	eval = nextBlock(t, l, true, nil)
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

	eval := nextBlock(t, l, true, nil)
	txns(t, l, eval, &app, &fund)
	endBlock(t, l, eval)

	createAsa := txntest.Txn{
		Type:            "appl",
		Sender:          addrs[1],
		ApplicationID:   appIndex,
		ApplicationArgs: [][]byte{[]byte("create")},
	}

	eval = nextBlock(t, l, true, nil)
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
		eval = nextBlock(t, l, true, nil)
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
	eval = nextBlock(t, l, true, nil)
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

	eval := nextBlock(t, l, true, nil)
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

	eval := nextBlock(t, l, true, nil)
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
	eval = nextBlock(t, l, true, nil)
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

	eval := nextBlock(t, l, true, nil)
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
	eval = nextBlock(t, l, true, nil)
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
	eval := nextBlock(t, l, true, nil)
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
	eval = nextBlock(t, l, true, nil)
	txn(t, l, eval, &fund)
	endBlock(t, l, eval)

	require.Equal(t, 1_000_000_000, int(micros(t, l, appIndex.Address())))

	// Build up Residue in RewardsState so it's ready to pay
	for i := 1; i < 10; i++ {
		eval := nextBlock(t, l, true, nil)
		endBlock(t, l, eval)
	}

	// pay a little
	pay := txntest.Txn{
		Type:            "appl",
		Sender:          addrs[0],
		ApplicationID:   appIndex,
		ApplicationArgs: [][]byte{[]byte("pay")},
	}
	eval = nextBlock(t, l, true, nil)
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
	eval = nextBlock(t, l, true, nil)
	txn(t, l, eval, &nonpart)
	endBlock(t, l, eval)
	require.Equal(t, 999_999_999, int(micros(t, l, appIndex.Address())))

	// Build up Residue in RewardsState so it's ready to pay AGAIN
	// But expect no rewards
	for i := 1; i < 100; i++ {
		eval := nextBlock(t, l, true, nil)
		endBlock(t, l, eval)
	}
	eval = nextBlock(t, l, true, nil)
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
	eval := nextBlock(t, l, true, nil)
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

	eval = nextBlock(t, l, true, nil)
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
	eval = nextBlock(t, l, true, nil)
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
	eval := nextBlock(t, l, true, nil)
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

	eval = nextBlock(t, l, true, nil)
	txns(t, l, eval, &caller, &fund)
	vb = endBlock(t, l, eval)
	require.Equal(t, callerIndex, vb.Block().Payset[0].ApplicationID)

	call := txntest.Txn{
		Type:          "appl",
		Sender:        addrs[0],
		ApplicationID: callerIndex,
		ForeignApps:   []basics.AppIndex{calleeIndex},
	}
	eval = nextBlock(t, l, true, nil)
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
// v6, because of the strict adherence to the foreign-arrays rules.
func TestCreateAndUse(t *testing.T) {
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

	eval := nextBlock(t, l, true, nil)
	txn(t, l, eval, &createapp)
	txn(t, l, eval, &fund)
	err := txgroup(t, l, eval, &createasa, &use)
	require.NoError(t, err)
	vb := endBlock(t, l, eval)

	require.Equal(t, appIndex, vb.Block().Payset[0].ApplyData.ApplicationID)
	require.Equal(t, asaIndex, vb.Block().Payset[2].ApplyData.ConfigAsset)
}

func TestGtxnEffects(t *testing.T) {
	genBalances, addrs, _ := ledgertesting.NewTestGenesis()
	l := newTestLedger(t, genBalances)
	defer l.Close()

	createapp := txntest.Txn{
		Type:   "appl",
		Sender: addrs[0],
		ApprovalProgram: main(`
         gtxn 0 CreatedAssetID
         int 3
         ==
         assert
`),
	}
	appIndex := basics.AppIndex(1)

	fund := txntest.Txn{
		Type:     "pay",
		Sender:   addrs[0],
		Receiver: appIndex.Address(),
		Amount:   1_000_000,
	}

	eval := nextBlock(t, l, true, nil)
	txns(t, l, eval, &createapp, &fund)

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

	err := txgroup(t, l, eval, &createasa, &see)
	require.NoError(t, err)
	vb := endBlock(t, l, eval)

	require.Equal(t, appIndex, vb.Block().Payset[0].ApplyData.ApplicationID)
	require.Equal(t, asaIndex, vb.Block().Payset[2].ApplyData.ConfigAsset)
}
