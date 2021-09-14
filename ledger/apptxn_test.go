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

package ledger

import (
	"fmt"
	"testing"

	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/txntest"
	"github.com/algorand/go-algorand/test/partitiontest"
	"github.com/stretchr/testify/require"
)

// main wraps up some TEAL source in a header and footer so that it is
// an app that does nothing at create time, but otherwise runs source,
// then approves, if the source avoids panicing and leaves the stack
// empty.
func main(source string) string {
	return fmt.Sprintf(`txn ApplicationID
            bz end
            %s
       end: int 1`, source)
}

// TestPayAction ensures a pay in teal affects balances
func TestPayAction(t *testing.T) {
	partitiontest.PartitionTest(t)

	genBalances, addrs, _ := newTestGenesis()
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

	eval := l.nextBlock(t)
	eval.txns(t, &create, &fund, &payout1)
	vb := l.endBlock(t, eval)

	// AD contains expected appIndex
	require.Equal(t, ai, vb.blk.Payset[0].ApplyData.ApplicationID)

	ad0 := l.micros(t, addrs[0])
	ad1 := l.micros(t, addrs[1])
	app := l.micros(t, ai.Address())

	// create(1000) and fund(1000 + 200000)
	require.Equal(t, uint64(202000), genBalances.Balances[addrs[0]].MicroAlgos.Raw-ad0)
	// paid 5000, but 1000 fee
	require.Equal(t, uint64(4000), ad1-genBalances.Balances[addrs[1]].MicroAlgos.Raw)
	// app still has 194000 (paid out 5000, and paid fee to do it)
	require.Equal(t, uint64(194000), app)

	// Build up Residue in RewardsState so it's ready to pay
	for i := 1; i < 10; i++ {
		eval = l.nextBlock(t)
		l.endBlock(t, eval)
	}

	eval = l.nextBlock(t)
	payout2 := txntest.Txn{
		Type:          "appl",
		Sender:        addrs[1],
		ApplicationID: ai,
		Accounts:      []basics.Address{addrs[2]}, // pay other
	}
	eval.txn(t, &payout2)
	// confirm that modifiedAccounts can see account in inner txn
	found := false
	for _, addr := range eval.state.modifiedAccounts() {
		if addr == addrs[2] {
			found = true
		}
	}
	require.True(t, found)
	l.endBlock(t, eval)

	payInBlock := eval.block.Payset[0]
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

	ad1 = l.micros(t, addrs[1])
	ad2 := l.micros(t, addrs[2])
	app = l.micros(t, ai.Address())

	// paid 5000, in first payout (only), but paid 1000 fee in each payout txn
	require.Equal(t, rewards+3000, ad1-genBalances.Balances[addrs[1]].MicroAlgos.Raw)
	// app still has 188000 (paid out 10000, and paid 2k fees to do it)
	// no rewards because owns less than an algo
	require.Equal(t, uint64(200000)-10000-2000, app)

	// paid 5000 by payout2, never paid any fees, got same rewards
	require.Equal(t, rewards+uint64(5000), ad2-genBalances.Balances[addrs[2]].MicroAlgos.Raw)

	// Now fund the app account much more, so we can confirm it gets rewards.
	tenkalgos := txntest.Txn{
		Type:     "pay",
		Sender:   addrs[0],
		Receiver: ai.Address(),
		Amount:   10 * 1000 * 1000000, // account min balance, plus fees
	}
	eval = l.nextBlock(t)
	eval.txn(t, &tenkalgos)
	l.endBlock(t, eval)
	beforepay := l.micros(t, ai.Address())

	// Build up Residue in RewardsState so it's ready to pay again
	for i := 1; i < 10; i++ {
		eval = l.nextBlock(t)
		l.endBlock(t, eval)
	}
	eval = l.nextBlock(t)
	eval.txn(t, payout2.Noted("2"))
	l.endBlock(t, eval)

	afterpay := l.micros(t, ai.Address())

	payInBlock = eval.block.Payset[0]
	inners = payInBlock.ApplyData.EvalDelta.InnerTxns
	require.Len(t, inners, 1)

	appreward := inners[0].SenderRewards.Raw
	require.Greater(t, appreward, uint64(1000))

	require.Equal(t, beforepay+appreward-5000-1000, afterpay)
}

// TestAxferAction ensures axfers in teal have the intended effects
func TestAxferAction(t *testing.T) {
	partitiontest.PartitionTest(t)

	genBalances, addrs, _ := newTestGenesis()
	l := newTestLedger(t, genBalances)
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

	eval := l.nextBlock(t)
	eval.txns(t, &asa, &app)
	vb := l.endBlock(t, eval)

	asaIndex := basics.AssetIndex(1)
	require.Equal(t, asaIndex, vb.blk.Payset[0].ApplyData.ConfigAsset)
	appIndex := basics.AppIndex(2)
	require.Equal(t, appIndex, vb.blk.Payset[1].ApplyData.ApplicationID)

	fund := txntest.Txn{
		Type:     "pay",
		Sender:   addrs[0],
		Receiver: appIndex.Address(),
		Amount:   300000, // account min balance, optin min balance, plus fees
		// stay under 1M, to avoid rewards complications
	}

	eval = l.nextBlock(t)
	eval.txn(t, &fund)
	l.endBlock(t, eval)

	fundgold := txntest.Txn{
		Type:          "axfer",
		Sender:        addrs[0],
		XferAsset:     asaIndex,
		AssetReceiver: appIndex.Address(),
		AssetAmount:   20000,
	}

	// Fail, because app account is not opted in.
	eval = l.nextBlock(t)
	eval.txn(t, &fundgold, fmt.Sprintf("asset %d missing", asaIndex))
	l.endBlock(t, eval)

	amount, in := l.asa(t, appIndex.Address(), asaIndex)
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
	eval = l.nextBlock(t)
	eval.txn(t, &optin)
	l.endBlock(t, eval)

	amount, in = l.asa(t, appIndex.Address(), asaIndex)
	require.True(t, in)
	require.Equal(t, amount, uint64(0))

	// Now, suceed, because opted in.
	eval = l.nextBlock(t)
	eval.txn(t, &fundgold)
	l.endBlock(t, eval)

	amount, in = l.asa(t, appIndex.Address(), asaIndex)
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
	eval = l.nextBlock(t)
	eval.txn(t, &withdraw)
	l.endBlock(t, eval)

	amount, in = l.asa(t, appIndex.Address(), asaIndex)
	require.True(t, in)
	require.Equal(t, amount, uint64(10000))

	eval = l.nextBlock(t)
	eval.txn(t, withdraw.Noted("2"))
	l.endBlock(t, eval)

	amount, in = l.asa(t, appIndex.Address(), asaIndex)
	require.True(t, in) // Zero left, but still opted in
	require.Equal(t, amount, uint64(0))

	eval = l.nextBlock(t)
	eval.txn(t, withdraw.Noted("3"), "underflow on subtracting")
	l.endBlock(t, eval)

	amount, in = l.asa(t, appIndex.Address(), asaIndex)
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

	eval = l.nextBlock(t)
	eval.txn(t, &close)
	l.endBlock(t, eval)

	amount, in = l.asa(t, appIndex.Address(), asaIndex)
	require.False(t, in) // Zero left, not opted in
	require.Equal(t, amount, uint64(0))

	// Now, fail again, opted out
	eval = l.nextBlock(t)
	eval.txn(t, fundgold.Noted("2"), fmt.Sprintf("asset %d missing", asaIndex))
	l.endBlock(t, eval)

	// Do it all again, so we can test closeTo when we have a non-zero balance
	// Tell the app to opt itself in.
	eval = l.nextBlock(t)
	eval.txns(t, optin.Noted("a"), fundgold.Noted("a"))
	l.endBlock(t, eval)

	amount, _ = l.asa(t, appIndex.Address(), asaIndex)
	require.Equal(t, uint64(20000), amount)
	left, _ := l.asa(t, addrs[0], asaIndex)

	eval = l.nextBlock(t)
	eval.txn(t, close.Noted("a"))
	l.endBlock(t, eval)

	amount, _ = l.asa(t, appIndex.Address(), asaIndex)
	require.Equal(t, uint64(0), amount)
	back, _ := l.asa(t, addrs[0], asaIndex)
	require.Equal(t, uint64(20000), back-left)
}

// TestClawbackAction ensures an app address can act as clawback address.
func TestClawbackAction(t *testing.T) {
	partitiontest.PartitionTest(t)

	genBalances, addrs, _ := newTestGenesis()
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
	eval := l.nextBlock(t)
	eval.txns(t, &asa, &app, &optin)
	vb := l.endBlock(t, eval)

	require.Equal(t, asaIndex, vb.blk.Payset[0].ApplyData.ConfigAsset)
	require.Equal(t, appIndex, vb.blk.Payset[1].ApplyData.ApplicationID)

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
	eval = l.nextBlock(t)
	eval.txgroup(t, &overpay, &clawmove)
	l.endBlock(t, eval)

	amount, _ := l.asa(t, addrs[1], asaIndex)
	require.Equal(t, amount, uint64(1000))
}

// TestRekeyAction ensures an app can transact for a rekeyed account
func TestRekeyAction(t *testing.T) {
	partitiontest.PartitionTest(t)

	genBalances, addrs, _ := newTestGenesis()
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

	eval := l.nextBlock(t)
	eval.txns(t, &ezpayer, &rekey)
	l.endBlock(t, eval)

	useacct := txntest.Txn{
		Type:          "appl",
		Sender:        addrs[1],
		ApplicationID: appIndex,
		Accounts:      []basics.Address{addrs[0], addrs[2]}, // pay 2 from 0 (which was rekeyed)
	}
	eval = l.nextBlock(t)
	eval.txn(t, &useacct)
	l.endBlock(t, eval)

	// App was never funded (didn't spend from it's own acct)
	require.Equal(t, uint64(0), l.micros(t, basics.AppIndex(1).Address()))
	// addrs[2] got paid
	require.Equal(t, uint64(5000), l.micros(t, addrs[2])-l.micros(t, addrs[6]))
	// addrs[0] paid 5k + rekey fee + inner txn fee
	require.Equal(t, uint64(7000), l.micros(t, addrs[6])-l.micros(t, addrs[0]))

	baduse := txntest.Txn{
		Type:          "appl",
		Sender:        addrs[1],
		ApplicationID: appIndex,
		Accounts:      []basics.Address{addrs[2], addrs[0]}, // pay 0 from 2
	}
	eval = l.nextBlock(t)
	eval.txn(t, &baduse, "unauthorized")
	l.endBlock(t, eval)

	// Now, we close addrs[0], which wipes its rekey status.  Reopen
	// it, and make sure the app can't spend.

	close := txntest.Txn{
		Type:          "appl",
		Sender:        addrs[1],
		ApplicationID: appIndex,
		Accounts:      []basics.Address{addrs[0], addrs[2], addrs[3]}, // close to 3
	}
	eval = l.nextBlock(t)
	eval.txn(t, &close)
	l.endBlock(t, eval)

	require.Equal(t, uint64(0), l.micros(t, addrs[0]))

	payback := txntest.Txn{
		Type:     "pay",
		Sender:   addrs[3],
		Receiver: addrs[0],
		Amount:   10_000_000,
	}
	eval = l.nextBlock(t)
	eval.txn(t, &payback)
	l.endBlock(t, eval)

	require.Equal(t, uint64(10_000_000), l.micros(t, addrs[0]))

	eval = l.nextBlock(t)
	eval.txn(t, useacct.Noted("2"), "unauthorized")
	l.endBlock(t, eval)
}

// TestRekeyActionCloseAccount ensures closing and reopening a rekeyed account in a single app call
// properly removes the app as an authorizer for the account
func TestRekeyActionCloseAccount(t *testing.T) {
	partitiontest.PartitionTest(t)

	genBalances, addrs, _ := newTestGenesis()
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

	eval := l.nextBlock(t)
	eval.txns(t, &create, &rekey, &fund)
	l.endBlock(t, eval)

	useacct := txntest.Txn{
		Type:          "appl",
		Sender:        addrs[1],
		ApplicationID: appIndex,
		Accounts:      []basics.Address{addrs[0], addrs[2]},
	}
	eval = l.nextBlock(t)
	eval.txn(t, &useacct, "unauthorized")
	l.endBlock(t, eval)
}

// TestDuplicatePayAction shows two pays with same parameters can be done as inner tarnsactions
func TestDuplicatePayAction(t *testing.T) {
	partitiontest.PartitionTest(t)

	genBalances, addrs, _ := newTestGenesis()
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

	eval := l.nextBlock(t)
	eval.txns(t, &create, &fund, &paytwice, create.Noted("in same block"))
	vb := l.endBlock(t, eval)

	require.Equal(t, appIndex, vb.blk.Payset[0].ApplyData.ApplicationID)
	require.Equal(t, 4, len(vb.blk.Payset))
	// create=1, fund=2, payTwice=3,4,5
	require.Equal(t, basics.AppIndex(6), vb.blk.Payset[3].ApplyData.ApplicationID)

	ad0 := l.micros(t, addrs[0])
	ad1 := l.micros(t, addrs[1])
	app := l.micros(t, appIndex.Address())

	// create(1000) and fund(1000 + 200000), extra create (1000)
	require.Equal(t, 203000, int(genBalances.Balances[addrs[0]].MicroAlgos.Raw-ad0))
	// paid 10000, but 1000 fee on tx
	require.Equal(t, 9000, int(ad1-genBalances.Balances[addrs[1]].MicroAlgos.Raw))
	// app still has 188000 (paid out 10000, and paid 2 x fee to do it)
	require.Equal(t, 188000, int(app))

	// Now create another app, and see if it gets the index we expect.
	eval = l.nextBlock(t)
	eval.txns(t, create.Noted("again"))
	vb = l.endBlock(t, eval)

	// create=1, fund=2, payTwice=3,4,5, insameblock=6
	require.Equal(t, basics.AppIndex(7), vb.blk.Payset[0].ApplyData.ApplicationID)
}

// TestInnerTxCount ensures that inner transactions increment the TxnCounter
func TestInnerTxnCount(t *testing.T) {
	partitiontest.PartitionTest(t)

	genBalances, addrs, _ := newTestGenesis()
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

	eval := l.nextBlock(t)
	eval.txns(t, &create, &fund)
	vb := l.endBlock(t, eval)
	require.Equal(t, 2, int(vb.blk.TxnCounter))

	eval = l.nextBlock(t)
	eval.txns(t, &payout1)
	vb = l.endBlock(t, eval)
	require.Equal(t, 4, int(vb.blk.TxnCounter))
}

// TestAcfgAction ensures assets can be created and configured in teal
func TestAcfgAction(t *testing.T) {
	partitiontest.PartitionTest(t)

	genBalances, addrs, _ := newTestGenesis()
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
         txn ApplicationArgs 0
         byte "manager"
         ==
         bz reserve
reserve:
         txn ApplicationArgs 0
         byte "reserve"
         ==
         bz freeze
freeze:
         txn ApplicationArgs 0
         byte "freeze"
         ==
         bz clawback
clawback:
         txn ApplicationArgs 0
         byte "manager"
         ==
submit:  itxn_submit
`),
	}

	fund := txntest.Txn{
		Type:     "pay",
		Sender:   addrs[0],
		Receiver: appIndex.Address(),
		Amount:   200_000, // exactly account min balance + one asset
	}

	eval := l.nextBlock(t)
	eval.txns(t, &app, &fund)
	l.endBlock(t, eval)

	createAsa := txntest.Txn{
		Type:            "appl",
		Sender:          addrs[1],
		ApplicationID:   appIndex,
		ApplicationArgs: [][]byte{[]byte("create")},
	}

	eval = l.nextBlock(t)
	// Can't create an asset if you have exactly 200,000 and need to pay fee
	eval.txn(t, &createAsa, "balance 199000 below min 200000")
	// fund it some more and try again
	eval.txns(t, fund.Noted("more!"), &createAsa)
	vb := l.endBlock(t, eval)

	asaIndex := vb.blk.Payset[1].EvalDelta.InnerTxns[0].ConfigAsset
	require.Equal(t, basics.AssetIndex(5), asaIndex)

	asaParams, err := l.asaParams(t, basics.AssetIndex(5))
	require.NoError(t, err)

	require.Equal(t, 1_000_000, int(asaParams.Total))
	require.Equal(t, 3, int(asaParams.Decimals))
	require.Equal(t, "oz", asaParams.UnitName)
	require.Equal(t, "Gold", asaParams.AssetName)
	require.Equal(t, "https://gold.rush/", asaParams.URL)

}

// TestAsaDuringInit ensures an ASA can be made while initilizing an
// app.  In practice, this is impossible, because you would not be
// able to prefund the account - you don't know the app id.  But here
// we can know, so it helps exercise txncounter changes.
func TestAsaDuringInit(t *testing.T) {
	partitiontest.PartitionTest(t)

	genBalances, addrs, _ := newTestGenesis()
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
         itxn CreatedApplicationID
         int 0
         ==
         &&
         itxn NumLogs
         int 0
         ==
         &&
`,
	}

	eval := l.nextBlock(t)
	eval.txns(t, &prefund, &app)
	vb := l.endBlock(t, eval)

	require.Equal(t, appIndex, vb.blk.Payset[1].ApplicationID)

	asaIndex := vb.blk.Payset[1].EvalDelta.InnerTxns[0].ConfigAsset
	require.Equal(t, basics.AssetIndex(3), asaIndex)
}
