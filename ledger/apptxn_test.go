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

package ledger

import (
	"encoding/hex"
	"fmt"
	"strconv"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/crypto/merklesignature"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/transactions"
	"github.com/algorand/go-algorand/data/transactions/logic"
	"github.com/algorand/go-algorand/data/txntest"
	ledgertesting "github.com/algorand/go-algorand/ledger/testing"
	"github.com/algorand/go-algorand/protocol"
	"github.com/algorand/go-algorand/test/partitiontest"
)

// TestPayAction ensures a inner pay transaction affects balances
func TestPayAction(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	genBalances, addrs, _ := ledgertesting.NewTestGenesis()
	// Inner txns start in v30
	ledgertesting.TestConsensusRange(t, 30, 0, func(t *testing.T, ver int, cv protocol.ConsensusVersion, cfg config.Local) {
		dl := NewDoubleLedger(t, genBalances, cv, cfg)
		defer dl.Close()

		ai := dl.fundedApp(addrs[0], 200000, // account min balance, plus fees
			main(`
         itxn_begin
         int pay
         itxn_field TypeEnum
         int 5000
         itxn_field Amount
         txn Accounts 1
         itxn_field Receiver
         itxn_submit
        `))

		// We're going to test some payout effects here too, so that we have an inner transaction example.
		proposer := basics.Address{0x01, 0x02, 0x03}
		dl.txns(&txntest.Txn{
			Type:     "pay",
			Sender:   addrs[7],
			Receiver: proposer,
			Amount:   1_000_000 * 1_000_000, // 1 million algos is surely an eligible amount
		}, &txntest.Txn{
			Type:         "keyreg",
			Sender:       proposer,
			Fee:          3_000_000,
			VotePK:       crypto.OneTimeSignatureVerifier{0x01},
			SelectionPK:  crypto.VRFVerifier{0x02},
			StateProofPK: merklesignature.Commitment{0x03},
			VoteFirst:    1, VoteLast: 1000,
		})

		payout1 := txntest.Txn{
			Type:          "appl",
			Sender:        addrs[1],
			ApplicationID: ai,
			Accounts:      []basics.Address{addrs[1]}, // pay self
		}

		presink := micros(dl.t, dl.generator, genBalances.FeeSink)
		preprop := micros(dl.t, dl.generator, proposer)
		dl.t.Log("presink", presink, "preprop", preprop)
		dl.beginBlock()
		dl.txns(&payout1)
		vb := dl.endBlock(proposer)
		const payoutsVer = 40
		if ver >= payoutsVer {
			require.True(t, dl.generator.GenesisProto().Payouts.Enabled)
			require.EqualValues(t, 2000, vb.Block().FeesCollected.Raw)
		} else {
			require.False(t, dl.generator.GenesisProto().Payouts.Enabled)
			require.Zero(t, vb.Block().FeesCollected)
		}

		postsink := micros(dl.t, dl.generator, genBalances.FeeSink)
		postprop := micros(dl.t, dl.generator, proposer)

		dl.t.Log("postsink", postsink, "postprop", postprop)
		if ver >= payoutsVer {
			bonus := 10_000_000                                 // config/consensus.go
			assert.EqualValues(t, bonus-1000, presink-postsink) // based on 50% in config/consensus.go
			require.EqualValues(t, bonus+1000, postprop-preprop)
		} else {
			require.EqualValues(t, 2000, postsink-presink) // no payouts yet
		}

		ad0 := micros(dl.t, dl.generator, addrs[0])
		ad1 := micros(dl.t, dl.generator, addrs[1])
		app := micros(dl.t, dl.generator, ai.Address())

		genAccounts := genBalances.Balances
		// create(1000) and fund(1000 + 200000)
		require.Equal(t, uint64(202000), genAccounts[addrs[0]].MicroAlgos.Raw-ad0)
		// paid 5000, but 1000 fee
		require.Equal(t, uint64(4000), ad1-genAccounts[addrs[1]].MicroAlgos.Raw)
		// app still has 194000 (paid out 5000, and paid fee to do it)
		require.Equal(t, uint64(194000), app)

		// Build up Residue in RewardsState so it's ready to pay
		for i := 1; i < 10; i++ {
			dl.fullBlock()
		}

		payout2 := txntest.Txn{
			Type:          "appl",
			Sender:        addrs[1],
			ApplicationID: ai,
			Accounts:      []basics.Address{addrs[2]}, // pay other
		}
		vb = dl.fullBlock(&payout2)
		// confirm that modifiedAccounts can see account in inner txn

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

		ad1 = micros(dl.t, dl.validator, addrs[1])
		ad2 := micros(dl.t, dl.validator, addrs[2])
		app = micros(dl.t, dl.validator, ai.Address())

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
		dl.fullBlock(&tenkalgos)
		beforepay := micros(dl.t, dl.validator, ai.Address())

		// Build up Residue in RewardsState so it's ready to pay again
		for i := 1; i < 10; i++ {
			dl.fullBlock()
		}
		tib := dl.txn(payout2.Noted("2"))

		afterpay := micros(dl.t, dl.validator, ai.Address())

		inners = tib.ApplyData.EvalDelta.InnerTxns
		require.Len(t, inners, 1)

		appreward := inners[0].SenderRewards.Raw
		require.Greater(t, appreward, uint64(1000))

		require.Equal(t, beforepay+appreward-5000-1000, afterpay)
	})
}

// TestAxferAction ensures axfers in teal have the intended effects
func TestAxferAction(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	genBalances, addrs, _ := ledgertesting.NewTestGenesis()
	// Inner txns start in v30
	ledgertesting.TestConsensusRange(t, 30, 0, func(t *testing.T, ver int, cv protocol.ConsensusVersion, cfg config.Local) {
		dl := NewDoubleLedger(t, genBalances, cv, cfg)
		defer dl.Close()

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

		source := main(`
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
`)

		asaID := dl.txn(&asa).ApplyData.ConfigAsset
		// account min balance, optin min balance, plus fees
		// stay under 1M, to avoid rewards complications
		appID := dl.fundedApp(addrs[0], 300_000, source)

		fundgold := txntest.Txn{
			Type:          "axfer",
			Sender:        addrs[0],
			XferAsset:     asaID,
			AssetReceiver: appID.Address(),
			AssetAmount:   20000,
		}

		// Fail, because app account is not opted in.
		dl.txn(&fundgold, fmt.Sprintf("asset %d missing", asaID))

		amount, in := holding(t, dl.generator, appID.Address(), asaID)
		require.False(t, in)
		require.Zero(t, amount)

		// Tell the app to opt itself in.
		optin := txntest.Txn{
			Type:            "appl",
			ApplicationID:   appID,
			Sender:          addrs[0],
			ApplicationArgs: [][]byte{[]byte("optin")},
			ForeignAssets:   []basics.AssetIndex{asaID},
		}
		dl.txn(&optin)

		amount, in = holding(t, dl.generator, appID.Address(), asaID)
		require.True(t, in)
		require.Zero(t, amount)

		// Now, succeed, because opted in.
		dl.txn(&fundgold)

		amount, in = holding(t, dl.generator, appID.Address(), asaID)
		require.True(t, in)
		require.Equal(t, uint64(20000), amount)

		withdraw := txntest.Txn{
			Type:            "appl",
			ApplicationID:   appID,
			Sender:          addrs[0],
			ApplicationArgs: [][]byte{[]byte("withdraw")},
			ForeignAssets:   []basics.AssetIndex{asaID},
			Accounts:        []basics.Address{addrs[0]},
		}
		dl.txn(&withdraw)

		amount, in = holding(t, dl.generator, appID.Address(), asaID)
		require.True(t, in)
		require.Equal(t, uint64(10000), amount)

		dl.txn(withdraw.Noted("2"))

		amount, in = holding(t, dl.generator, appID.Address(), asaID)
		require.True(t, in) // Zero left, but still opted in
		require.Zero(t, amount)

		dl.txn(withdraw.Noted("3"), "underflow on subtracting")

		amount, in = holding(t, dl.generator, appID.Address(), asaID)
		require.True(t, in) // Zero left, but still opted in
		require.Zero(t, amount)

		close := txntest.Txn{
			Type:            "appl",
			ApplicationID:   appID,
			Sender:          addrs[0],
			ApplicationArgs: [][]byte{[]byte("close")},
			ForeignAssets:   []basics.AssetIndex{asaID},
			Accounts:        []basics.Address{addrs[0]},
		}

		dl.txn(&close)

		amount, in = holding(t, dl.generator, appID.Address(), asaID)
		require.False(t, in) // Zero left, not opted in
		require.Zero(t, amount)

		// Now, fail again, opted out
		dl.txn(fundgold.Noted("2"), fmt.Sprintf("asset %d missing", asaID))

		// Do it all again, so we can test closeTo when we have a non-zero balance
		// Tell the app to opt itself in.
		dl.txns(optin.Noted("a"), fundgold.Noted("a"))

		amount, _ = holding(t, dl.generator, appID.Address(), asaID)
		require.Equal(t, uint64(20000), amount)
		left, _ := holding(t, dl.generator, addrs[0], asaID)

		dl.txn(close.Noted("a"))

		amount, _ = holding(t, dl.generator, appID.Address(), asaID)
		require.Zero(t, amount)
		back, _ := holding(t, dl.generator, addrs[0], asaID)
		require.Equal(t, uint64(20000), back-left)
	})
}

// TestClawbackAction ensures an app address can act as clawback address.
func TestClawbackAction(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	genBalances, addrs, _ := ledgertesting.NewTestGenesis()

	// 31 allowed inner appl.
	ledgertesting.TestConsensusRange(t, 31, 0, func(t *testing.T, ver int, cv protocol.ConsensusVersion, cfg config.Local) {
		dl := NewDoubleLedger(t, genBalances, cv, cfg)
		defer dl.Close()

		app := txntest.Txn{
			Type:   "appl",
			Sender: addrs[0],
			ApprovalProgram: main(`
         itxn_begin
          int axfer;       itxn_field TypeEnum
          txn Assets 0;    itxn_field XferAsset
          txn Accounts 1;  itxn_field AssetSender
          txn Accounts 2;  itxn_field AssetReceiver
          int 1000;        itxn_field AssetAmount
         itxn_submit
`),
		}
		appID := dl.txn(&app).ApplyData.ApplicationID

		asa := txntest.Txn{
			Type:   "acfg",
			Sender: addrs[0],
			AssetParams: basics.AssetParams{
				Total:    1005,
				Clawback: appID.Address(),
			},
		}
		asaID := dl.txn(&asa).ApplyData.ConfigAsset

		optin := txntest.Txn{
			Type:          "axfer",
			Sender:        addrs[1],
			AssetReceiver: addrs[1],
			XferAsset:     asaID,
		}
		dl.txn(&optin)

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
			ApplicationID: appID,
			ForeignAssets: []basics.AssetIndex{asaID},
			Accounts:      []basics.Address{addrs[0], addrs[1]},
		}
		dl.txgroup("", &overpay, &clawmove)

		amount, _ := holding(t, dl.generator, addrs[1], asaID)
		require.EqualValues(t, 1000, amount)
		amount, _ = holding(t, dl.generator, addrs[0], asaID)
		require.EqualValues(t, 5, amount)
	})
}

// TestRekeyAction ensures an app can transact for a rekeyed account
func TestRekeyAction(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	genBalances, addrs, _ := ledgertesting.NewTestGenesis()

	// 30 allowed inner txns.
	ledgertesting.TestConsensusRange(t, 30, 0, func(t *testing.T, ver int, cv protocol.ConsensusVersion, cfg config.Local) {
		dl := NewDoubleLedger(t, genBalances, cv, cfg)
		defer dl.Close()

		ezpayer := txntest.Txn{
			Type:   "appl",
			Sender: addrs[5],
			ApprovalProgram: main(`
         itxn_begin
          int pay;         itxn_field TypeEnum
          int 5000;        itxn_field Amount
          txn Accounts 1;  itxn_field Sender
          txn Accounts 2;  itxn_field Receiver
          txn NumAccounts
          int 3
          ==
          bz skipclose
          txn Accounts 3;  itxn_field CloseRemainderTo
skipclose:
         itxn_submit
`),
		}
		appID := dl.txn(&ezpayer).ApplyData.ApplicationID

		rekey := txntest.Txn{
			Type:     "pay",
			Sender:   addrs[0],
			Receiver: addrs[0],
			RekeyTo:  appID.Address(),
		}

		dl.txn(&rekey)

		useacct := txntest.Txn{
			Type:          "appl",
			Sender:        addrs[1],
			ApplicationID: appID,
			Accounts:      []basics.Address{addrs[0], addrs[2]}, // pay 2 from 0 (which was rekeyed)
		}
		dl.txn(&useacct)

		// App was never funded (didn't spend from it's own acct)
		require.Zero(t, micros(t, dl.generator, appID.Address()))
		// addrs[2] got paid
		require.Equal(t, uint64(5000), micros(t, dl.generator, addrs[2])-micros(t, dl.generator, addrs[6]))
		// addrs[0] paid 5k + rekey fee + inner txn fee
		require.Equal(t, uint64(7000), micros(t, dl.generator, addrs[6])-micros(t, dl.generator, addrs[0]))

		baduse := txntest.Txn{
			Type:          "appl",
			Sender:        addrs[1],
			ApplicationID: appID,
			Accounts:      []basics.Address{addrs[2], addrs[0]}, // pay 0 from 2
		}
		dl.txn(&baduse, "unauthorized")

		// Now, we close addrs[0], which wipes its rekey status.  Reopen
		// it, and make sure the app can't spend.

		close := txntest.Txn{
			Type:          "appl",
			Sender:        addrs[1],
			ApplicationID: appID,
			Accounts:      []basics.Address{addrs[0], addrs[2], addrs[3]}, // close to 3
		}
		dl.txn(&close)

		require.Zero(t, micros(t, dl.generator, addrs[0]))

		payback := txntest.Txn{
			Type:     "pay",
			Sender:   addrs[3],
			Receiver: addrs[0],
			Amount:   10_000_000,
		}
		dl.txn(&payback)

		require.Equal(t, uint64(10_000_000), micros(t, dl.generator, addrs[0]))

		dl.txn(useacct.Noted("2"), "unauthorized")
	})
}

// TestRekeyActionCloseAccount ensures closing and reopening a rekeyed account in a single app call
// properly removes the app as an authorizer for the account
func TestRekeyActionCloseAccount(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	genBalances, addrs, _ := ledgertesting.NewTestGenesis()

	// 30 allowed inner txs.
	ledgertesting.TestConsensusRange(t, 30, 0, func(t *testing.T, ver int, cv protocol.ConsensusVersion, cfg config.Local) {
		dl := NewDoubleLedger(t, genBalances, cv, cfg)
		defer dl.Close()

		// use addrs[5] for creation, so addr[0] will be closeable
		appID := dl.fundedApp(addrs[5], 1_000_000,
			main(`
         // pay from, and close, account 1
         itxn_begin
          int pay;         itxn_field TypeEnum
          txn Accounts 1;  itxn_field Sender
          txn Accounts 2;  itxn_field CloseRemainderTo
         itxn_submit

         // reopen account 1
         itxn_begin
          int pay;         itxn_field TypeEnum
          int 5000;        itxn_field Amount
          txn Accounts 1;  itxn_field Receiver
         itxn_submit

         // send from account 1 again (should fail because closing an account erases rekeying)
         itxn_begin
          int pay;         itxn_field TypeEnum
          int 1;           itxn_field Amount
          txn Accounts 1;  itxn_field Sender
          txn Accounts 2;  itxn_field Receiver
         itxn_submit
`))

		// rekey addr[1] to the app
		dl.txn(&txntest.Txn{
			Type:     "pay",
			Sender:   addrs[0],
			Receiver: addrs[0],
			RekeyTo:  appID.Address(),
		})

		useacct := txntest.Txn{
			Type:          "appl",
			Sender:        addrs[1],
			ApplicationID: appID,
			Accounts:      []basics.Address{addrs[0], addrs[2]},
		}
		dl.txn(&useacct, "unauthorized")
		// do it again, to ensure the lack of authorization is in the right
		// place, by matching on the opcode that comes before the itxn_submit we
		// want to know failed (it'll be in the error).
		dl.txn(&useacct, "itxn_field Receiver")
	})
}

// TestDuplicatePayAction shows two pays with same parameters can be done as inner tarnsactions
func TestDuplicatePayAction(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	genBalances, addrs, _ := ledgertesting.NewTestGenesis()
	// Inner txns start in v30
	ledgertesting.TestConsensusRange(t, 30, 0, func(t *testing.T, ver int, cv protocol.ConsensusVersion, cfg config.Local) {
		dl := NewDoubleLedger(t, genBalances, cv, cfg)
		defer dl.Close()

		source := main(`
         itxn_begin
          int pay;         itxn_field TypeEnum
          int 5000;        itxn_field Amount
          txn Accounts 1;  itxn_field Receiver
         itxn_submit
         itxn_begin
          int pay;         itxn_field TypeEnum
          int 5000;        itxn_field Amount
          txn Accounts 1;  itxn_field Receiver
         itxn_submit
`)
		appID := dl.fundedApp(addrs[0], 200_000, source)

		paytwice := txntest.Txn{
			Type:          "appl",
			Sender:        addrs[1],
			ApplicationID: appID,
			Accounts:      []basics.Address{addrs[1]}, // pay self
		}

		dl.txn(&paytwice)
		copyID := dl.fundedApp(addrs[0], 200_000, source)
		require.Equal(t, appID+5, copyID) // 4 between (fund, outer, two innner pays)

		ad0 := micros(t, dl.generator, addrs[0])
		ad1 := micros(t, dl.generator, addrs[1])
		app := micros(t, dl.generator, appID.Address())

		// create(1000) and fund(1000 + 200000), extra create+fund (1000 + 201000)
		require.Equal(t, 404000, int(genBalances.Balances[addrs[0]].MicroAlgos.Raw-ad0))
		// paid 10000, but 1000 fee on tx
		require.Equal(t, 9000, int(ad1-genBalances.Balances[addrs[1]].MicroAlgos.Raw))
		// app still has 188000 (paid out 10000, and paid 2 x fee to do it)
		require.Equal(t, 188000, int(app))

		// Now create another app, and see if it gets the ID we expect (2
		// higher, because of the intervening fund txn)
		finalID := dl.fundedApp(addrs[0], 200_000, source)
		require.Equal(t, copyID+2, finalID)
	})
}

// TestInnerTxCount ensures that inner transactions increment the TxnCounter
func TestInnerTxnCount(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	genBalances, addrs, _ := ledgertesting.NewTestGenesis()

	// 30 allowed inner txs.
	ledgertesting.TestConsensusRange(t, 30, 0, func(t *testing.T, ver int, cv protocol.ConsensusVersion, cfg config.Local) {
		dl := NewDoubleLedger(t, genBalances, cv, cfg)
		defer dl.Close()

		appID := dl.fundedApp(addrs[0], 200000, // account min balance, plus fees
			main(`
         itxn_begin
         int pay
         itxn_field TypeEnum
         int 5000
         itxn_field Amount
         txn Accounts 1
         itxn_field Receiver
         itxn_submit
`))

		payout1 := txntest.Txn{
			Type:          "appl",
			Sender:        addrs[1],
			ApplicationID: appID,
			Accounts:      []basics.Address{addrs[1]}, // pay self
		}

		vb := dl.fullBlock(&payout1)
		before := vb.Block().TxnCounter
		vb = dl.fullBlock(payout1.Noted("again"))
		require.Equal(t, before+2, vb.Block().TxnCounter)
	})
}

// TestAcfgAction ensures assets can be created and configured in teal
func TestAcfgAction(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	genBalances, addrs, _ := ledgertesting.NewTestGenesis()

	// 30 allowed inner txs.
	ledgertesting.TestConsensusRange(t, 30, 0, func(t *testing.T, ver int, cv protocol.ConsensusVersion, cfg config.Local) {
		dl := NewDoubleLedger(t, genBalances, cv, cfg)
		defer dl.Close()

		appID := dl.fundedApp(addrs[0], 200_000, // exactly account min balance + one asset
			main(`
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
`))

		createAsa := txntest.Txn{
			Type:            "appl",
			Sender:          addrs[1],
			ApplicationID:   appID,
			ApplicationArgs: [][]byte{[]byte("create")},
		}

		// Can't create an asset if you have exactly 200,000 and need to pay fee
		dl.txn(&createAsa, "balance 199000 below min 200000")
		// add some more
		dl.txn(&txntest.Txn{
			Type:     "pay",
			Sender:   addrs[0],
			Receiver: appID.Address(),
			Amount:   10_000,
		})
		asaID := dl.txn(&createAsa).EvalDelta.InnerTxns[0].ConfigAsset
		require.NotZero(t, asaID)

		asaParams, err := asaParams(t, dl.generator, asaID)
		require.NoError(t, err)

		require.Equal(t, 1_000_000, int(asaParams.Total))
		require.Equal(t, 3, int(asaParams.Decimals))
		require.Equal(t, "oz", asaParams.UnitName)
		require.Equal(t, "Gold", asaParams.AssetName)
		require.Equal(t, "https://gold.rush/", asaParams.URL)

		require.Equal(t, appID.Address(), asaParams.Manager)

		for _, a := range []string{"reserve", "freeze", "clawback", "manager"} {
			check := txntest.Txn{
				Type:            "appl",
				Sender:          addrs[1],
				ApplicationID:   appID,
				ApplicationArgs: [][]byte{[]byte(a), []byte("junkjunkjunkjunkjunkjunkjunkjunk")},
				ForeignAssets:   []basics.AssetIndex{asaID},
			}
			t.Log(a)
			dl.txn(&check)
		}
		// Not the manager anymore so this won't work
		nodice := txntest.Txn{
			Type:            "appl",
			Sender:          addrs[1],
			ApplicationID:   appID,
			ApplicationArgs: [][]byte{[]byte("freeze"), []byte("junkjunkjunkjunkjunkjunkjunkjunk")},
			ForeignAssets:   []basics.AssetIndex{asaID},
		}
		dl.txn(&nodice, "this transaction should be issued by the manager")
	})
}

// TestAsaDuringInit ensures an ASA can be made while initilizing an
// app.  In practice, this is impossible, because you would not be
// able to prefund the account - you don't know the app id.  But here
// we can know, so it helps exercise txncounter changes.
func TestAsaDuringInit(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	genBalances, addrs, _ := ledgertesting.NewTestGenesis()

	// 30 allowed inner txs.
	ledgertesting.TestConsensusRange(t, 30, 0, func(t *testing.T, ver int, cv protocol.ConsensusVersion, cfg config.Local) {
		dl := NewDoubleLedger(t, genBalances, cv, cfg)
		defer dl.Close()

		appID := basics.AppIndex(2)
		if ver >= 38 { // AppForbidLowResources
			appID += 1000
		}
		prefund := txntest.Txn{
			Type:     "pay",
			Sender:   addrs[0],
			Receiver: appID.Address(),
			Amount:   300000, // plenty for min balances, fees
		}

		app := txntest.Txn{
			Type:   "appl",
			Sender: addrs[0],
			ApprovalProgram: `
         itxn_begin
         int acfg;      itxn_field TypeEnum
		  int 1000000;  itxn_field ConfigAssetTotal
		  byte "oz";	itxn_field ConfigAssetUnitName
		  byte "Gold";  itxn_field ConfigAssetName
         itxn_submit
         itxn CreatedAssetID
         int ` + strconv.Itoa(int(appID+1)) + `
         ==
         assert
         itxn CreatedApplicationID; int 0; ==; assert
         itxn NumLogs; int 0; ==`,
		}

		payset := dl.txns(&prefund, &app)
		require.Equal(t, appID, payset[1].ApplicationID)

		asaID := payset[1].EvalDelta.InnerTxns[0].ConfigAsset
		require.EqualValues(t, appID+1, asaID)
	})
}

func TestInnerRekey(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	genBalances, addrs, _ := ledgertesting.NewTestGenesis()

	// 31 allowed inner rekeys.
	ledgertesting.TestConsensusRange(t, 31, 0, func(t *testing.T, ver int, cv protocol.ConsensusVersion, cfg config.Local) {
		dl := NewDoubleLedger(t, genBalances, cv, cfg)
		defer dl.Close()

		appID := dl.fundedApp(addrs[0], 1_000_000,
			main(`
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
`))
		require.NotZero(t, appID)

		rekey := txntest.Txn{
			Type:          "appl",
			Sender:        addrs[1],
			ApplicationID: appID,
		}
		dl.fullBlock(&rekey)
		dl.txn(rekey.Noted("2"), "unauthorized")
	})
}

// TestInnerAppCreateAndOptin tests a weird way to create an app and opt it into
// an ASA all from one top-level transaction. Part of the trick is to use an
// inner helper app.  The app being created rekeys itself to the inner app,
// which funds the outer app and opts it into the ASA. It could have worked
// differently - the inner app could have just funded the outer app, and then
// the outer app could have opted-in.  But this technique tests something
// interesting, that the inner app can perform an opt-in on the outer app, which
// tests that the newly created app's holdings are available. In practice, the
// helper should rekey it back, but we don't bother here.
func TestInnerAppCreateAndOptin(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	genBalances, addrs, _ := ledgertesting.NewTestGenesis()

	// v31 allows inner appl and inner rekey
	ledgertesting.TestConsensusRange(t, 31, 0, func(t *testing.T, ver int, cv protocol.ConsensusVersion, cfg config.Local) {
		dl := NewDoubleLedger(t, genBalances, cv, cfg)
		defer dl.Close()

		createasa := txntest.Txn{
			Type:        "acfg",
			Sender:      addrs[0],
			AssetParams: basics.AssetParams{Total: 2, UnitName: "$"},
		}
		asaID := dl.txn(&createasa).ApplyData.ConfigAsset
		require.NotZero(t, asaID)

		// helper app, is called during the creation of an app.  When such an
		// app is created, it rekeys itself to this helper and calls it. The
		// helpers opts the caller into an ASA, and funds the MBR the caller
		// needs for that optin.
		helper := dl.fundedApp(addrs[0], 1_000_000,
			main(`
  itxn_begin
   int axfer; itxn_field TypeEnum
   int `+strconv.Itoa(int(asaID))+`; itxn_field XferAsset
   txn Sender; itxn_field Sender // call as the caller! (works because of rekey by caller)
   txn Sender; itxn_field AssetReceiver // 0 to self == opt-in
  itxn_next
   int pay;	   itxn_field TypeEnum // pay 200kmAlgo to the caller, for MBR
   int 200000; itxn_field Amount
   txn Sender; itxn_field Receiver
  itxn_submit
`))
		// Don't use `main` here, we want to do the work during creation. Rekey
		// to the helper and invoke it, trusting it to opt us into the ASA.
		createapp := txntest.Txn{
			Type:   "appl",
			Sender: addrs[0],
			Fee:    3 * 1000, // to pay for self, call to helper, and helper's axfer
			ApprovalProgram: `
  itxn_begin
   int appl;      itxn_field TypeEnum
   addr ` + helper.Address().String() + `; itxn_field RekeyTo
   int ` + strconv.Itoa(int(helper)) + `; itxn_field ApplicationID
   txn Assets 0; itxn_field Assets
  itxn_submit
  int 1
`,
			ForeignApps:   []basics.AppIndex{helper},
			ForeignAssets: []basics.AssetIndex{asaID},
		}
		appID := dl.txn(&createapp).ApplyData.ApplicationID
		require.NotZero(t, appID)
	})
}

// TestParentGlobals tests that a newly created app can call an inner app, and
// the inner app will have access to the parent globals, even if the originally
// created app ID isn't passed down, because the rule is that "pending" created
// apps are available. We added this rule in v38, but because it is more
// lenient, not more restrictive, we removed the consensus gated code. So it now
// works from v31 on.
func TestParentGlobals(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	genBalances, addrs, _ := ledgertesting.NewTestGenesis()

	ledgertesting.TestConsensusRange(t, 31, 0, func(t *testing.T, ver int, cv protocol.ConsensusVersion, cfg config.Local) {
		dl := NewDoubleLedger(t, genBalances, cv, cfg)
		defer dl.Close()

		// checkParent is called during the creation of an app.  It tries to
		// access its parent's globals, by using `global CallerApplicationID`
		checkParent := dl.fundedApp(addrs[0], 1_000_000,
			main(`
  global CallerApplicationID
  byte "X"
  app_global_get_ex; pop; pop;	// we only care that it didn't panic
`))

		// Don't use `main` here, we want to do the work during creation.
		createProgram := `
  itxn_begin
   int appl;      itxn_field TypeEnum
   int ` + strconv.Itoa(int(checkParent)) + `; itxn_field ApplicationID
  itxn_submit
  int 1
`
		createapp := txntest.Txn{
			Type:            "appl",
			Sender:          addrs[0],
			Fee:             2 * 1000, // to pay for self and call to helper
			ApprovalProgram: createProgram,
			ForeignApps:     []basics.AppIndex{checkParent},
		}
		var creator basics.AppIndex
		creator = dl.txn(&createapp).ApplyData.ApplicationID
		require.NotZero(t, creator)

		// Now, test the same pattern, but do it all inside of yet another outer
		// app, to show that the parent is available even if it was, itself
		// created as an inner.  To do so, we also need to get 0.2 MBR to the
		// outer app, since it will be creating the "middle" app.

		outerAppAddress := (creator + 3).Address() // creator called an inner, so next is creator+2, then fund
		outer := txntest.Txn{
			Type:   "appl",
			Sender: addrs[0],
			Fee:    3 * 1000, // to pay for self, call to inner create, and its call to helper
			ApprovalProgram: `
  itxn_begin
   int appl;      itxn_field TypeEnum
   txna Applications 1; itxn_field Applications; // We are checking some versions from before resource sharing
   byte 0x` + hex.EncodeToString(createapp.SignedTxn().Txn.ApprovalProgram) + `; itxn_field ApprovalProgram
   byte 0x` + hex.EncodeToString(createapp.SignedTxn().Txn.ClearStateProgram) + `; itxn_field ClearStateProgram
  itxn_submit
  int 1
`,
			ForeignApps: []basics.AppIndex{checkParent, creator},
		}
		fund := txntest.Txn{
			Type:     "pay",
			Amount:   200_000,
			Sender:   addrs[0],
			Receiver: outerAppAddress,
		}
		dl.txgroup("", &fund, &outer)
	})
}

func TestNote(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	genBalances, addrs, _ := ledgertesting.NewTestGenesis()

	// 31 allowed inner note setting.
	ledgertesting.TestConsensusRange(t, 31, 0, func(t *testing.T, ver int, cv protocol.ConsensusVersion, cfg config.Local) {
		dl := NewDoubleLedger(t, genBalances, cv, cfg)
		defer dl.Close()

		appID := dl.fundedApp(addrs[0], 1_000_000,
			main(`
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
`))

		note := txntest.Txn{
			Type:          "appl",
			Sender:        addrs[1],
			ApplicationID: appID,
		}

		alphabet := dl.txn(&note).EvalDelta.InnerTxns[0].Txn.Note
		require.Equal(t, "abcdefghijklmnopqrstuvwxyz01234567890", string(alphabet))
	})
}

func TestKeyreg(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	genBalances, addrs, _ := ledgertesting.NewTestGenesis()

	// 31 allowed inner keyreg
	ledgertesting.TestConsensusRange(t, 31, 0, func(t *testing.T, ver int, cv protocol.ConsensusVersion, cfg config.Local) {
		dl := NewDoubleLedger(t, genBalances, cv, cfg)
		defer dl.Close()

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
		vb := dl.fullBlock(&app)
		appID := vb.Block().Payset[0].ApplicationID
		require.NotZero(t, appID)

		// Give the app a lot of money
		fund := txntest.Txn{
			Type:     "pay",
			Sender:   addrs[0],
			Receiver: appID.Address(),
			Amount:   1_000_000_000,
		}
		dl.fullBlock(&fund)

		require.Equal(t, 1_000_000_000, int(micros(t, dl.generator, appID.Address())))

		// Build up Residue in RewardsState so it's ready to pay
		for i := 1; i < 10; i++ {
			dl.fullBlock()
		}

		// pay a little
		pay := txntest.Txn{
			Type:            "appl",
			Sender:          addrs[0],
			ApplicationID:   appID,
			ApplicationArgs: [][]byte{[]byte("pay")},
		}
		dl.fullBlock(&pay)
		// 2000 was earned in rewards (- 1000 fee, -1 pay)
		require.Equal(t, 1_000_000_999, int(micros(t, dl.generator, appID.Address())))

		// Go nonpart
		nonpart := txntest.Txn{
			Type:            "appl",
			Sender:          addrs[0],
			ApplicationID:   appID,
			ApplicationArgs: [][]byte{[]byte("nonpart")},
		}
		dl.fullBlock(&nonpart)
		require.Equal(t, 999_999_999, int(micros(t, dl.generator, appID.Address())))

		// Build up Residue in RewardsState so it's ready to pay AGAIN
		// But expect no rewards
		for i := 1; i < 100; i++ {
			dl.fullBlock()
		}
		dl.txn(pay.Noted("again"))
		dl.txn(nonpart.Noted("again"), "cannot change online/offline")
		require.Equal(t, 999_998_998, int(micros(t, dl.generator, appID.Address())))
	})
}

func TestInnerAppCall(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	genBalances, addrs, _ := ledgertesting.NewTestGenesis()

	// 31 allowed inner appl.
	ledgertesting.TestConsensusRange(t, 31, 0, func(t *testing.T, ver int, cv protocol.ConsensusVersion, cfg config.Local) {
		dl := NewDoubleLedger(t, genBalances, cv, cfg)
		defer dl.Close()

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
		vb := dl.fullBlock(&app0)
		id0 := vb.Block().Payset[0].ApplicationID

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

		vb = dl.fullBlock(&app1)
		id1 := vb.Block().Payset[0].ApplicationID

		fund0 := txntest.Txn{
			Type:     "pay",
			Sender:   addrs[0],
			Receiver: id0.Address(),
			Amount:   1_000_000_000,
		}
		fund1 := fund0
		fund1.Receiver = id1.Address()

		call1 := txntest.Txn{
			Type:          "appl",
			Sender:        addrs[2],
			ApplicationID: id1,
			ForeignApps:   []basics.AppIndex{id0},
		}
		dl.fullBlock(&fund0, &fund1, &call1)
	})
}

// TestInnerAppManipulate ensures that apps called from inner transactions make
// the changes expected when invoked.
func TestInnerAppManipulate(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	genBalances, addrs, _ := ledgertesting.NewTestGenesis()

	// 31 allowed inner appl.
	ledgertesting.TestConsensusRange(t, 31, 0, func(t *testing.T, ver int, cv protocol.ConsensusVersion, cfg config.Local) {
		dl := NewDoubleLedger(t, genBalances, cv, cfg)
		defer dl.Close()

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

		calleeIndex := dl.txn(&callee).ApplyData.ApplicationID
		require.NotZero(t, calleeIndex)

		fund := txntest.Txn{
			Type:     "pay",
			Sender:   addrs[0],
			Receiver: calleeIndex.Address(),
			Amount:   1_000_000,
		}
		dl.fullBlock(&fund)

		callerIndex := dl.fundedApp(addrs[0], 1_000_000, main(`
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
`))

		call := txntest.Txn{
			Type:          "appl",
			Sender:        addrs[0],
			ApplicationID: callerIndex,
			ForeignApps:   []basics.AppIndex{calleeIndex},
		}
		tib := dl.txn(&call)
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
	})
}

// TestCreateAndUse checks that an ASA can be created in an early tx, and then
// used in a later app call tx (in the same group).  This was not allowed until
// teal 6 (v31), because of the strict adherence to the foreign-arrays rules.
func TestCreateAndUse(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	genBalances, addrs, _ := ledgertesting.NewTestGenesis()
	// At 30 the asset reference is illegal, then from v31 it works.
	ledgertesting.TestConsensusRange(t, 30, 0, func(t *testing.T, ver int, cv protocol.ConsensusVersion, cfg config.Local) {
		dl := NewDoubleLedger(t, genBalances, cv, cfg)
		defer dl.Close()

		appID := dl.fundedApp(addrs[0], 1_000_000, main(`
         itxn_begin
          int axfer; itxn_field TypeEnum
          int 0;     itxn_field Amount
          gaid 0;    itxn_field XferAsset
          global CurrentApplicationAddress;  itxn_field Sender
          global CurrentApplicationAddress;  itxn_field AssetReceiver
         itxn_submit
`))

		createasa := txntest.Txn{
			Type:   "acfg",
			Sender: addrs[0],
			AssetParams: basics.AssetParams{
				Total: 1000000,
			},
		}
		asaID := basics.AssetIndex(appID + 2) // accounts for intervening fund txn

		use := txntest.Txn{
			Type:          "appl",
			Sender:        addrs[0],
			ApplicationID: appID,
			// The point of this test is to show the following (psychic) setting is unnecessary.
			//ForeignAssets: []basics.AssetIndex{asaID},
		}

		if ver == 30 {
			dl.txgroup("unavailable Asset", &createasa, &use)
			return
		}
		// v31 onward, create & use works
		payset := dl.txgroup("", &createasa, &use)
		require.Equal(t, asaID, payset[0].ApplyData.ConfigAsset)
	})
}

func TestGtxnEffects(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	genBalances, addrs, _ := ledgertesting.NewTestGenesis()
	// At 30 `gtxn CreatedAssetID` is illegal, then from v31 it works.
	ledgertesting.TestConsensusRange(t, 30, 0, func(t *testing.T, ver int, cv protocol.ConsensusVersion, cfg config.Local) {
		dl := NewDoubleLedger(t, genBalances, cv, cfg)
		defer dl.Close()

		// needed in very first app, so hardcode
		asaID := basics.AssetIndex(3)
		if ver >= 38 {
			asaID += 1000
		}
		appID := dl.fundedApp(addrs[0], 1_000_000, main(`
         gtxn 0 CreatedAssetID
         int `+strconv.Itoa(int(asaID))+`
         ==
         assert`))

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
		see := txntest.Txn{
			Type:          "appl",
			Sender:        addrs[0],
			ApplicationID: appID,
		}

		if ver == 30 {
			dl.txgroup("Unable to obtain effects from top-level transactions", &createasa, &see)
			return
		}
		payset := dl.txgroup("", &createasa, &see)
		require.Equal(t, asaID, payset[0].ApplyData.ConfigAsset)
	})
}

func TestBasicReentry(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	genBalances, addrs, _ := ledgertesting.NewTestGenesis()
	ledgertesting.TestConsensusRange(t, 31, 0, func(t *testing.T, ver int, cv protocol.ConsensusVersion, cfg config.Local) {
		dl := NewDoubleLedger(t, genBalances, cv, cfg)
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
		id0 := dl.txn(&app0).ApplyData.ApplicationID

		call1 := txntest.Txn{
			Type:          "appl",
			Sender:        addrs[2],
			ApplicationID: id0,
			ForeignApps:   []basics.AppIndex{id0},
		}
		dl.txn(&call1, "self-call")
	})
}

func TestIndirectReentry(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	genBalances, addrs, _ := ledgertesting.NewTestGenesis()

	// 31 allowed inner appl.
	ledgertesting.TestConsensusRange(t, 31, 0, func(t *testing.T, ver int, cv protocol.ConsensusVersion, cfg config.Local) {
		dl := NewDoubleLedger(t, genBalances, cv, cfg)
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
   txn Applications 2
   itxn_field Applications
  itxn_submit
`),
		}
		vb := dl.fullBlock(&app0)
		id0 := vb.Block().Payset[0].ApplicationID

		fund := txntest.Txn{
			Type:     "pay",
			Sender:   addrs[0],
			Receiver: id0.Address(),
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
		vb = dl.fullBlock(&app1, &fund)
		id1 := vb.Block().Payset[0].ApplicationID

		call1 := txntest.Txn{
			Type:          "appl",
			Sender:        addrs[0],
			ApplicationID: id0,
			ForeignApps:   []basics.AppIndex{id1, id0},
		}
		dl.txn(&call1, "attempt to re-enter")
	})
}

// TestValidAppReentry tests a valid form of reentry (which may not be the correct word here).
// When A calls B then returns to A then A calls C which calls B, the execution
// should not produce an error because B doesn't occur in the call stack twice.
func TestValidAppReentry(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	genBalances, addrs, _ := ledgertesting.NewTestGenesis()

	// 31 allowed inner appl.
	ledgertesting.TestConsensusRange(t, 31, 0, func(t *testing.T, ver int, cv protocol.ConsensusVersion, cfg config.Local) {
		dl := NewDoubleLedger(t, genBalances, cv, cfg)
		defer dl.Close()

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
		vb := dl.fullBlock(&app0)
		id0 := vb.Block().Payset[0].ApplicationID

		fund0 := txntest.Txn{
			Type:     "pay",
			Sender:   addrs[0],
			Receiver: id0.Address(),
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
		id1 := vb.Block().Payset[0].ApplicationID

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
		vb = dl.fullBlock(&app2)
		id2 := vb.Block().Payset[0].ApplicationID

		fund2 := txntest.Txn{
			Type:     "pay",
			Sender:   addrs[0],
			Receiver: id2.Address(),
			Amount:   1_000_000,
		}

		dl.txn(&fund2)

		call1 := txntest.Txn{
			Type:          "appl",
			Sender:        addrs[0],
			ApplicationID: id0,
			ForeignApps:   []basics.AppIndex{id2, id1, id0},
		}
		dl.txn(&call1)
	})
}

func TestMaxInnerTxForSingleAppCall(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	genBalances, addrs, _ := ledgertesting.NewTestGenesis()
	// v31 = inner appl
	ledgertesting.TestConsensusRange(t, 31, 0, func(t *testing.T, ver int, cv protocol.ConsensusVersion, cfg config.Local) {
		dl := NewDoubleLedger(t, genBalances, cv, cfg)
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
		id0 := dl.txn(&app0).ApplyData.ApplicationID

		fund0 := txntest.Txn{
			Type:     "pay",
			Sender:   addrs[0],
			Receiver: id0.Address(),
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

		payset := dl.txns(&app1, &fund0)
		id1 := payset[0].ApplicationID

		callTxGroup := make([]*txntest.Txn, 16)
		callTxGroup[0] = &txntest.Txn{
			Type:            "appl",
			Sender:          addrs[0],
			ApplicationID:   id0,
			ForeignApps:     []basics.AppIndex{id1},
			ApplicationArgs: [][]byte{{1, 0}}, // 256 inner calls
		}
		for i := 1; i < 16; i++ {
			callTxGroup[i] = &txntest.Txn{
				Type:          "appl",
				Sender:        addrs[0],
				ApplicationID: id1,
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

func TestAbortWhenInnerAppCallErrs(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	genBalances, addrs, _ := ledgertesting.NewTestGenesis()
	// 31 allowed inner appl.
	ledgertesting.TestConsensusRange(t, 31, 0, func(t *testing.T, ver int, cv protocol.ConsensusVersion, cfg config.Local) {
		dl := NewDoubleLedger(t, genBalances, cv, cfg)
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
itxn_submit
int 1
int 1
==
assert
`),
		}
		vb := dl.fullBlock(&app0)
		id0 := vb.Block().Payset[0].ApplicationID

		fund0 := txntest.Txn{
			Type:     "pay",
			Sender:   addrs[0],
			Receiver: id0.Address(),
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
		vb = dl.fullBlock(&app1, &fund0)
		id1 := vb.Block().Payset[0].ApplicationID

		callTx := txntest.Txn{
			Type:          "appl",
			Sender:        addrs[0],
			ApplicationID: id0,
			ForeignApps:   []basics.AppIndex{id1},
		}

		dl.txn(&callTx, "logic eval error")
	})
}

// TestSelfCheckHoldingNewApp checks whether a newly created app can check its
// own holdings.  There can't really be any value in it from before this group,
// since it could not have opted in. But it should be legal to look.
func TestSelfCheckHoldingNewApp(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	genBalances, addrs, _ := ledgertesting.NewTestGenesis()

	// 31 allowed inner appls.
	ledgertesting.TestConsensusRange(t, 31, 0, func(t *testing.T, ver int, cv protocol.ConsensusVersion, cfg config.Local) {
		dl := NewDoubleLedger(t, genBalances, cv, cfg)
		defer dl.Close()

		asset := txntest.Txn{
			Type:        "acfg",
			Sender:      addrs[0],
			ConfigAsset: 0,
			AssetParams: basics.AssetParams{
				Total:     10,
				Decimals:  1,
				UnitName:  "X",
				AssetName: "TEN",
			},
		}
		assetID := dl.txn(&asset).ApplyData.ConfigAsset

		selfcheck := txntest.Txn{
			Type:   "appl",
			Sender: addrs[0],
			ApprovalProgram: `
 global CurrentApplicationAddress
 txn Assets 0
 asset_holding_get AssetBalance
 !; assert				// is not opted in, so exists=0
 !						// value is also 0
`,
			ForeignAssets: []basics.AssetIndex{assetID},
		}
		selfcheck.ApplicationID = dl.txn(&selfcheck).ApplicationID

		dl.txn(&selfcheck)

	})
}

// TestCheckHoldingNewApp checks whether a newly created app (account) can have
// its holding value checked in a later txn.  There can't really be any value in
// it from before this group, since it could not have opted in. But it should be
// legal to look.
func TestCheckHoldingNewApp(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	genBalances, addrs, _ := ledgertesting.NewTestGenesis()

	// 31 allowed inner appls.
	ledgertesting.TestConsensusRange(t, 31, 0, func(t *testing.T, ver int, cv protocol.ConsensusVersion, cfg config.Local) {
		dl := NewDoubleLedger(t, genBalances, cv, cfg)
		defer dl.Close()

		asset := txntest.Txn{
			Type:        "acfg",
			Sender:      addrs[0],
			ConfigAsset: 0,
			AssetParams: basics.AssetParams{
				Total:     10,
				Decimals:  1,
				UnitName:  "X",
				AssetName: "TEN",
			},
		}
		assetID := dl.txn(&asset).ApplyData.ConfigAsset

		check := txntest.Txn{
			Type:   "appl",
			Sender: addrs[0],
			ApprovalProgram: main(`
 gaid 0
 app_params_get AppAddress
 assert
 txn Assets 0
 asset_holding_get AssetBalance
 !; assert						// is not opted in, so exists=0
 !; assert						// value is also 0
`),
			ForeignAssets: []basics.AssetIndex{assetID},
		}
		check.ApplicationID = dl.txn(&check).ApplyData.ApplicationID

		create := txntest.Txn{
			Type:          "appl",
			Sender:        addrs[1],
			ApplicationID: 0,
		}
		dl.txgroup("", &create, &check)
	})
}

// TestInnerAppVersionCalling ensure that inner app calls must be the >=v6 apps
func TestInnerAppVersionCalling(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	genBalances, addrs, _ := ledgertesting.NewTestGenesis()

	// 31 allowed inner appls. v34 lowered proto.MinInnerApplVersion
	ledgertesting.TestConsensusRange(t, 31, 0, func(t *testing.T, ver int, cv protocol.ConsensusVersion, cfg config.Local) {
		dl := NewDoubleLedger(t, genBalances, cv, cfg)
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

		payset := dl.txns(&create5, &create6, &create5with3)
		v5id := payset[0].ApplicationID
		v6id := payset[1].ApplicationID
		v5withv3csp := payset[2].ApplicationID

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

		if ver <= 33 {
			dl.txn(&call, "inner app call with version v5 < v6")
			call.ForeignApps[0] = v6id
			dl.txn(&call, "overspend") // it tried to execute, but test doesn't bother funding

			// Can't create a v3 app from inside an app, because that is calling
			createAndOptin.ApplicationArgs = [][]byte{three.Program, three.Program}
			dl.txn(&createAndOptin, "inner app call with version v3 < v6")

			// nor v5 in proto ver 33
			createAndOptin.ApplicationArgs = [][]byte{five.Program, five.Program}
			dl.txn(&createAndOptin, "inner app call with version v5 < v6")

			// 6 is good
			createAndOptin.ApplicationArgs = [][]byte{six.Program, six.Program}
			dl.txn(&createAndOptin, "overspend") // passed the checks, but is an overspend
		} else {
			// after 33 proto.MinInnerApplVersion is lowered to 4, so calls and optins to v5 are ok
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

	// matching required in v6 which is v31
	ledgertesting.TestConsensusRange(t, 31, 0, func(t *testing.T, ver int, cv protocol.ConsensusVersion, cfg config.Local) {
		dl := NewDoubleLedger(t, genBalances, cv, cfg)
		defer dl.Close()

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
		dl.txn(&create)

		create.ClearStateProgram = six.Program
		dl.txn(&create, "version mismatch")

		create.ApprovalProgram = six.Program
		dl.txn(&create)

		create.ClearStateProgram = four.Program
		dl.txn(&create, "version mismatch")

		// four doesn't match five, but it doesn't have to
		create.ApprovalProgram = five.Program
		dl.txn(&create)
	})
}

func TestAppDowngrade(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	two, err := logic.AssembleStringWithVersion("int 1", 2)
	require.NoError(t, err)
	three, err := logic.AssembleStringWithVersion("int 1", 3)
	require.NoError(t, err)
	four, err := logic.AssembleStringWithVersion("int 1", 4)
	require.NoError(t, err)
	five, err := logic.AssembleStringWithVersion("int 1", 5)
	require.NoError(t, err)
	six, err := logic.AssembleStringWithVersion("int 1", 6)
	require.NoError(t, err)

	genBalances, addrs, _ := ledgertesting.NewTestGenesis()

	// Confirm that in old protocol version, downgrade is legal
	// Start at 28 because we want to v4 app to downgrade to v3
	ledgertesting.TestConsensusRange(t, 28, 30, func(t *testing.T, ver int, cv protocol.ConsensusVersion, cfg config.Local) {
		dl := NewDoubleLedger(t, genBalances, cv, cfg)
		defer dl.Close()

		create := txntest.Txn{
			Type:              "appl",
			Sender:            addrs[0],
			ApprovalProgram:   four.Program,
			ClearStateProgram: four.Program,
		}

		app := dl.txn(&create).ApplicationID

		update := txntest.Txn{
			Type:              "appl",
			ApplicationID:     app,
			OnCompletion:      transactions.UpdateApplicationOC,
			Sender:            addrs[0],
			ApprovalProgram:   three.Program,
			ClearStateProgram: three.Program,
		}

		// No change - legal
		dl.fullBlock(&update)

		update.ApprovalProgram = two.Program
		// Also legal, and let's check mismatched version while we're at it.
		dl.fullBlock(&update)
	})

	ledgertesting.TestConsensusRange(t, 31, 0, func(t *testing.T, ver int, cv protocol.ConsensusVersion, cfg config.Local) {
		dl := NewDoubleLedger(t, genBalances, cv, cfg)
		defer dl.Close()

		create := txntest.Txn{
			Type:              "appl",
			Sender:            addrs[0],
			ApprovalProgram:   four.Program,
			ClearStateProgram: four.Program,
		}

		app := dl.txn(&create).ApplicationID

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

		// Downgrade (allowed for pre 6 programs until MinInnerApplVersion was lowered)
		update.ClearStateProgram = four.Program
		if ver <= 33 {
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

func TestInnerCreatedAppsAreCallable(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	genBalances, addrs, _ := ledgertesting.NewTestGenesis()

	// 31 allowed inner appl.
	ledgertesting.TestConsensusRange(t, 31, 0, func(t *testing.T, ver int, cv protocol.ConsensusVersion, cfg config.Local) {
		dl := NewDoubleLedger(t, genBalances, cv, cfg)
		defer dl.Close()

		ops, err := logic.AssembleStringWithVersion("int 1\nint 1\nassert", dl.generator.GenesisProto().LogicSigVersion)
		require.NoError(t, err)
		program := "byte 0x" + hex.EncodeToString(ops.Program)

		appID := dl.fundedApp(addrs[0], 1_000_000,
			main(`
		 itxn_begin
		  int appl;    itxn_field TypeEnum
		  `+program+`; itxn_field ApprovalProgram
		  `+program+`; itxn_field ClearStateProgram
		  int 1;       itxn_field GlobalNumUint
		  int 2;       itxn_field LocalNumByteSlice
		  int 3;       itxn_field LocalNumUint
		 itxn_submit`))

		callCreator := txntest.Txn{
			Type:          "appl",
			Sender:        addrs[0],
			ApplicationID: appID,
		}

		tib := dl.txn(&callCreator)
		createdID := tib.ApplyData.EvalDelta.InnerTxns[0].ApplyData.ApplicationID
		require.NotZero(t, createdID)

		callCreated := txntest.Txn{
			Type:          "appl",
			Sender:        addrs[0],
			ApplicationID: createdID,
		}

		dl.txn(&callCreated)
	})
}

func TestInvalidAppsNotAccessible(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	genBalances, addrs, _ := ledgertesting.NewTestGenesis()

	// v31 = inner appl
	ledgertesting.TestConsensusRange(t, 31, 0, func(t *testing.T, ver int, cv protocol.ConsensusVersion, cfg config.Local) {
		dl := NewDoubleLedger(t, genBalances, cv, cfg)
		defer dl.Close()

		// make an app, which we'll try to use without setting up foreign array
		tib := dl.txn(&txntest.Txn{
			Type:   "appl",
			Sender: addrs[0],
		})
		appID := tib.ApplyData.ApplicationID

		// an app that tries to access appID when called
		app0 := txntest.Txn{
			Type:   "appl",
			Sender: addrs[0],
			ApprovalProgram: main(`
itxn_begin
	int appl
	itxn_field TypeEnum
	int ` + strconv.Itoa(int(appID)) + `
	itxn_field ApplicationID
itxn_submit`),
		}
		callerID := dl.txn(&app0).ApplicationID

		fundCaller := txntest.Txn{
			Type:     "pay",
			Sender:   addrs[0],
			Receiver: callerID.Address(),
			Amount:   1_000_000,
		}
		dl.fullBlock(&fundCaller)

		callTx := txntest.Txn{
			Type:          "appl",
			Sender:        addrs[0],
			ApplicationID: callerID,
		}

		dl.txn(&callTx, "unavailable App "+strconv.Itoa(int(appID)))

		// confirm everything is done right if ForeignApps _is_ set up
		callTx.ForeignApps = []basics.AppIndex{appID}
		dl.txn(&callTx)
	})
}

func TestInvalidAssetsNotAccessible(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	genBalances, addrs, _ := ledgertesting.NewTestGenesis()

	// v31 = inner appl
	ledgertesting.TestConsensusRange(t, 31, 0, func(t *testing.T, ver int, cv protocol.ConsensusVersion, cfg config.Local) {
		dl := NewDoubleLedger(t, genBalances, cv, cfg)
		defer dl.Close()

		createasa := txntest.Txn{
			Type:   "acfg",
			Sender: addrs[0],
			AssetParams: basics.AssetParams{
				Total:     1000000,
				UnitName:  "oz",
				AssetName: "Gold",
				URL:       "https://gold.rush/",
			},
		}
		asaID := dl.txn(&createasa).ConfigAsset
		require.NotZero(t, asaID)

		appID := dl.fundedApp(addrs[0], 1_000_000,
			main(`
			itxn_begin
			int axfer; itxn_field TypeEnum
			int 0;     itxn_field Amount
			int `+strconv.Itoa(int(asaID))+`;     itxn_field XferAsset
			global CurrentApplicationAddress;  itxn_field Sender
			global CurrentApplicationAddress;  itxn_field AssetReceiver
			itxn_submit
`))

		use := txntest.Txn{
			Type:          "appl",
			Sender:        addrs[0],
			ApplicationID: appID,
		}

		dl.txn(&use, "unavailable Asset "+strconv.Itoa(int(asaID)))
		// confirm everything is done right if ForeignAssets _is_ set up
		use.ForeignAssets = []basics.AssetIndex{asaID}
		dl.txn(&use)

	})
}

func executeMegaContract(b *testing.B) {
	genBalances, addrs, _ := ledgertesting.NewTestGenesis()

	vTest := config.Consensus[protocol.ConsensusFuture]
	vTest.MaxAppProgramCost = 20000
	var cv protocol.ConsensusVersion = "temp test"
	config.Consensus[cv] = vTest

	cfg := config.GetDefaultLocal()
	l := newSimpleLedgerWithConsensusVersion(b, genBalances, cv, cfg)
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
	t.Parallel()

	genBalances, addrs, _ := ledgertesting.NewTestGenesis()
	// Inner apps start in v31
	ledgertesting.TestConsensusRange(t, 31, 0, func(t *testing.T, ver int, cv protocol.ConsensusVersion, cfg config.Local) {
		dl := NewDoubleLedger(t, genBalances, cv, cfg)
		defer dl.Close()

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

		vb := dl.fullBlock(&inner)
		innerID := vb.Block().Payset[0].ApplicationID

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
			ForeignApps: []basics.AppIndex{innerID},
		}

		vb = dl.fullBlock(&outer)
		outerID := vb.Block().Payset[0].ApplicationID

		fund := txntest.Txn{
			Type:     "pay",
			Sender:   addrs[0],
			Receiver: outerID.Address(),
			Amount:   1_000_000,
		}

		call := txntest.Txn{
			Type:            "appl",
			Sender:          addrs[0],
			ApplicationID:   outerID,
			ApplicationArgs: [][]byte{{byte(transactions.OptInOC)}},
			ForeignApps:     []basics.AppIndex{innerID},
		}
		dl.txns(&fund, &call)

		outerAcct := lookup(t, dl.generator, outerID.Address())
		require.Len(t, outerAcct.AppLocalStates, 1)
		require.Equal(t, outerAcct.TotalAppSchema, basics.StateSchema{
			NumUint:      2,
			NumByteSlice: 2,
		})

		call.ApplicationArgs = [][]byte{{byte(transactions.ClearStateOC)}}
		dl.txn(&call)

		outerAcct = lookup(t, dl.generator, outerID.Address())
		require.Empty(t, outerAcct.AppLocalStates)
		require.Empty(t, outerAcct.TotalAppSchema)
	})
}

// TestInnerClearStateBadCallee ensures that inner clear state programs are not
// allowed to use more than 700 (MaxAppProgramCost)
func TestInnerClearStateBadCallee(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	genBalances, addrs, _ := ledgertesting.NewTestGenesis()
	// Inner appls start in v31
	ledgertesting.TestConsensusRange(t, 31, 0, func(t *testing.T, ver int, cv protocol.ConsensusVersion, cfg config.Local) {
		dl := NewDoubleLedger(t, genBalances, cv, cfg)
		defer dl.Close()

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

		vb := dl.fullBlock(&badCallee)
		badID := vb.Block().Payset[0].ApplicationID

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
			ForeignApps: []basics.AppIndex{badID},
		}

		vb = dl.fullBlock(&outer)
		outerID := vb.Block().Payset[0].ApplicationID

		fund := txntest.Txn{
			Type:     "pay",
			Sender:   addrs[0],
			Receiver: outerID.Address(),
			Amount:   1_000_000,
		}

		call := txntest.Txn{
			Type:            "appl",
			Sender:          addrs[0],
			ApplicationID:   outerID,
			ApplicationArgs: [][]byte{{byte(transactions.OptInOC)}},
			ForeignApps:     []basics.AppIndex{badID},
		}
		dl.fullBlock(&fund, &call)

		outerAcct := lookup(t, dl.generator, outerID.Address())
		require.Len(t, outerAcct.AppLocalStates, 1)

		// When doing a clear state, `call` checks that budget wasn't stolen
		call.ApplicationArgs = [][]byte{{byte(transactions.ClearStateOC)}}
		dl.fullBlock(&call)

		// Clearstate took effect, despite failure from infinite loop
		outerAcct = lookup(t, dl.generator, outerID.Address())
		require.Empty(t, outerAcct.AppLocalStates)
	})
}

// TestInnerClearStateBadCaller ensures that inner clear state programs cannot
// be called with less than 700 (MaxAppProgramCost)) OpcodeBudget.
func TestInnerClearStateBadCaller(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	genBalances, addrs, _ := ledgertesting.NewTestGenesis()
	// Inner appls start in v31
	ledgertesting.TestConsensusRange(t, 31, 0, func(t *testing.T, ver int, cv protocol.ConsensusVersion, cfg config.Local) {
		dl := NewDoubleLedger(t, genBalances, cv, cfg)
		defer dl.Close()

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

		vb := dl.fullBlock(&inner, &waster)
		innerID := vb.Block().Payset[0].ApplicationID
		wasterID := vb.Block().Payset[1].ApplicationID

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

		vb = dl.fullBlock(&grouper)
		grouperID := vb.Block().Payset[0].ApplicationID

		fund := txntest.Txn{
			Type:     "pay",
			Sender:   addrs[0],
			Receiver: grouperID.Address(),
			Amount:   1_000_000,
		}

		call := txntest.Txn{
			Type:            "appl",
			Sender:          addrs[0],
			ApplicationID:   grouperID,
			ApplicationArgs: [][]byte{{byte(transactions.OptInOC)}, {byte(transactions.OptInOC)}},
			ForeignApps:     []basics.AppIndex{wasterID, innerID},
		}
		dl.fullBlock(&fund, &call)

		gAcct := lookup(t, dl.generator, grouperID.Address())
		require.Len(t, gAcct.AppLocalStates, 2)

		call.ApplicationArgs = [][]byte{{byte(transactions.CloseOutOC)}, {byte(transactions.ClearStateOC)}}
		dl.txn(&call, "ClearState execution with low OpcodeBudget")

		// Clearstate did not take effect, since the caller tried to shortchange the CSP
		gAcct = lookup(t, dl.generator, grouperID.Address())
		require.Len(t, gAcct.AppLocalStates, 2)
	})
}

// TestClearStateInnerPay ensures that ClearState programs can run inner txns in
// v30, but not in vFuture. (Test should add v31 after it exists.)
func TestClearStateInnerPay(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

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
			cfg := config.GetDefaultLocal()
			l := newSimpleLedgerWithConsensusVersion(t, genBalances, test.consensus, cfg)
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
			id0 := vb.Block().Payset[0].ApplicationID

			fund0 := txntest.Txn{
				Type:     "pay",
				Sender:   addrs[0],
				Receiver: id0.Address(),
				Amount:   1_000_000,
			}

			optin := txntest.Txn{
				Type:          "appl",
				Sender:        addrs[1],
				ApplicationID: id0,
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
				ApplicationID: id0,
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
				require.Equal(t, vb.Block().Payset[0].Txn.ApplicationID, id0)
				require.Equal(t, vb.Block().Payset[0].Txn.OnCompletion, transactions.ClearStateOC)
				require.Len(t, vb.Block().Payset[0].EvalDelta.InnerTxns, 1)
				require.Equal(t, vb.Block().Payset[0].EvalDelta.InnerTxns[0].Txn.Amount.Raw, uint64(2000))
			} else {
				// Only the fee is paid because pay is "erased", so goes from 2k down to 1k
				require.Equal(t, uint64(1000), ad1-genBalances.Balances[addrs[1]].MicroAlgos.Raw)
				// no InnerTxn in block
				require.Equal(t, vb.Block().Payset[0].Txn.ApplicationID, id0)
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
	t.Parallel()

	genBalances, addrs, _ := ledgertesting.NewTestGenesis()
	// Inner appls start in v31
	ledgertesting.TestConsensusRange(t, 31, 0, func(t *testing.T, ver int, cv protocol.ConsensusVersion, cfg config.Local) {
		dl := NewDoubleLedger(t, genBalances, cv, cfg)
		defer dl.Close()

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

		vb := dl.fullBlock(&appA, &appB, &appC)
		idA := vb.Block().Payset[0].ApplicationID
		idB := vb.Block().Payset[1].ApplicationID
		idC := vb.Block().Payset[2].ApplicationID

		fundA := txntest.Txn{
			Type:     "pay",
			Sender:   addrs[0],
			Receiver: idA.Address(),
			Amount:   1_000_000,
		}

		callA := txntest.Txn{
			Type:          "appl",
			Sender:        addrs[0],
			ApplicationID: idA,
			ForeignApps:   []basics.AppIndex{idB, idC},
		}

		dl.fullBlock(&fundA, &callA)
	})
}

// TestLocalChangesAcrossApps ensures that state changes are seen by other app
// calls when using inners.
func TestLocalChangesAcrossApps(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	genBalances, addrs, _ := ledgertesting.NewTestGenesis()
	// Inner appls start in v31
	ledgertesting.TestConsensusRange(t, 31, 0, func(t *testing.T, ver int, cv protocol.ConsensusVersion, cfg config.Local) {
		dl := NewDoubleLedger(t, genBalances, cv, cfg)
		defer dl.Close()

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

		vb := dl.fullBlock(&appA, &appB, &appC)
		idA := vb.Block().Payset[0].ApplicationID
		idB := vb.Block().Payset[1].ApplicationID
		idC := vb.Block().Payset[2].ApplicationID

		fundA := txntest.Txn{
			Type:     "pay",
			Sender:   addrs[0],
			Receiver: idA.Address(),
			Amount:   1_000_000,
		}

		callA := txntest.Txn{
			Type:          "appl",
			Sender:        addrs[0],
			ApplicationID: idA,
			ForeignApps:   []basics.AppIndex{idB, idC},
		}

		dl.fullBlock(&fundA, &callA)
	})
}

func TestForeignAppAccountsAccessible(t *testing.T) {
	partitiontest.PartitionTest(t)

	genBalances, addrs, _ := ledgertesting.NewTestGenesis()
	ledgertesting.TestConsensusRange(t, 32, 0, func(t *testing.T, ver int, cv protocol.ConsensusVersion, cfg config.Local) {
		dl := NewDoubleLedger(t, genBalances, cv, cfg)
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

		payset := dl.txns(&appA, &appB)
		id0 := payset[0].ApplicationID
		id1 := payset[1].ApplicationID

		fund1 := txntest.Txn{
			Type:     "pay",
			Sender:   addrs[0],
			Receiver: id1.Address(),
			Amount:   1_000_000_000,
		}
		fund0 := fund1
		fund0.Receiver = id0.Address()

		callTx := txntest.Txn{
			Type:          "appl",
			Sender:        addrs[2],
			ApplicationID: id1,
			ForeignApps:   []basics.AppIndex{id0},
		}

		if ver <= 33 {
			dl.txgroup("unavailable Account", &fund0, &fund1, &callTx)
			return
		}
		payset = dl.txgroup("", &fund0, &fund1, &callTx)
		require.Equal(t, id0.Address(), payset[2].EvalDelta.InnerTxns[0].Txn.Receiver)
		require.Equal(t, uint64(100), payset[2].EvalDelta.InnerTxns[0].Txn.Amount.Raw)
	})
}

// While accounts of foreign apps are available in most contexts, they still
// cannot be used as mutable references; ie the accounts cannot be used by
// opcodes that modify local storage.
func TestForeignAppAccountsImmutable(t *testing.T) {
	partitiontest.PartitionTest(t)

	genBalances, addrs, _ := ledgertesting.NewTestGenesis()
	ledgertesting.TestConsensusRange(t, 32, 0, func(t *testing.T, ver int, cv protocol.ConsensusVersion, cfg config.Local) {
		dl := NewDoubleLedger(t, genBalances, cv, cfg)
		defer dl.Close()

		appA := txntest.Txn{
			Type:   "appl",
			Sender: addrs[0],
			ApprovalProgram: main(`
itxn_begin
int appl;               itxn_field TypeEnum
txn Applications 1;     itxn_field ApplicationID
int OptIn;              itxn_field OnCompletion
itxn_submit
`),
		}

		appB := txntest.Txn{
			Type:   "appl",
			Sender: addrs[0],
			ApprovalProgram: main(`
txn NumApplications				// allow "bare" optin
bz end
txn Applications 1
app_params_get AppAddress
assert
byte "X"
byte "ABC"
app_local_put
`),
			LocalStateSchema: basics.StateSchema{NumByteSlice: 1},
		}

		payset := dl.txns(&appA, &appB)
		id0 := payset[0].ApplicationID
		id1 := payset[1].ApplicationID

		fund1 := txntest.Txn{
			Type:     "pay",
			Sender:   addrs[0],
			Receiver: id1.Address(),
			Amount:   1_000_000_000,
		}
		fund0 := fund1
		fund0.Receiver = id0.Address()

		optin := txntest.Txn{
			Type:          "appl",
			Sender:        addrs[2],
			ApplicationID: id0,
			ForeignApps:   []basics.AppIndex{id1},
		}

		callTx := txntest.Txn{
			Type:          "appl",
			Sender:        addrs[2],
			ApplicationID: id1,
			ForeignApps:   []basics.AppIndex{id0},
		}

		var problem string
		switch {
		case ver < 34: // before v7, app accounts not available at all
			problem = "unavailable Account " + id0.Address().String()
		case ver < 38: // as of v7, it's the mutation that's the problem
			problem = "invalid Account reference for mutation"
		}
		dl.txgroup(problem, &fund0, &fund1, &optin, &callTx)
	})
}

// In the case where the foreign app account is also provided in the
// transaction's account field, mutable references should be allowed.
func TestForeignAppAccountsMutable(t *testing.T) {
	partitiontest.PartitionTest(t)

	genBalances, addrs, _ := ledgertesting.NewTestGenesis()
	ledgertesting.TestConsensusRange(t, 32, 0, func(t *testing.T, ver int, cv protocol.ConsensusVersion, cfg config.Local) {
		dl := NewDoubleLedger(t, genBalances, cv, cfg)
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

		payset := dl.txns(&appA, &appB)
		id0 := payset[0].ApplicationID
		id1 := payset[1].ApplicationID

		fund1 := txntest.Txn{
			Type:     "pay",
			Sender:   addrs[0],
			Receiver: id1.Address(),
			Amount:   1_000_000_000,
		}
		fund0 := fund1
		fund0.Receiver = id0.Address()
		fund1.Receiver = id1.Address()

		callA := txntest.Txn{
			Type:          "appl",
			Sender:        addrs[2],
			ApplicationID: id0,
			ForeignApps:   []basics.AppIndex{id1},
		}

		callB := txntest.Txn{
			Type:          "appl",
			Sender:        addrs[2],
			ApplicationID: id1,
			ForeignApps:   []basics.AppIndex{id0},
			Accounts:      []basics.Address{id0.Address()},
		}

		payset = dl.txns(&fund0, &fund1, &callA, &callB)
		require.Equal(t, "Y", payset[3].EvalDelta.LocalDeltas[1]["X"].Bytes)
	})
}

// TestReloadWithTxns confirms that the ledger can be reloaded from "disk" when
// doing so requires replaying some interesting AVM txns.
func TestReloadWithTxns(t *testing.T) {
	partitiontest.PartitionTest(t)

	genBalances, addrs, _ := ledgertesting.NewTestGenesis()
	ledgertesting.TestConsensusRange(t, 34, 0, func(t *testing.T, ver int, cv protocol.ConsensusVersion, cfg config.Local) {
		dl := NewDoubleLedger(t, genBalances, cv, cfg)
		defer dl.Close()

		dl.fullBlock() // So that the `block` opcode has a block to inspect

		lookHdr := txntest.Txn{
			Type:            "appl",
			Sender:          addrs[0],
			ApprovalProgram: "txn FirstValid;  int 1;  -;  block BlkTimestamp",
		}

		dl.fullBlock(&lookHdr)

		dl.reloadLedgers()
	})
}

// TestEvalAppState ensures txns in a group can't violate app state schema
// limits. It ensures that commitToParent -> applyChild copies child's cow state
// usage counts into parent and the usage counts are correctly propagated from
// parent cow to child cow and back. When limits are not violated, the test
// ensures that the updates are correct.
func TestEvalAppState(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	genBalances, addrs, _ := ledgertesting.NewTestGenesis()
	// v24 = apps
	ledgertesting.TestConsensusRange(t, 24, 0, func(t *testing.T, ver int, cv protocol.ConsensusVersion, cfg config.Local) {
		dl := NewDoubleLedger(t, genBalances, cv, cfg)
		defer dl.Close()

		appID := basics.AppIndex(1)
		if ver >= 38 { // AppForbidLowResources
			appID += 1000
		}
		appcall1 := txntest.Txn{
			Type:              protocol.ApplicationCallTx,
			Sender:            addrs[0],
			GlobalStateSchema: basics.StateSchema{NumByteSlice: 1},
			ApprovalProgram: `#pragma version 2
	txn ApplicationID
	bz create
	byte "caller"
	txn Sender
	app_global_put
	b ok
create:
	byte "creator"
	txn Sender
	app_global_put
ok:
	int 1`,
			ClearStateProgram: "#pragma version 2\nint 1",
		}

		appcall2 := txntest.Txn{
			Type:          protocol.ApplicationCallTx,
			Sender:        addrs[0],
			ApplicationID: appID,
		}

		dl.beginBlock()
		dl.txgroup("store bytes count 2 exceeds schema bytes count 1", &appcall1, &appcall2)

		appcall1.GlobalStateSchema = basics.StateSchema{NumByteSlice: 2}
		dl.txgroup("", &appcall1, &appcall2)
		vb := dl.endBlock()
		deltas := vb.Delta()

		params, ok := deltas.Accts.GetAppParams(addrs[0], appID)
		require.True(t, ok)
		require.Equal(t, basics.TealKeyValue{
			"caller":  {Type: basics.TealBytesType, Bytes: string(addrs[0][:])},
			"creator": {Type: basics.TealBytesType, Bytes: string(addrs[0][:])},
		}, params.Params.GlobalState)
	})
}

func TestGarbageClearState(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	genBalances, addrs, _ := ledgertesting.NewTestGenesis()
	// v24 = apps
	ledgertesting.TestConsensusRange(t, 24, 0, func(t *testing.T, ver int, cv protocol.ConsensusVersion, cfg config.Local) {
		dl := NewDoubleLedger(t, genBalances, cv, cfg)
		defer dl.Close()

		createTxn := txntest.Txn{
			Type:              "appl",
			Sender:            addrs[0],
			ApprovalProgram:   "int 1",
			ClearStateProgram: []byte{},
		}

		dl.txn(&createTxn, "invalid program (empty)")

		createTxn.ClearStateProgram = []byte{0xfe} // bad uvarint
		dl.txn(&createTxn, "invalid version")
	})
}

func TestRewardsInAD(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	genBalances, addrs, _ := ledgertesting.NewTestGenesis()
	// v15 put rewards into ApplyData
	ledgertesting.TestConsensusRange(t, 11, 0, func(t *testing.T, ver int, cv protocol.ConsensusVersion, cfg config.Local) {
		dl := NewDoubleLedger(t, genBalances, cv, cfg)
		defer dl.Close()

		payTxn := txntest.Txn{Type: protocol.PaymentTx, Sender: addrs[0], Receiver: addrs[1]}
		nonpartTxn := txntest.Txn{Type: protocol.KeyRegistrationTx, Sender: addrs[2], Nonparticipation: true}
		payNonPart := txntest.Txn{Type: protocol.PaymentTx, Sender: addrs[0], Receiver: addrs[2]}

		if ver < 18 { // Nonpart reyreg happens in v18
			dl.txn(&nonpartTxn, "tries to mark an account as nonparticipating")
		} else {
			dl.fullBlock(&nonpartTxn)
		}

		// Build up Residue in RewardsState so it's ready to pay
		for i := 1; i < 10; i++ {
			dl.fullBlock()
		}

		payset := dl.txns(&payTxn, &payNonPart)
		payInBlock := payset[0]
		nonPartInBlock := payset[1]
		if ver >= 15 {
			require.Greater(t, payInBlock.ApplyData.SenderRewards.Raw, uint64(1000))
			require.Greater(t, payInBlock.ApplyData.ReceiverRewards.Raw, uint64(1000))
			require.Equal(t, payInBlock.ApplyData.SenderRewards, payInBlock.ApplyData.ReceiverRewards)
			// Sender is not due for more, and Receiver is nonpart
			require.Zero(t, nonPartInBlock.ApplyData.SenderRewards)
			if ver < 18 {
				require.Greater(t, nonPartInBlock.ApplyData.ReceiverRewards.Raw, uint64(1000))
			} else {
				require.Zero(t, nonPartInBlock.ApplyData.ReceiverRewards)
			}
		} else {
			require.Zero(t, payInBlock.ApplyData.SenderRewards)
			require.Zero(t, payInBlock.ApplyData.ReceiverRewards)
			require.Zero(t, nonPartInBlock.ApplyData.SenderRewards)
			require.Zero(t, nonPartInBlock.ApplyData.ReceiverRewards)
		}
	})
}

// TestDeleteNonExistentKeys checks if the EvalDeltas from deleting missing keys are correct
func TestDeleteNonExistentKeys(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	genBalances, addrs, _ := ledgertesting.NewTestGenesis()
	// AVM v4 start, so we can use `txn Sender`
	ledgertesting.TestConsensusRange(t, 28, 0, func(t *testing.T, ver int, cv protocol.ConsensusVersion, cfg config.Local) {
		dl := NewDoubleLedger(t, genBalances, cv, cfg)
		defer dl.Close()

		createTxn := txntest.Txn{
			Type:   "appl",
			Sender: addrs[0],
			ApprovalProgram: main(`
byte "missing_global"
app_global_del
txn Sender
byte "missing_local"
app_local_del
`),
		}

		appID := dl.txn(&createTxn).ApplyData.ApplicationID

		optInTxn := txntest.Txn{
			Type:          "appl",
			Sender:        addrs[1],
			ApplicationID: appID,
			OnCompletion:  transactions.OptInOC,
		}

		tib := dl.txn(&optInTxn)
		require.Len(t, tib.EvalDelta.GlobalDelta, 0)
		// For a while, we encoded an empty localdelta
		deltas := 1
		if ver >= 27 {
			deltas = 0
		}
		require.Len(t, tib.EvalDelta.LocalDeltas, deltas)
	})
}

func TestDuplicates(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	genBalances, addrs, _ := ledgertesting.NewTestGenesis()
	ledgertesting.TestConsensusRange(t, 11, 0, func(t *testing.T, ver int, cv protocol.ConsensusVersion, cfg config.Local) {
		dl := NewDoubleLedger(t, genBalances, cv, cfg)
		defer dl.Close()

		pay := txntest.Txn{
			Type:     "pay",
			Sender:   addrs[0],
			Receiver: addrs[1],
			Amount:   10,
		}
		dl.txn(&pay)
		dl.txn(&pay, "transaction already in ledger")

		// Test same transaction in a later block
		dl.txn(&pay, "transaction already in ledger")

		// Change the note so it can go in again
		pay.Note = []byte("1")
		dl.txn(&pay)

		// Change note again, but try the txn twice in same group
		if dl.generator.GenesisProto().MaxTxGroupSize > 1 {
			pay.Note = []byte("2")
			dl.txgroup("transaction already in ledger", &pay, &pay)
		}
	})
}

// TestHeaderAccess tests FirstValidTime and `block` which can access previous
// block headers.
func TestHeaderAccess(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	genBalances, addrs, _ := ledgertesting.NewTestGenesis()
	// Added in v34
	ledgertesting.TestConsensusRange(t, 34, 0, func(t *testing.T, ver int, cv protocol.ConsensusVersion, cfg config.Local) {
		dl := NewDoubleLedger(t, genBalances, cv, cfg)
		defer dl.Close()

		fvt := txntest.Txn{
			Type:            "appl",
			Sender:          addrs[0],
			FirstValid:      0,
			ApprovalProgram: "txn FirstValidTime",
		}
		dl.txn(&fvt, "round 0 is not available")

		// advance current to 2
		pay := txntest.Txn{Type: "pay", Sender: addrs[0], Receiver: addrs[0]}
		dl.fullBlock(&pay)

		fvt.FirstValid = 1
		dl.txn(&fvt, "round 0 is not available")

		fvt.FirstValid = 2
		dl.txn(&fvt) // current becomes 3

		// Advance current round far enough to test access MaxTxnLife ago
		for i := 0; i < int(config.Consensus[cv].MaxTxnLife); i++ {
			dl.fullBlock()
		}

		// current should be 1003. Confirm.
		require.EqualValues(t, 1002, dl.generator.Latest())
		require.EqualValues(t, 1002, dl.validator.Latest())

		fvt.FirstValid = 1003
		fvt.LastValid = 1010
		dl.txn(&fvt) // success advances the round
		// now we're confident current is 1004, so construct a txn that is as
		// old as possible, and confirm access.
		fvt.FirstValid = 1004 - basics.Round(config.Consensus[cv].MaxTxnLife)
		fvt.LastValid = 1004
		dl.txn(&fvt)
	})

}

// TestLogsInBlock ensures that logs appear in the block properly
func TestLogsInBlock(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	genBalances, addrs, _ := ledgertesting.NewTestGenesis()
	// Run tests from v30 onward
	ledgertesting.TestConsensusRange(t, 30, 0, func(t *testing.T, ver int, cv protocol.ConsensusVersion, cfg config.Local) {
		dl := NewDoubleLedger(t, genBalances, cv, cfg)
		defer dl.Close()

		createTxn := txntest.Txn{
			Type:            "appl",
			Sender:          addrs[0],
			ApprovalProgram: "byte \"APP\"\n log\n int 1",
			// Fail the clear state
			ClearStateProgram: "byte \"CLR\"\n log\n int 0",
		}
		createInBlock := dl.txn(&createTxn)
		appID := createInBlock.ApplyData.ApplicationID
		require.Equal(t, "APP", createInBlock.ApplyData.EvalDelta.Logs[0])

		optInTxn := txntest.Txn{
			Type:          protocol.ApplicationCallTx,
			Sender:        addrs[1],
			ApplicationID: appID,
			OnCompletion:  transactions.OptInOC,
		}
		optInInBlock := dl.txn(&optInTxn)
		require.Equal(t, "APP", optInInBlock.ApplyData.EvalDelta.Logs[0])

		clearTxn := txntest.Txn{
			Type:          protocol.ApplicationCallTx,
			Sender:        addrs[1],
			ApplicationID: appID,
			OnCompletion:  transactions.ClearStateOC,
		}
		clearInBlock := dl.txn(&clearTxn)
		// Logs do not appear if the ClearState failed
		require.Len(t, clearInBlock.ApplyData.EvalDelta.Logs, 0)
	})
}

// TestUnfundedSenders confirms that accounts that don't even exist
// can be the Sender in some situations.  If some other transaction
// covers the fee, and the transaction itself does not require an
// asset or a min balance, it's fine.
func TestUnfundedSenders(t *testing.T) {
	/*
		In a 0-fee transaction from unfunded sender, we still call balances.Move
		to “pay” the fee.  Move() does not short-circuit a Move of 0 (for good
		reason, it allows compounding rewards).  Therefore, in Move, we do
		rewards processing on the unfunded account.  Before
		proto.UnfundedSenders, the rewards procesing would set the RewardsBase,
		which would require the account be written to DB, and therefore the MBR
		check would kick in (and fail). Now it skips the update if the account
		has less than RewardsUnit, as the update is meaningless anyway.
	*/

	partitiontest.PartitionTest(t)
	t.Parallel()

	genBalances, addrs, _ := ledgertesting.NewTestGenesis()

	ledgertesting.TestConsensusRange(t, 24, 0, func(t *testing.T, ver int, cv protocol.ConsensusVersion, cfg config.Local) {
		dl := NewDoubleLedger(t, genBalances, cv, cfg)
		defer dl.Close()

		ghost := basics.Address{0x01}

		asaCreate := txntest.Txn{
			Type:   "acfg",
			Sender: addrs[0],
			AssetParams: basics.AssetParams{
				Total:    10,
				Clawback: ghost,
				Freeze:   ghost,
				Manager:  ghost,
			},
		}

		appCreate := txntest.Txn{
			Type:   "appl",
			Sender: addrs[0],
		}

		payset := dl.txns(&asaCreate, &appCreate)
		asaID := payset[0].ApplyData.ConfigAsset
		// we are testing some versions before ApplyData.ConfigAsset was
		// populated. At that time, initial ID was 1, so we can hardcode.
		if asaID == 0 {
			asaID = 1
		}
		appID := payset[1].ApplyData.ApplicationID
		if appID == 0 {
			appID = 2
		}

		// Advance so that rewardsLevel increases
		for i := 1; i < 10; i++ {
			dl.fullBlock()
		}

		benefactor := txntest.Txn{
			Type:     "pay",
			Sender:   addrs[0],
			Receiver: addrs[0],
			Fee:      2000,
		}

		ephemeral := []txntest.Txn{
			{
				Type:     "pay",
				Amount:   0,
				Sender:   ghost,
				Receiver: ghost,
				Fee:      0,
			},
			{ // Axfer of 0
				Type:          "axfer",
				AssetAmount:   0,
				Sender:        ghost,
				AssetReceiver: basics.Address{0x02},
				XferAsset:     basics.AssetIndex(1),
				Fee:           0,
			},
			{ // Clawback
				Type:          "axfer",
				AssetAmount:   0,
				Sender:        ghost,
				AssetReceiver: addrs[0],
				AssetSender:   addrs[1],
				XferAsset:     asaID,
				Fee:           0,
			},
			{ // Freeze
				Type:          "afrz",
				Sender:        ghost,
				FreezeAccount: addrs[0], // creator, therefore is opted in
				FreezeAsset:   asaID,
				AssetFrozen:   true,
				Fee:           0,
			},
			{ // Unfreeze
				Type:          "afrz",
				Sender:        ghost,
				FreezeAccount: addrs[0], // creator, therefore is opted in
				FreezeAsset:   asaID,
				AssetFrozen:   false,
				Fee:           0,
			},
			{ // App call
				Type:          "appl",
				Sender:        ghost,
				ApplicationID: appID,
				Fee:           0,
			},
			{ // App creation (only works because it's also deleted)
				Type:         "appl",
				Sender:       ghost,
				OnCompletion: transactions.DeleteApplicationOC,
				Fee:          0,
			},
		}

		// v34 enabled UnfundedSenders
		var problem string
		if ver < 34 {
			// In the old days, balances.Move would try to increase the rewardsState on the unfunded account
			problem = "balance 0 below min"
		}
		for i, e := range ephemeral {
			dl.txgroup(problem, benefactor.Noted(strconv.Itoa(i)), &e)
		}
	})
}

// TestAppCallAppDuringInit is similar to TestUnfundedSenders test, but now the
// unfunded sender is a newly created app.  The fee has been paid by the outer
// transaction, so the app should be able to make an app call as that requires
// no min balance.
func TestAppCallAppDuringInit(t *testing.T) {
	partitiontest.PartitionTest(t)

	genBalances, addrs, _ := ledgertesting.NewTestGenesis()
	ledgertesting.TestConsensusRange(t, 31, 0, func(t *testing.T, ver int, cv protocol.ConsensusVersion, cfg config.Local) {
		dl := NewDoubleLedger(t, genBalances, cv, cfg)
		defer dl.Close()

		approve := txntest.Txn{
			Type:   "appl",
			Sender: addrs[0],
		}

		// construct a simple approval app
		approveID := dl.txn(&approve).ApplicationID

		// Advance so that rewardsLevel increases
		for i := 1; i < 10; i++ {
			dl.fullBlock()
		}

		// now make a new app that calls it during init
		callInInit := txntest.Txn{
			Type:   "appl",
			Sender: addrs[0],
			ApprovalProgram: `
			  itxn_begin
			  int appl
			  itxn_field TypeEnum
			  txn Applications 1
			  itxn_field ApplicationID
			  itxn_submit
              int 1
            `,
			ForeignApps: []basics.AppIndex{approveID},
			Fee:         2000, // Enough to have the inner fee paid for
		}
		// v34 is the likely version for UnfundedSenders. Change if that doesn't happen.
		var problem string
		if ver < 34 {
			// In the old days, balances.Move would try to increase the rewardsState on the unfunded account
			problem = "balance 0 below min"
		}
		dl.txn(&callInInit, problem)
	})
}
