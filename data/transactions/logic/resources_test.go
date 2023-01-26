// Copyright (C) 2019-2023 Algorand, Inc.
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

package logic_test

import (
	"fmt"
	"testing"

	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/transactions/logic"
	"github.com/algorand/go-algorand/data/txntest"
	"github.com/algorand/go-algorand/protocol"
	"github.com/algorand/go-algorand/test/partitiontest"
)

// TestAppSharing confirms that as of v9, assets can be accessed across
// groups, but that before then, they could not.
func TestAppSharing(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	// Create some sample transactions. The main reason this a blackbox test
	// (_test package) is to have access to txntest.
	appl0 := txntest.Txn{
		Type:        protocol.ApplicationCallTx,
		Sender:      basics.Address{1, 2, 3, 4},
		ForeignApps: []basics.AppIndex{500},
	}

	appl1 := txntest.Txn{
		Type:   protocol.ApplicationCallTx,
		Sender: basics.Address{4, 3, 2, 1},
	}

	appl2 := txntest.Txn{
		Type:   protocol.ApplicationCallTx,
		Sender: basics.Address{1, 2, 3, 4},
	}

	getSchema := `
int 500
app_params_get AppGlobalNumByteSlice
!; assert; pop; int 1
`
	sources := []string{getSchema, getSchema}
	// In v8, the first tx can read app params of 500, because it's in its
	// foreign array, but the second can't
	logic.TestApps(t, sources, txntest.Group(&appl0, &appl1), 8, nil,
		logic.NewExpect(1, "invalid App reference 500"))
	// In v9, the second can, because the first can.
	logic.TestApps(t, sources, txntest.Group(&appl0, &appl1), 9, nil)

	getLocalEx := `
int 0							// Sender
int 500
byte "some-key"
app_local_get_ex
pop; pop; int 1
`

	sources = []string{getLocalEx, getLocalEx}
	// In contrast, here there's no help from v9, because the second tx is
	// reading the locals for a different account.

	// app_local_get* requires the address and the app exist, else the program fails
	logic.TestApps(t, sources, txntest.Group(&appl0, &appl1), 8, nil,
		logic.NewExpect(0, "no account"))

	_, _, ledger := logic.MakeSampleEnv()
	ledger.NewAccount(appl0.Sender, 100_000)
	ledger.NewApp(appl0.Sender, 500, basics.AppParams{})
	ledger.NewLocals(appl0.Sender, 500) // opt in
	// Now txn0 passes, but txn1 has an error because it can't see app 500
	logic.TestApps(t, sources, txntest.Group(&appl0, &appl1), 9, ledger,
		logic.NewExpect(1, "invalid Local State access"))

	// But it's ok in appl2, because appl2 uses the same Sender, even though the
	// foreign-app is not repeated in appl2 so the holding being accessed is is
	// the one from tx0.
	logic.TestApps(t, sources, txntest.Group(&appl0, &appl2), 9, ledger)
}

// TestAssetSharing confirms that as of v9, assets can be accessed across
// groups, but that before then, they could not.
func TestAssetSharing(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	// Create some sample transactions. The main reason this a blackbox test
	// (_test package) is to have access to txntest.
	appl0 := txntest.Txn{
		Type:          protocol.ApplicationCallTx,
		Sender:        basics.Address{1, 2, 3, 4},
		ForeignAssets: []basics.AssetIndex{400},
	}

	appl1 := txntest.Txn{
		Type:   protocol.ApplicationCallTx,
		Sender: basics.Address{4, 3, 2, 1},
	}

	appl2 := txntest.Txn{
		Type:   protocol.ApplicationCallTx,
		Sender: basics.Address{1, 2, 3, 4},
	}

	getTotal := `
int 400
asset_params_get AssetTotal
pop; pop; int 1
`
	sources := []string{getTotal, getTotal}
	// In v8, the first tx can read asset 400, because it's in its foreign arry,
	// but the second can't
	logic.TestApps(t, sources, txntest.Group(&appl0, &appl1), 8, nil,
		logic.NewExpect(1, "invalid Asset reference 400"))
	// In v9, the second can, because the first can.
	logic.TestApps(t, sources, txntest.Group(&appl0, &appl1), 9, nil)

	getBalance := `
int 0
int 400
asset_holding_get AssetBalance
pop; pop; int 1
`

	sources = []string{getBalance, getBalance}
	// In contrast, here there's no help from v9, because the second tx is
	// reading a holding for a different account.
	logic.TestApps(t, sources, txntest.Group(&appl0, &appl1), 8, nil,
		logic.NewExpect(1, "invalid Asset reference 400"))
	logic.TestApps(t, sources, txntest.Group(&appl0, &appl1), 9, nil,
		logic.NewExpect(1, "invalid Holding access"))
	// But it's ok in appl2, because the same account is used, even though the
	// foreign-asset is not repeated in appl2.
	logic.TestApps(t, sources, txntest.Group(&appl0, &appl2), 9, nil)
}

// TestOtherTxSharing tests resource sharing across other kinds of transactions besides appl.
func TestOtherTxSharing(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	_, _, ledger := logic.MakeSampleEnv()

	senderAcct := basics.Address{1, 2, 3, 4, 5, 6, 1}
	ledger.NewAccount(senderAcct, 2001)
	senderBalance := "txn ApplicationArgs 0; balance; int 2001; =="

	receiverAcct := basics.Address{1, 2, 3, 4, 5, 6, 2}
	ledger.NewAccount(receiverAcct, 2002)
	receiverBalance := "txn ApplicationArgs 0; balance; int 2002; =="

	otherAcct := basics.Address{1, 2, 3, 4, 5, 6, 3}
	ledger.NewAccount(otherAcct, 2003)
	otherBalance := "txn ApplicationArgs 0; balance; int 2003; =="

	appl := txntest.Txn{
		Type:            protocol.ApplicationCallTx,
		Sender:          basics.Address{5, 5, 5, 5}, // different from all other accounts used
		ApplicationArgs: [][]byte{senderAcct[:]},
	}

	keyreg := txntest.Txn{
		Type:   protocol.KeyRegistrationTx,
		Sender: senderAcct,
	}
	pay := txntest.Txn{
		Type:     protocol.PaymentTx,
		Sender:   senderAcct,
		Receiver: receiverAcct,
	}
	acfg := txntest.Txn{
		Type:   protocol.AssetConfigTx,
		Sender: senderAcct,
		AssetParams: basics.AssetParams{
			Manager:  otherAcct, // other is here to show they _don't_ become available
			Reserve:  otherAcct,
			Freeze:   otherAcct,
			Clawback: otherAcct,
		},
	}
	axfer := txntest.Txn{
		Type:          protocol.AssetTransferTx,
		XferAsset:     100, // must be < 256, later code assumes it fits in a byte
		Sender:        senderAcct,
		AssetReceiver: receiverAcct,
		AssetSender:   otherAcct,
	}
	afrz := txntest.Txn{
		Type:          protocol.AssetFreezeTx,
		FreezeAsset:   200, // must be < 256, later code assumes it fits in a byte
		Sender:        senderAcct,
		FreezeAccount: otherAcct,
	}

	sources := []string{"", senderBalance}
	rsources := []string{senderBalance, ""}
	for _, send := range []txntest.Txn{keyreg, pay, acfg, axfer, afrz} {
		logic.TestApps(t, sources, txntest.Group(&send, &appl), 9, ledger)
		logic.TestApps(t, rsources, txntest.Group(&appl, &send), 9, ledger)

		logic.TestApps(t, sources, txntest.Group(&send, &appl), 8, ledger,
			logic.NewExpect(1, "invalid Account reference"))
		logic.TestApps(t, rsources, txntest.Group(&appl, &send), 8, ledger,
			logic.NewExpect(0, "invalid Account reference"))
	}

	holdingAccess := `
	txn ApplicationArgs 0
	txn ApplicationArgs 1; btoi
	asset_holding_get AssetBalance
	pop; pop; int 1
`
	sources = []string{"", holdingAccess}
	rsources = []string{holdingAccess, ""}

	t.Run("keyreg", func(t *testing.T) {
		appl.ApplicationArgs = [][]byte{senderAcct[:], {200}}
		logic.TestApps(t, sources, txntest.Group(&keyreg, &appl), 9, ledger,
			logic.NewExpect(1, "invalid Asset reference 200"))
		withRef := appl
		withRef.ForeignAssets = []basics.AssetIndex{200}
		logic.TestApps(t, sources, txntest.Group(&keyreg, &withRef), 9, ledger,
			logic.NewExpect(1, "invalid Holding access "+senderAcct.String()))
	})
	t.Run("pay", func(t *testing.T) {
		// The receiver is available for algo balance reading
		appl.ApplicationArgs = [][]byte{receiverAcct[:]}
		logic.TestApps(t, []string{"", receiverBalance}, txntest.Group(&pay, &appl), 9, ledger)

		// The other account is not (it's not even in the pay txn)
		appl.ApplicationArgs = [][]byte{otherAcct[:]}
		logic.TestApps(t, []string{"", otherBalance}, txntest.Group(&pay, &appl), 9, ledger,
			logic.NewExpect(1, "invalid Account reference "+otherAcct.String()))

		// The other account becomes accessible because used in CloseRemainderTo
		withClose := pay
		withClose.CloseRemainderTo = otherAcct
		logic.TestApps(t, []string{"", otherBalance}, txntest.Group(&withClose, &appl), 9, ledger)
	})

	t.Run("acfg", func(t *testing.T) {
		// The other account is not available even though it's all the extra addresses
		appl.ApplicationArgs = [][]byte{otherAcct[:]}
		logic.TestApps(t, []string{"", otherBalance}, txntest.Group(&acfg, &appl), 9, ledger,
			logic.NewExpect(1, "invalid Account reference "+otherAcct.String()))
	})

	t.Run("axfer", func(t *testing.T) {
		// The receiver is also available for algo balance reading
		appl.ApplicationArgs = [][]byte{receiverAcct[:]}
		logic.TestApps(t, []string{"", receiverBalance}, txntest.Group(&axfer, &appl), 9, ledger)

		// as is the "other" (AssetSender)
		appl.ApplicationArgs = [][]byte{otherAcct[:]}
		logic.TestApps(t, []string{"", otherBalance}, txntest.Group(&axfer, &appl), 9, ledger)

		// receiver holding is available
		appl.ApplicationArgs = [][]byte{receiverAcct[:], {byte(axfer.XferAsset)}}
		logic.TestApps(t, []string{"", holdingAccess}, txntest.Group(&axfer, &appl), 9, ledger)

		// The other account becomes accessible because used in CloseRemainderTo
		// (for asa and algo)
		withClose := axfer
		withClose.AssetCloseTo = otherAcct
		appl.ApplicationArgs = [][]byte{otherAcct[:], {byte(axfer.XferAsset)}}
		logic.TestApps(t, []string{"", otherBalance}, txntest.Group(&withClose, &appl), 9, ledger)
		logic.TestApps(t, []string{"", holdingAccess}, txntest.Group(&withClose, &appl), 9, ledger)
	})

	t.Run("afrz", func(t *testing.T) {
		// The other account is available (for algo and asset)
		appl.ApplicationArgs = [][]byte{otherAcct[:], {byte(afrz.FreezeAsset)}}
		logic.TestApps(t, []string{"", otherBalance}, txntest.Group(&afrz, &appl), 9, ledger)
		logic.TestApps(t, []string{"", holdingAccess}, txntest.Group(&afrz, &appl), 9, ledger)
	})
}

// TestSharedInnerTxns checks how inner txns access resources.
func TestSharedInnerTxns(t *testing.T) {
	_, _, ledger := logic.MakeSampleEnv()

	const asa1 = 201
	const asa2 = 202

	senderAcct := basics.Address{1, 2, 3, 4, 5, 6, 1}
	ledger.NewAccount(senderAcct, 2001)
	ledger.NewHolding(senderAcct, asa1, 1, false)

	receiverAcct := basics.Address{1, 2, 3, 4, 5, 6, 2}
	ledger.NewAccount(receiverAcct, 2002)
	ledger.NewHolding(receiverAcct, asa1, 1, false)

	otherAcct := basics.Address{1, 2, 3, 4, 5, 6, 3}
	ledger.NewAccount(otherAcct, 2003)
	ledger.NewHolding(otherAcct, asa1, 1, false)

	unusedAcct := basics.Address{1, 2, 3, 4, 5, 6, 4}

	payToArg := `
itxn_begin
  int pay;               itxn_field TypeEnum
  int 100;               itxn_field Amount
  txn ApplicationArgs 0; itxn_field Receiver
itxn_submit
int 1
`
	axferToArgs := `
itxn_begin
  int axfer;                   itxn_field TypeEnum
  int 2;                       itxn_field AssetAmount
  txn ApplicationArgs 0;       itxn_field AssetReceiver
  txn ApplicationArgs 1; btoi; itxn_field XferAsset
itxn_submit
int 1
`

	appl := txntest.Txn{
		Type:   protocol.ApplicationCallTx,
		Sender: basics.Address{5, 5, 5, 5}, // different from all other accounts used
	}
	// App will do a lot of txns. Start well funded.
	ledger.NewAccount(basics.AppIndex(888).Address(), 1_000_000)
	// And needs some ASAs for inner axfer testing
	ledger.NewHolding(basics.AppIndex(888).Address(), asa1, 1_000_000, false)

	t.Run("keyreg", func(t *testing.T) {
		keyreg := txntest.Txn{
			Type:   protocol.KeyRegistrationTx,
			Sender: senderAcct,
		}

		// appl has no foreign ref to senderAcct, but can still inner pay it
		appl.ApplicationArgs = [][]byte{senderAcct[:]}
		logic.TestApps(t, []string{"", payToArg}, txntest.Group(&keyreg, &appl), 9, ledger)
		logic.TestApps(t, []string{"", payToArg}, txntest.Group(&keyreg, &appl), 8, ledger,
			logic.NewExpect(1, "invalid Account reference "+senderAcct.String()))

		// confirm you can't just pay _anybody_. receiverAcct is not in use at all.
		appl.ApplicationArgs = [][]byte{receiverAcct[:]}
		logic.TestApps(t, []string{"", payToArg}, txntest.Group(&keyreg, &appl), 9, ledger,
			logic.NewExpect(1, "invalid Account reference "+receiverAcct.String()))
	})

	t.Run("pay", func(t *testing.T) {
		pay := txntest.Txn{
			Type:     protocol.PaymentTx,
			Sender:   senderAcct,
			Receiver: receiverAcct,
		}

		// appl has no foreign ref to senderAcct or receiverAcct, but can still inner pay them
		appl.ApplicationArgs = [][]byte{senderAcct[:]}
		logic.TestApps(t, []string{"", payToArg}, txntest.Group(&pay, &appl), 9, ledger)
		logic.TestApps(t, []string{"", payToArg}, txntest.Group(&pay, &appl), 8, ledger,
			logic.NewExpect(1, "invalid Account reference "+senderAcct.String()))

		appl.ApplicationArgs = [][]byte{receiverAcct[:]}
		logic.TestApps(t, []string{"", payToArg}, txntest.Group(&pay, &appl), 9, ledger)
		logic.TestApps(t, []string{"", payToArg}, txntest.Group(&pay, &appl), 8, ledger,
			logic.NewExpect(1, "invalid Account reference "+receiverAcct.String()))

		// confirm you can't just pay _anybody_. otherAcct is not in use at all.
		appl.ApplicationArgs = [][]byte{otherAcct[:]}
		logic.TestApps(t, []string{"", payToArg}, txntest.Group(&pay, &appl), 9, ledger,
			logic.NewExpect(1, "invalid Account reference "+otherAcct.String()))
	})

	t.Run("axfer", func(t *testing.T) {
		axfer := txntest.Txn{
			Type:          protocol.AssetTransferTx,
			XferAsset:     asa1,
			Sender:        senderAcct,
			AssetReceiver: receiverAcct,
			AssetSender:   otherAcct,
		}

		// appl can pay or axfer to the sender
		appl.ApplicationArgs = [][]byte{senderAcct[:], {asa1}}
		logic.TestApps(t, []string{"", payToArg}, txntest.Group(&axfer, &appl), 9, ledger)
		logic.TestApps(t, []string{"", axferToArgs}, txntest.Group(&axfer, &appl), 9, ledger)
		// and to the receiver
		appl.ApplicationArgs = [][]byte{receiverAcct[:], {asa1}}
		logic.TestApps(t, []string{payToArg}, txntest.Group(&appl, &axfer), 9, ledger)
		logic.TestApps(t, []string{axferToArgs}, txntest.Group(&appl, &axfer), 9, ledger)
		// and to the clawback
		appl.ApplicationArgs = [][]byte{otherAcct[:], {asa1}}
		logic.TestApps(t, []string{"", payToArg}, txntest.Group(&axfer, &appl), 9, ledger)
		logic.TestApps(t, []string{"", axferToArgs}, txntest.Group(&axfer, &appl), 9, ledger)

		// but can't axfer a different asset
		appl.ApplicationArgs = [][]byte{senderAcct[:], {asa2}}
		logic.TestApps(t, []string{"", axferToArgs}, txntest.Group(&axfer, &appl), 9, ledger,
			logic.NewExpect(1, fmt.Sprintf("invalid Asset reference %d", asa2)))
		// or correct asset to an unknown address
		appl.ApplicationArgs = [][]byte{unusedAcct[:], {asa1}}
		logic.TestApps(t, []string{"", axferToArgs}, txntest.Group(&axfer, &appl), 9, ledger,
			logic.NewExpect(1, "invalid Account reference"))
	})

}
