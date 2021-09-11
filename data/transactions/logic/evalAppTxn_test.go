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

package logic

import (
	"fmt"
	"testing"

	"github.com/algorand/go-algorand/data/basics"
)

func TestActionTypes(t *testing.T) {
	ep, ledger := makeSampleEnv()
	testApp(t, "tx_submit; int 1;", ep, "tx_submit without tx_begin")
	testApp(t, "int pay; tx_field TypeEnum; tx_submit; int 1;", ep, "tx_field without tx_begin")
	testApp(t, "tx_begin; tx_submit; int 1;", ep, "Invalid inner transaction type")
	// bad type
	testApp(t, "tx_begin; byte \"pya\"; tx_field Type; tx_submit; int 1;", ep, "pya is not a valid Type")
	// mixed up the int form for the byte form
	testApp(t, obfuscate("tx_begin; int pay; tx_field Type; tx_submit; int 1;"), ep, "Type arg not a byte array")
	// or vice versa
	testApp(t, obfuscate("tx_begin; byte \"pay\"; tx_field TypeEnum; tx_submit; int 1;"), ep, "not a uint64")

	// good types, not alllowed yet
	testApp(t, "tx_begin; byte \"keyreg\"; tx_field Type; tx_submit; int 1;", ep, "keyreg is not a valid Type for tx_field")
	testApp(t, "tx_begin; byte \"appl\"; tx_field Type; tx_submit; int 1;", ep, "appl is not a valid Type for tx_field")
	// same, as enums
	testApp(t, "tx_begin; int keyreg; tx_field TypeEnum; tx_submit; int 1;", ep, "keyreg is not a valid Type for tx_field")
	testApp(t, "tx_begin; int appl; tx_field TypeEnum; tx_submit; int 1;", ep, "appl is not a valid Type for tx_field")
	testApp(t, "tx_begin; int 42; tx_field TypeEnum; tx_submit; int 1;", ep, "42 is not a valid TypeEnum")
	testApp(t, "tx_begin; int 0; tx_field TypeEnum; tx_submit; int 1;", ep, "0 is not a valid TypeEnum")

	// "insufficient balance" because app account is charged fee
	// (defaults make these 0 pay|axfer to zero address, from app account)
	testApp(t, "tx_begin; byte \"pay\"; tx_field Type; tx_submit; int 1;", ep, "insufficient balance")
	testApp(t, "tx_begin; byte \"axfer\"; tx_field Type; tx_submit; int 1;", ep, "insufficient balance")
	testApp(t, "tx_begin; int pay; tx_field TypeEnum; tx_submit; int 1;", ep, "insufficient balance")
	testApp(t, "tx_begin; int axfer; tx_field TypeEnum; tx_submit; int 1;", ep, "insufficient balance")

	testApp(t, "tx_begin; byte \"acfg\"; tx_field Type; tx_submit; int 1;", ep, "insufficient balance")
	testApp(t, "tx_begin; byte \"afrz\"; tx_field Type; tx_submit; int 1;", ep, "insufficient balance")
	testApp(t, "tx_begin; int acfg; tx_field TypeEnum; tx_submit; int 1;", ep, "insufficient balance")
	testApp(t, "tx_begin; int afrz; tx_field TypeEnum; tx_submit; int 1;", ep, "insufficient balance")

	// Establish 888 as the app id, and fund it.
	ledger.NewApp(ep.Txn.Txn.Receiver, 888, basics.AppParams{})
	ledger.NewAccount(basics.AppIndex(888).Address(), 200000)

	testApp(t, "tx_begin; byte \"pay\"; tx_field Type; tx_submit; int 1;", ep)
	testApp(t, "tx_begin; int pay; tx_field TypeEnum; tx_submit; int 1;", ep)
	// Can't submit because we haven't finished setup, but type passes tx_field
	testApp(t, "tx_begin; byte \"axfer\"; tx_field Type; int 1;", ep)
	testApp(t, "tx_begin; int axfer; tx_field TypeEnum; int 1;", ep)
	testApp(t, "tx_begin; byte \"acfg\"; tx_field Type; int 1;", ep)
	testApp(t, "tx_begin; int acfg; tx_field TypeEnum; int 1;", ep)
	testApp(t, "tx_begin; byte \"afrz\"; tx_field Type; int 1;", ep)
	testApp(t, "tx_begin; int afrz; tx_field TypeEnum; int 1;", ep)
}

func TestFieldTypes(t *testing.T) {
	ep, _ := makeSampleEnv()
	testApp(t, "tx_begin; byte \"pay\"; tx_field Sender;", ep, "not an address")
	testApp(t, obfuscate("tx_begin; int 7; tx_field Receiver;"), ep, "not an address")
	testApp(t, "tx_begin; byte \"\"; tx_field CloseRemainderTo;", ep, "not an address")
	testApp(t, "tx_begin; byte \"\"; tx_field AssetSender;", ep, "not an address")
	// can't really tell if it's an addres, so 32 bytes gets further
	testApp(t, "tx_begin; byte \"01234567890123456789012345678901\"; tx_field AssetReceiver;",
		ep, "invalid Account reference")
	// but a b32 string rep is not an account
	testApp(t, "tx_begin; byte \"GAYTEMZUGU3DOOBZGAYTEMZUGU3DOOBZGAYTEMZUGU3DOOBZGAYZIZD42E\"; tx_field AssetCloseTo;",
		ep, "not an address")

	testApp(t, obfuscate("tx_begin; byte \"pay\"; tx_field Fee;"), ep, "not a uint64")
	testApp(t, obfuscate("tx_begin; byte 0x01; tx_field Amount;"), ep, "not a uint64")
	testApp(t, obfuscate("tx_begin; byte 0x01; tx_field XferAsset;"), ep, "not a uint64")
	testApp(t, obfuscate("tx_begin; byte 0x01; tx_field AssetAmount;"), ep, "not a uint64")

}

func TestAppPay(t *testing.T) {
	pay := `
  tx_begin
  tx_field Amount
  tx_field Receiver
  tx_field Sender
  int pay
  tx_field TypeEnum
  tx_submit
  int 1
`

	ep, ledger := makeSampleEnv()
	ledger.NewApp(ep.Txn.Txn.Receiver, 888, basics.AppParams{})
	testApp(t, "txn Sender; balance; int 0; ==;", ep)
	testApp(t, "txn Sender; txn Accounts 1; int 100"+pay, ep, "unauthorized")
	testApp(t, "global CurrentApplicationAddress; txn Accounts 1; int 100"+pay, ep,
		"insufficient balance")
	ledger.NewAccount(ledger.ApplicationID().Address(), 1000000)

	// You might expect this to fail because of min balance issue
	// (receiving account only gets 100 microalgos).  It does not fail at
	// this level, instead, we must be certain that the existing min
	// balance check in eval.transaction() properly notices and fails
	// the transaction later.  This fits with the model that we check
	// min balances once at the end of each "top-level" transaction.
	testApp(t, "global CurrentApplicationAddress; txn Accounts 1; int 100"+pay, ep)

	// 100 of 1000000 spent, plus MinTxnFee in our fake protocol is 1001
	testApp(t, "global CurrentApplicationAddress; balance; int 998899; ==", ep)
	testApp(t, "txn Receiver; balance; int 100; ==", ep)

	close := `
  tx_begin
  int pay;      tx_field TypeEnum
  txn Receiver; tx_field CloseRemainderTo
  tx_submit
  int 1
`
	testApp(t, close, ep)
	testApp(t, "global CurrentApplicationAddress; balance; !", ep)
	// Receiver got most of the algos (except 1001 for fee)
	testApp(t, "txn Receiver; balance; int 997998; ==", ep)
}

func TestAppAssetOptIn(t *testing.T) {
	ep, ledger := makeSampleEnv()
	// Establish 888 as the app id, and fund it.
	ledger.NewApp(ep.Txn.Txn.Receiver, 888, basics.AppParams{})
	ledger.NewAccount(basics.AppIndex(888).Address(), 200000)

	axfer := `
tx_begin
int axfer;  tx_field TypeEnum;
int 25;     tx_field XferAsset;
int 2;      tx_field AssetAmount;
txn Sender; tx_field AssetReceiver;
tx_submit
int 1
`
	testApp(t, axfer, ep, "invalid Asset reference")
	ep.Txn.Txn.ForeignAssets = append(ep.Txn.Txn.ForeignAssets, 25)
	testApp(t, axfer, ep, "not opted in") // app account not opted in
	optin := `
tx_begin
int axfer; tx_field TypeEnum;
int 25;    tx_field XferAsset;
int 0;     tx_field AssetAmount;
global CurrentApplicationAddress; tx_field AssetReceiver;
tx_submit
int 1
`
	testApp(t, optin, ep, "does not exist")
	// Asset 25
	ledger.NewAsset(ep.Txn.Txn.Sender, 25, basics.AssetParams{
		Total:     10,
		UnitName:  "x",
		AssetName: "Cross",
	})
	testApp(t, optin, ep)

	testApp(t, axfer, ep, "insufficient balance") // opted in, but balance=0

	// Fund the app account with the asset
	ledger.NewHolding(basics.AppIndex(888).Address(), 25, 5, false)
	testApp(t, axfer, ep)
	testApp(t, axfer, ep)
	testApp(t, axfer, ep, "insufficient balance") // balance = 1, tried to move 2)
	testApp(t, "global CurrentApplicationAddress; int 25; asset_holding_get AssetBalance; assert; int 1; ==", ep)

	close := `
tx_begin
int axfer;  tx_field TypeEnum;
int 25;     tx_field XferAsset;
int 0;      tx_field AssetAmount;
txn Sender; tx_field AssetReceiver;
txn Sender; tx_field AssetCloseTo;
tx_submit
int 1
`
	testApp(t, close, ep)
	testApp(t, "global CurrentApplicationAddress; int 25; asset_holding_get AssetBalance; !; assert; !", ep)
}

func TestRekeyPay(t *testing.T) {
	pay := `
  tx_begin
  tx_field Amount
  tx_field Receiver
  tx_field Sender
  int pay
  tx_field TypeEnum
  tx_submit
`

	ep, ledger := makeSampleEnv()
	ledger.NewApp(ep.Txn.Txn.Receiver, 888, basics.AppParams{})
	testApp(t, "txn Sender; balance; int 0; ==;", ep)
	testApp(t, "txn Sender; txn Accounts 1; int 100"+pay, ep, "unauthorized")
	ledger.NewAccount(ep.Txn.Txn.Sender, 120+ep.Proto.MinTxnFee)
	ledger.Rekey(ep.Txn.Txn.Sender, basics.AppIndex(888).Address())
	testApp(t, "txn Sender; txn Accounts 1; int 100"+pay+"; int 1", ep)
	// Note that the Sender would fail min balance check if we did it here.
	// It seems proper to wait until end of txn though.
	// See explanation in logicLedger's Perform()
}

func TestDefaultSender(t *testing.T) {
	pay := `
  tx_begin
  tx_field Amount
  tx_field Receiver
  int pay
  tx_field TypeEnum
  tx_submit
`

	ep, ledger := makeSampleEnv()
	ledger.NewApp(ep.Txn.Txn.Receiver, 888, basics.AppParams{})
	ep.Txn.Txn.Accounts = append(ep.Txn.Txn.Accounts, ledger.ApplicationID().Address())
	testApp(t, "txn Accounts 1; int 100"+pay, ep, "insufficient balance")
	ledger.NewAccount(ledger.ApplicationID().Address(), 1000000)
	testApp(t, "txn Accounts 1; int 100"+pay+"int 1", ep)
	testApp(t, "global CurrentApplicationAddress; balance; int 998899; ==", ep)
}

func TestAppAxfer(t *testing.T) {
	axfer := `
  tx_begin
  int 77
  tx_field XferAsset
  tx_field AssetAmount
  tx_field AssetReceiver
  tx_field Sender
  int axfer
  tx_field TypeEnum
  tx_submit
`

	ep, ledger := makeSampleEnv()
	ledger.NewApp(ep.Txn.Txn.Receiver, 888, basics.AppParams{})
	ledger.NewAsset(ep.Txn.Txn.Receiver, 777, basics.AssetParams{}) // not in foreign-assets of sample
	ledger.NewAsset(ep.Txn.Txn.Receiver, 77, basics.AssetParams{})  // in foreign-assets of sample
	testApp(t, "txn Sender; int 777; asset_holding_get AssetBalance; assert; int 0; ==;", ep,
		"invalid Asset reference") // 777 not in foreign-assets
	testApp(t, "txn Sender; int 77; asset_holding_get AssetBalance; assert; int 0; ==;", ep,
		"assert failed") // because Sender not opted-in
	testApp(t, "global CurrentApplicationAddress; int 77; asset_holding_get AssetBalance; assert; int 0; ==;", ep,
		"assert failed") // app account not opted in

	ledger.NewAccount(ledger.ApplicationID().Address(), 10000) // plenty for fees
	ledger.NewHolding(ledger.ApplicationID().Address(), 77, 3000, false)
	testApp(t, "global CurrentApplicationAddress; int 77; asset_holding_get AssetBalance; assert; int 3000; ==;", ep)

	testApp(t, "txn Sender; txn Accounts 1; int 100"+axfer, ep, "unauthorized")
	testApp(t, "global CurrentApplicationAddress; txn Accounts 0; int 100"+axfer, ep,
		fmt.Sprintf("Receiver (%s) not opted in", ep.Txn.Txn.Sender)) // txn.Sender (receiver of the axfer) isn't opted in
	testApp(t, "global CurrentApplicationAddress; txn Accounts 1; int 100000"+axfer, ep,
		"insufficient balance")

	// Temporarily remove from ForeignAssets to ensure App Account
	// doesn't get some sort of free pass to send arbitrary assets.
	save := ep.Txn.Txn.ForeignAssets
	ep.Txn.Txn.ForeignAssets = []basics.AssetIndex{6, 10}
	testApp(t, "global CurrentApplicationAddress; txn Accounts 1; int 100000"+axfer, ep,
		"invalid Asset reference 77")
	ep.Txn.Txn.ForeignAssets = save

	noid := `
  tx_begin
  tx_field AssetAmount
  tx_field AssetReceiver
  tx_field Sender
  int axfer
  tx_field TypeEnum
  tx_submit
`
	testApp(t, "global CurrentApplicationAddress; txn Accounts 1; int 100"+noid+"int 1", ep,
		fmt.Sprintf("Sender (%s) not opted in to 0", ledger.ApplicationID().Address()))

	testApp(t, "global CurrentApplicationAddress; txn Accounts 1; int 100"+axfer+"int 1", ep)

	// 100 of 3000 spent
	testApp(t, "global CurrentApplicationAddress; int 77; asset_holding_get AssetBalance; assert; int 2900; ==", ep)
	testApp(t, "txn Accounts 1; int 77; asset_holding_get AssetBalance; assert; int 100; ==", ep)
}

func TestExtraFields(t *testing.T) {
	pay := `
  tx_begin
  int 7; tx_field AssetAmount;
  tx_field Amount
  tx_field Receiver
  tx_field Sender
  int pay
  tx_field TypeEnum
  tx_submit
`

	ep, ledger := makeSampleEnv()
	ledger.NewApp(ep.Txn.Txn.Receiver, 888, basics.AppParams{})
	testApp(t, "txn Sender; balance; int 0; ==;", ep)
	testApp(t, "txn Sender; txn Accounts 1; int 100"+pay, ep, "unauthorized")
	testApp(t, "global CurrentApplicationAddress; txn Accounts 1; int 100"+pay, ep,
		"non-zero fields for type axfer")
}

func TestBadField(t *testing.T) {
	pay := `
  tx_begin
  int 7; tx_field AssetAmount;
  tx_field Amount
  tx_field Receiver
  tx_field Sender
  int pay
  tx_field TypeEnum
  txn Receiver
  tx_field RekeyTo				// NOT ALLOWED
  tx_submit
`

	ep, ledger := makeSampleEnv()
	ledger.NewApp(ep.Txn.Txn.Receiver, 888, basics.AppParams{})
	testApp(t, "global CurrentApplicationAddress; txn Accounts 1; int 100"+pay, ep,
		"invalid tx_field RekeyTo")
}

func TestNumInner(t *testing.T) {
	pay := `
  tx_begin
  int 1
  tx_field Amount
  txn Accounts 1
  tx_field Receiver
  int pay
  tx_field TypeEnum
  tx_submit
`

	ep, ledger := makeSampleEnv()
	ledger.NewApp(ep.Txn.Txn.Receiver, 888, basics.AppParams{})
	ledger.NewAccount(ledger.ApplicationID().Address(), 1000000)
	testApp(t, pay+";int 1", ep)
	testApp(t, pay+pay+";int 1", ep)
	testApp(t, pay+pay+pay+";int 1", ep)
	testApp(t, pay+pay+pay+pay+";int 1", ep)
	// In the sample proto, MaxInnerTransactions = 4
	testApp(t, pay+pay+pay+pay+pay+";int 1", ep, "tx_submit with MaxInnerTransactions")
}

func TestAssetCreate(t *testing.T) {
	create := `
  tx_begin
  int acfg
  tx_field TypeEnum
  int 1000000
  tx_field ConfigAssetTotal
  int 3
  tx_field ConfigAssetDecimals
  byte "oz"
  tx_field ConfigAssetUnitName
  byte "Gold"
  tx_field ConfigAssetName
  byte "https:://gold.rush/"
  tx_field ConfigAssetURL
  tx_submit
  int 1
`
	ep, ledger := makeSampleEnv()
	ledger.NewApp(ep.Txn.Txn.Receiver, 888, basics.AppParams{})
	testApp(t, create, ep, "insufficient balance")
	// Give it enough for fee.  Recall that we don't check min balance at this level.
	ledger.NewAccount(ledger.ApplicationID().Address(), defaultEvalProto().MinTxnFee)
	testApp(t, create, ep)
}

func TestAssetFreeze(t *testing.T) {
	create := `
  tx_begin
  int acfg                         ; tx_field TypeEnum
  int 1000000                      ; tx_field ConfigAssetTotal
  int 3                            ; tx_field ConfigAssetDecimals
  byte "oz"                        ; tx_field ConfigAssetUnitName
  byte "Gold"                      ; tx_field ConfigAssetName
  byte "https:://gold.rush/"       ; tx_field ConfigAssetURL
  global CurrentApplicationAddress ; tx_field ConfigAssetFreeze;
  tx_submit
  int 1
`
	ep, ledger := makeSampleEnv()
	ledger.NewApp(ep.Txn.Txn.Receiver, 888, basics.AppParams{})
	// Give it enough for fees.  Recall that we don't check min balance at this level.
	ledger.NewAccount(ledger.ApplicationID().Address(), 12*defaultEvalProto().MinTxnFee)
	testApp(t, create, ep)

	freeze := `
  tx_begin
  int afrz        ; tx_field TypeEnum
  int 889         ; tx_field FreezeAsset
  int 1           ; tx_field FreezeAssetFrozen
  txn Accounts 1  ; tx_field FreezeAssetAccount
  tx_submit
  int 1
`
	testApp(t, freeze, ep, "invalid Asset reference")
	ep.Txn.Txn.ForeignAssets = []basics.AssetIndex{basics.AssetIndex(889)}
	testApp(t, freeze, ep, "does not hold Asset")
	ledger.NewHolding(ep.Txn.Txn.Receiver, 889, 55, false)
	testApp(t, freeze, ep)
}
