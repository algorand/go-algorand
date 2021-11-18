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
	"encoding/hex"
	"fmt"
	"strings"
	"testing"

	"github.com/algorand/go-algorand/data/basics"

	"github.com/stretchr/testify/require"
)

func TestInnerTypesV5(t *testing.T) {
	v5, _, _ := makeSampleEnvWithVersion(5)
	// not alllowed in v5
	testApp(t, "itxn_begin; byte \"keyreg\"; itxn_field Type; itxn_submit; int 1;", v5, "keyreg is not a valid Type for itxn_field")
	testApp(t, "itxn_begin; int keyreg; itxn_field TypeEnum; itxn_submit; int 1;", v5, "keyreg is not a valid Type for itxn_field")

	testApp(t, "itxn_begin; byte \"appl\"; itxn_field Type; itxn_submit; int 1;", v5, "appl is not a valid Type for itxn_field")
	testApp(t, "itxn_begin; int appl; itxn_field TypeEnum; itxn_submit; int 1;", v5, "appl is not a valid Type for itxn_field")
}

func TestCurrentInnerTypes(t *testing.T) {
	ep, tx, ledger := makeSampleEnv()
	testApp(t, "itxn_submit; int 1;", ep, "itxn_submit without itxn_begin")
	testApp(t, "int pay; itxn_field TypeEnum; itxn_submit; int 1;", ep, "itxn_field without itxn_begin")
	testApp(t, "itxn_begin; itxn_submit; int 1;", ep, "unknown tx type")
	// bad type
	testApp(t, "itxn_begin; byte \"pya\"; itxn_field Type; itxn_submit; int 1;", ep, "pya is not a valid Type")
	// mixed up the int form for the byte form
	testApp(t, obfuscate("itxn_begin; int pay; itxn_field Type; itxn_submit; int 1;"), ep, "Type arg not a byte array")
	// or vice versa
	testApp(t, obfuscate("itxn_begin; byte \"pay\"; itxn_field TypeEnum; itxn_submit; int 1;"), ep, "not a uint64")

	// some bad types
	testApp(t, "itxn_begin; int 42; itxn_field TypeEnum; itxn_submit; int 1;", ep, "42 is not a valid TypeEnum")
	testApp(t, "itxn_begin; int 0; itxn_field TypeEnum; itxn_submit; int 1;", ep, "0 is not a valid TypeEnum")

	// "insufficient balance" because app account is charged fee
	// (defaults make these 0 pay|axfer to zero address, from app account)
	testApp(t, "itxn_begin; byte \"pay\"; itxn_field Type; itxn_submit; int 1;", ep, "insufficient balance")
	testApp(t, "itxn_begin; byte \"axfer\"; itxn_field Type; itxn_submit; int 1;", ep, "insufficient balance")
	testApp(t, "itxn_begin; int pay; itxn_field TypeEnum; itxn_submit; int 1;", ep, "insufficient balance")
	testApp(t, "itxn_begin; int axfer; itxn_field TypeEnum; itxn_submit; int 1;", ep, "insufficient balance")

	testApp(t, "itxn_begin; byte \"acfg\"; itxn_field Type; itxn_submit; int 1;", ep, "insufficient balance")
	testApp(t, "itxn_begin; byte \"afrz\"; itxn_field Type; itxn_submit; int 1;", ep, "insufficient balance")
	testApp(t, "itxn_begin; int acfg; itxn_field TypeEnum; itxn_submit; int 1;", ep, "insufficient balance")
	testApp(t, "itxn_begin; int afrz; itxn_field TypeEnum; itxn_submit; int 1;", ep, "insufficient balance")

	// allowed since v6
	testApp(t, "itxn_begin; byte \"keyreg\"; itxn_field Type; itxn_submit; int 1;", ep, "insufficient balance")
	testApp(t, "itxn_begin; int keyreg; itxn_field TypeEnum; itxn_submit; int 1;", ep, "insufficient balance")
	testApp(t, "itxn_begin; byte \"appl\"; itxn_field Type; itxn_submit; int 1;", ep, "insufficient balance")
	testApp(t, "itxn_begin; int appl; itxn_field TypeEnum; itxn_submit; int 1;", ep, "insufficient balance")

	// Establish 888 as the app id, and fund it.
	ledger.NewApp(tx.Receiver, 888, basics.AppParams{})
	ledger.NewAccount(basics.AppIndex(888).Address(), 200000)

	testApp(t, "itxn_begin; byte \"pay\"; itxn_field Type; itxn_submit; int 1;", ep)
	testApp(t, "itxn_begin; int pay; itxn_field TypeEnum; itxn_submit; int 1;", ep)
	// Can't submit because we haven't finished setup, but type passes itxn_field
	testApp(t, "itxn_begin; byte \"axfer\"; itxn_field Type; int 1;", ep)
	testApp(t, "itxn_begin; int axfer; itxn_field TypeEnum; int 1;", ep)
	testApp(t, "itxn_begin; byte \"acfg\"; itxn_field Type; int 1;", ep)
	testApp(t, "itxn_begin; int acfg; itxn_field TypeEnum; int 1;", ep)
	testApp(t, "itxn_begin; byte \"afrz\"; itxn_field Type; int 1;", ep)
	testApp(t, "itxn_begin; int afrz; itxn_field TypeEnum; int 1;", ep)
}

func TestFieldTypes(t *testing.T) {
	ep, _, _ := makeSampleEnv()
	testApp(t, "itxn_begin; byte \"pay\"; itxn_field Sender;", ep, "not an address")
	testApp(t, obfuscate("itxn_begin; int 7; itxn_field Receiver;"), ep, "not an address")
	testApp(t, "itxn_begin; byte \"\"; itxn_field CloseRemainderTo;", ep, "not an address")
	testApp(t, "itxn_begin; byte \"\"; itxn_field AssetSender;", ep, "not an address")
	// can't really tell if it's an addres, so 32 bytes gets further
	testApp(t, "itxn_begin; byte \"01234567890123456789012345678901\"; itxn_field AssetReceiver;",
		ep, "invalid Account reference")
	// but a b32 string rep is not an account
	testApp(t, "itxn_begin; byte \"GAYTEMZUGU3DOOBZGAYTEMZUGU3DOOBZGAYTEMZUGU3DOOBZGAYZIZD42E\"; itxn_field AssetCloseTo;",
		ep, "not an address")

	testApp(t, obfuscate("itxn_begin; byte \"pay\"; itxn_field Fee;"), ep, "not a uint64")
	testApp(t, obfuscate("itxn_begin; byte 0x01; itxn_field Amount;"), ep, "not a uint64")
	testApp(t, obfuscate("itxn_begin; byte 0x01; itxn_field XferAsset;"), ep, "not a uint64")
	testApp(t, obfuscate("itxn_begin; byte 0x01; itxn_field AssetAmount;"), ep, "not a uint64")

}

func TestAppPay(t *testing.T) {
	pay := `
  itxn_begin
  itxn_field Amount
  itxn_field Receiver
  itxn_field Sender
  int pay
  itxn_field TypeEnum
  itxn_submit
  int 1
`

	ep, tx, ledger := makeSampleEnv()
	ledger.NewApp(tx.Receiver, 888, basics.AppParams{})
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
  itxn_begin
  int pay;      itxn_field TypeEnum
  txn Receiver; itxn_field CloseRemainderTo
  itxn_submit
  int 1
`
	testApp(t, close, ep)
	testApp(t, "global CurrentApplicationAddress; balance; !", ep)
	// Receiver got most of the algos (except 1001 for fee)
	testApp(t, "txn Receiver; balance; int 997998; ==", ep)
}

func TestAppAssetOptIn(t *testing.T) {
	ep, tx, ledger := makeSampleEnv()
	// Establish 888 as the app id, and fund it.
	ledger.NewApp(tx.Receiver, 888, basics.AppParams{})
	ledger.NewAccount(basics.AppIndex(888).Address(), 200000)

	axfer := `
itxn_begin
int axfer;  itxn_field TypeEnum;
int 25;     itxn_field XferAsset;
int 2;      itxn_field AssetAmount;
txn Sender; itxn_field AssetReceiver;
itxn_submit
int 1
`
	testApp(t, axfer, ep, "invalid Asset reference")
	tx.ForeignAssets = append(tx.ForeignAssets, 25)
	testApp(t, axfer, ep, "not opted in") // app account not opted in
	optin := `
itxn_begin
int axfer; itxn_field TypeEnum;
int 25;    itxn_field XferAsset;
int 0;     itxn_field AssetAmount;
global CurrentApplicationAddress; itxn_field AssetReceiver;
itxn_submit
int 1
`
	testApp(t, optin, ep, "does not exist")
	// Asset 25
	ledger.NewAsset(tx.Sender, 25, basics.AssetParams{
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
itxn_begin
int axfer;  itxn_field TypeEnum;
int 25;     itxn_field XferAsset;
int 0;      itxn_field AssetAmount;
txn Sender; itxn_field AssetReceiver;
txn Sender; itxn_field AssetCloseTo;
itxn_submit
int 1
`
	testApp(t, close, ep)
	testApp(t, "global CurrentApplicationAddress; int 25; asset_holding_get AssetBalance; !; assert; !", ep)
}

func TestRekeyPay(t *testing.T) {
	pay := `
  itxn_begin
  itxn_field Amount
  itxn_field Receiver
  itxn_field Sender
  int pay
  itxn_field TypeEnum
  itxn_submit
`

	ep, tx, ledger := makeSampleEnv()
	ledger.NewApp(tx.Receiver, 888, basics.AppParams{})
	testApp(t, "txn Sender; balance; int 0; ==;", ep)
	testApp(t, "txn Sender; txn Accounts 1; int 100"+pay, ep, "unauthorized")
	ledger.NewAccount(tx.Sender, 120+ep.Proto.MinTxnFee)
	ledger.Rekey(tx.Sender, basics.AppIndex(888).Address())
	testApp(t, "txn Sender; txn Accounts 1; int 100"+pay+"; int 1", ep)
	// Note that the Sender would fail min balance check if we did it here.
	// It seems proper to wait until end of txn though.
	// See explanation in logicLedger's Perform()
}

func TestRekeyBack(t *testing.T) {
	payAndUnkey := `
  itxn_begin
  itxn_field Amount
  itxn_field Receiver
  itxn_field Sender
  int pay
  itxn_field TypeEnum
  txn Sender
  itxn_field RekeyTo
  itxn_submit
`

	ep, tx, ledger := makeSampleEnv()
	ledger.NewApp(tx.Receiver, 888, basics.AppParams{})
	testApp(t, "txn Sender; balance; int 0; ==;", ep)
	testApp(t, "txn Sender; txn Accounts 1; int 100"+payAndUnkey, ep, "unauthorized")
	ledger.NewAccount(tx.Sender, 120+3*ep.Proto.MinTxnFee)
	ledger.Rekey(tx.Sender, basics.AppIndex(888).Address())
	testApp(t, "txn Sender; txn Accounts 1; int 100"+payAndUnkey+"; int 1", ep)
	// now rekeyed back to original
	testApp(t, "txn Sender; txn Accounts 1; int 100"+payAndUnkey, ep, "unauthorized")
}

func TestDefaultSender(t *testing.T) {
	pay := `
  itxn_begin
  itxn_field Amount
  itxn_field Receiver
  int pay
  itxn_field TypeEnum
  itxn_submit
`

	ep, tx, ledger := makeSampleEnv()
	ledger.NewApp(tx.Receiver, 888, basics.AppParams{})
	tx.Accounts = append(tx.Accounts, ledger.ApplicationID().Address())
	testApp(t, "txn Accounts 1; int 100"+pay, ep, "insufficient balance")
	ledger.NewAccount(ledger.ApplicationID().Address(), 1000000)
	testApp(t, "txn Accounts 1; int 100"+pay+"int 1", ep)
	testApp(t, "global CurrentApplicationAddress; balance; int 998899; ==", ep)
}

func TestAppAxfer(t *testing.T) {
	axfer := `
  itxn_begin
  int 77
  itxn_field XferAsset
  itxn_field AssetAmount
  itxn_field AssetReceiver
  itxn_field Sender
  int axfer
  itxn_field TypeEnum
  itxn_submit
`

	ep, tx, ledger := makeSampleEnv()
	ledger.NewApp(tx.Receiver, 888, basics.AppParams{})
	ledger.NewAsset(tx.Receiver, 777, basics.AssetParams{}) // not in foreign-assets of sample
	ledger.NewAsset(tx.Receiver, 77, basics.AssetParams{})  // in foreign-assets of sample
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
		fmt.Sprintf("Receiver (%s) not opted in", tx.Sender)) // txn.Sender (receiver of the axfer) isn't opted in
	testApp(t, "global CurrentApplicationAddress; txn Accounts 1; int 100000"+axfer, ep,
		"insufficient balance")

	// Temporarily remove from ForeignAssets to ensure App Account
	// doesn't get some sort of free pass to send arbitrary assets.
	save := tx.ForeignAssets
	tx.ForeignAssets = []basics.AssetIndex{6, 10}
	testApp(t, "global CurrentApplicationAddress; txn Accounts 1; int 100000"+axfer, ep,
		"invalid Asset reference 77")
	tx.ForeignAssets = save

	noid := `
  itxn_begin
  itxn_field AssetAmount
  itxn_field AssetReceiver
  itxn_field Sender
  int axfer
  itxn_field TypeEnum
  itxn_submit
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
  itxn_begin
  int 7; itxn_field AssetAmount;
  itxn_field Amount
  itxn_field Receiver
  itxn_field Sender
  int pay
  itxn_field TypeEnum
  itxn_submit
`

	ep, tx, ledger := makeSampleEnv()
	ledger.NewApp(tx.Receiver, 888, basics.AppParams{})
	testApp(t, "txn Sender; balance; int 0; ==;", ep)
	testApp(t, "txn Sender; txn Accounts 1; int 100"+pay, ep, "unauthorized")
	testApp(t, "global CurrentApplicationAddress; txn Accounts 1; int 100"+pay, ep,
		"non-zero fields for type axfer")
}

func TestBadFieldV5(t *testing.T) {
	pay := `
  itxn_begin
  int 7; itxn_field AssetAmount;
  itxn_field Amount
  itxn_field Receiver
  itxn_field Sender
  int pay
  itxn_field TypeEnum
  txn Receiver
  itxn_field Sender				// Will be changed to RekeyTo
  itxn_submit
`

	ep, tx, ledger := makeSampleEnvWithVersion(5)
	ledger.NewApp(tx.Receiver, 888, basics.AppParams{})
	// Assemble a good program, then change the field to a bad one
	ops := testProg(t, "global CurrentApplicationAddress; txn Accounts 1; int 100"+pay, 5)
	ops.Program[len(ops.Program)-2] = byte(RekeyTo)
	testAppBytes(t, ops.Program, ep, "invalid itxn_field RekeyTo")
}

func TestBadField(t *testing.T) {
	pay := `
  itxn_begin
  int 7; itxn_field AssetAmount;
  itxn_field Amount
  itxn_field Receiver
  itxn_field Sender
  int pay
  itxn_field TypeEnum
  txn Receiver
  itxn_field RekeyTo			// ALLOWED, since v6
  int 10
  itxn_field Amount				// Will be changed to FirstValid
  itxn_submit
`

	ep, tx, ledger := makeSampleEnv()
	ledger.NewApp(tx.Receiver, 888, basics.AppParams{})
	ops := testProg(t, "global CurrentApplicationAddress; txn Accounts 1; int 100"+pay, AssemblerMaxVersion)
	ops.Program[len(ops.Program)-2] = byte(FirstValid)
	testAppBytes(t, ops.Program, ep, "invalid itxn_field FirstValid")
}

func TestNumInner(t *testing.T) {
	pay := `
  itxn_begin
  int 1
  itxn_field Amount
  txn Accounts 1
  itxn_field Receiver
  int pay
  itxn_field TypeEnum
  itxn_submit
`

	ep, tx, ledger := makeSampleEnv()
	ledger.NewApp(tx.Receiver, 888, basics.AppParams{})
	ledger.NewAccount(ledger.ApplicationID().Address(), 1000000)
	testApp(t, pay+";int 1", ep)
	testApp(t, pay+pay+";int 1", ep)
	testApp(t, pay+pay+pay+";int 1", ep)
	testApp(t, pay+pay+pay+pay+";int 1", ep)
	// In the sample proto, MaxInnerTransactions = 4
	testApp(t, pay+pay+pay+pay+pay+";int 1", ep, "too many inner transactions")
}

func TestAssetCreate(t *testing.T) {
	create := `
  itxn_begin
  int acfg
  itxn_field TypeEnum
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
  itxn_submit
  int 1
`
	ep, tx, ledger := makeSampleEnv()
	ledger.NewApp(tx.Receiver, 888, basics.AppParams{})
	testApp(t, create, ep, "insufficient balance")
	// Give it enough for fee.  Recall that we don't check min balance at this level.
	ledger.NewAccount(ledger.ApplicationID().Address(), defaultEvalProto().MinTxnFee)
	testApp(t, create, ep)
}

func TestAssetFreeze(t *testing.T) {
	create := `
  itxn_begin
  int acfg                         ; itxn_field TypeEnum
  int 1000000                      ; itxn_field ConfigAssetTotal
  int 3                            ; itxn_field ConfigAssetDecimals
  byte "oz"                        ; itxn_field ConfigAssetUnitName
  byte "Gold"                      ; itxn_field ConfigAssetName
  byte "https://gold.rush/"        ; itxn_field ConfigAssetURL
  global CurrentApplicationAddress ; itxn_field ConfigAssetFreeze;
  itxn_submit
  itxn CreatedAssetID
  int 889
  ==
`
	ep, tx, ledger := makeSampleEnv()
	ledger.NewApp(tx.Receiver, 888, basics.AppParams{})
	// Give it enough for fees.  Recall that we don't check min balance at this level.
	ledger.NewAccount(ledger.ApplicationID().Address(), 12*defaultEvalProto().MinTxnFee)
	testApp(t, create, ep)

	freeze := `
  itxn_begin
  int afrz                    ; itxn_field TypeEnum
  int 889                     ; itxn_field FreezeAsset
  txn ApplicationArgs 0; btoi ; itxn_field FreezeAssetFrozen
  txn Accounts 1              ; itxn_field FreezeAssetAccount
  itxn_submit
  int 1
`
	testApp(t, freeze, ep, "invalid Asset reference")
	tx.ForeignAssets = []basics.AssetIndex{basics.AssetIndex(889)}
	tx.ApplicationArgs = [][]byte{{0x01}}
	testApp(t, freeze, ep, "does not hold Asset")
	ledger.NewHolding(tx.Receiver, 889, 55, false)
	testApp(t, freeze, ep)
	holding, err := ledger.AssetHolding(tx.Receiver, 889)
	require.NoError(t, err)
	require.Equal(t, true, holding.Frozen)
	tx.ApplicationArgs = [][]byte{{0x00}}
	testApp(t, freeze, ep)
	holding, err = ledger.AssetHolding(tx.Receiver, 889)
	require.NoError(t, err)
	require.Equal(t, false, holding.Frozen)
}

func TestFieldSetting(t *testing.T) {
	ep, tx, ledger := makeSampleEnv()
	ledger.NewApp(tx.Receiver, 888, basics.AppParams{})
	ledger.NewAccount(ledger.ApplicationID().Address(), 10*defaultEvalProto().MinTxnFee)
	testApp(t, "itxn_begin; int 500; bzero; itxn_field Note; int 1", ep)
	testApp(t, "itxn_begin; int 501; bzero; itxn_field Note; int 1", ep,
		"Note may not exceed")

	testApp(t, "itxn_begin; int 32; bzero; itxn_field VotePK; int 1", ep)
	testApp(t, "itxn_begin; int 31; bzero; itxn_field VotePK; int 1", ep,
		"VotePK must be 32")

	testApp(t, "itxn_begin; int 32; bzero; itxn_field SelectionPK; int 1", ep)
	testApp(t, "itxn_begin; int 33; bzero; itxn_field SelectionPK; int 1", ep,
		"SelectionPK must be 32")

	testApp(t, "itxn_begin; int 32; bzero; itxn_field RekeyTo; int 1", ep)
	testApp(t, "itxn_begin; int 31; bzero; itxn_field RekeyTo; int 1", ep,
		"not an address")

	testApp(t, "itxn_begin; int 6; bzero; itxn_field ConfigAssetUnitName; int 1", ep)
	testApp(t, "itxn_begin; int 7; bzero; itxn_field ConfigAssetUnitName; int 1", ep,
		"value is too long")

	testApp(t, "itxn_begin; int 12; bzero; itxn_field ConfigAssetName; int 1", ep)
	testApp(t, "itxn_begin; int 13; bzero; itxn_field ConfigAssetName; int 1", ep,
		"value is too long")
}

func TestInnerGroup(t *testing.T) {
	ep, tx, ledger := makeSampleEnv()
	ledger.NewApp(tx.Receiver, 888, basics.AppParams{})
	// Need both fees and both payments
	ledger.NewAccount(ledger.ApplicationID().Address(), 999+2*defaultEvalProto().MinTxnFee)
	pay := `
int pay;    itxn_field TypeEnum;
int 500;    itxn_field Amount;
txn Sender; itxn_field Receiver;
`
	testApp(t, "itxn_begin"+pay+"itxn_next"+pay+"itxn_submit; int 1", ep,
		"insufficient balance")

	// NewAccount overwrites the existing balance
	ledger.NewAccount(ledger.ApplicationID().Address(), 1000+2*defaultEvalProto().MinTxnFee)
	testApp(t, "itxn_begin"+pay+"itxn_next"+pay+"itxn_submit; int 1", ep)
}

func TestInnerFeePooling(t *testing.T) {
	ep, tx, ledger := makeSampleEnv()
	ledger.NewApp(tx.Receiver, 888, basics.AppParams{})
	ledger.NewAccount(ledger.ApplicationID().Address(), 50_000)
	pay := `
int pay;    itxn_field TypeEnum;
int 500;    itxn_field Amount;
txn Sender; itxn_field Receiver;
`
	// Force the first fee to 3, but the second will default to 2*fee-3 = 2002-3
	testApp(t, "itxn_begin"+
		pay+
		"int 3; itxn_field Fee;"+
		"itxn_next"+
		pay+
		"itxn_submit; itxn Fee; int 1999; ==", ep)

	// Same first, but force the second too low
	testApp(t, "itxn_begin"+
		pay+
		"int 3; itxn_field Fee;"+
		"itxn_next"+
		pay+
		"int 1998; itxn_field Fee;"+
		"itxn_submit; int 1", ep, "fee too small")

	// Overpay in first itxn, the second will default to less
	testApp(t, "itxn_begin"+
		pay+
		"int 2000; itxn_field Fee;"+
		"itxn_next"+
		pay+
		"itxn_submit; itxn Fee; int 2; ==", ep)

	// Same first, but force the second too low
	testApp(t, "itxn_begin"+
		pay+
		"int 2000; itxn_field Fee;"+
		"itxn_next"+
		pay+
		"int 1; itxn_field Fee;"+
		"itxn_submit; itxn Fee; int 1", ep, "fee too small")
}

// TestApplCreation is only determining what appl transactions can be
// constructed not what can be submitted, so it tests what "bad" fields cause
// immediate failures.
func TestApplCreation(t *testing.T) {
	ep, tx, _ := makeSampleEnv()

	p := "itxn_begin;"
	s := "; int 1"

	testApp(t, p+"int 31; itxn_field ApplicationID"+s, ep,
		"invalid App reference")
	tx.ForeignApps = append(tx.ForeignApps, 31)
	testApp(t, p+"int 31; itxn_field ApplicationID"+s, ep)

	testApp(t, p+"int 0; itxn_field OnCompletion"+s, ep)
	testApp(t, p+"int 1; itxn_field OnCompletion"+s, ep)
	testApp(t, p+"int 2; itxn_field OnCompletion"+s, ep)
	testApp(t, p+"int 3; itxn_field OnCompletion"+s, ep)
	testApp(t, p+"int 4; itxn_field OnCompletion"+s, ep)
	testApp(t, p+"int 5; itxn_field OnCompletion"+s, ep)
	testApp(t, p+"int 6; itxn_field OnCompletion"+s, ep, "6 is larger than max=5")
	testApp(t, p+"int NoOp; itxn_field OnCompletion"+s, ep)
	testApp(t, p+"int OptIn; itxn_field OnCompletion"+s, ep)
	testApp(t, p+"int CloseOut; itxn_field OnCompletion"+s, ep)
	testApp(t, p+"int ClearState; itxn_field OnCompletion"+s, ep)
	testApp(t, p+"int UpdateApplication; itxn_field OnCompletion"+s, ep)
	testApp(t, p+"int DeleteApplication; itxn_field OnCompletion"+s, ep)

	testApp(t, p+"int 800; bzero; itxn_field ApplicationArgs"+s, ep)
	testApp(t, p+"int 801; bzero; itxn_field ApplicationArgs", ep,
		"length too long")
	testApp(t, p+"int 401; bzero; dup; itxn_field ApplicationArgs; itxn_field ApplicationArgs", ep,
		"length too long")

	testApp(t, p+strings.Repeat("byte 0x11; itxn_field ApplicationArgs;", 12)+s, ep)
	testApp(t, p+strings.Repeat("byte 0x11; itxn_field ApplicationArgs;", 13)+s, ep,
		"too many application args")

	testApp(t, p+strings.Repeat("int 32; bzero; itxn_field Accounts;", 3)+s, ep,
		"invalid Account reference")
	tx.Accounts = append(tx.Accounts, basics.Address{})
	testApp(t, fmt.Sprintf(p+"%s"+s,
		strings.Repeat("int 32; bzero; itxn_field Accounts;", 3)), ep)
	testApp(t, fmt.Sprintf(p+"%s"+s,
		strings.Repeat("int 32; bzero; itxn_field Accounts;", 4)), ep,
		"too many foreign accounts")

	testApp(t, p+strings.Repeat("int 621; itxn_field Applications;", 5)+s, ep,
		"invalid App reference")
	tx.ForeignApps = append(tx.ForeignApps, basics.AppIndex(621))
	testApp(t, p+strings.Repeat("int 621; itxn_field Applications;", 5)+s, ep)
	testApp(t, p+strings.Repeat("int 621; itxn_field Applications;", 6)+s, ep,
		"too many foreign apps")

	testApp(t, p+strings.Repeat("int 621; itxn_field Assets;", 6)+s, ep,
		"invalid Asset reference")
	tx.ForeignAssets = append(tx.ForeignAssets, basics.AssetIndex(621))
	testApp(t, p+strings.Repeat("int 621; itxn_field Assets;", 6)+s, ep)
	testApp(t, p+strings.Repeat("int 621; itxn_field Assets;", 7)+s, ep,
		"too many foreign assets")

	testApp(t, p+"int 2700; bzero; itxn_field ApprovalProgram"+s, ep)
	testApp(t, p+"int 2701; bzero; itxn_field ApprovalProgram"+s, ep,
		"may not exceed 2700")
	testApp(t, p+"int 2700; bzero; itxn_field ClearStateProgram"+s, ep)
	testApp(t, p+"int 2701; bzero; itxn_field ClearStateProgram"+s, ep,
		"may not exceed 2700")

	testApp(t, p+"int 30; itxn_field GlobalNumUint"+s, ep)
	testApp(t, p+"int 31; itxn_field GlobalNumUint"+s, ep, "31 is larger than max=30")
	testApp(t, p+"int 30; itxn_field GlobalNumByteSlice"+s, ep)
	testApp(t, p+"int 31; itxn_field GlobalNumByteSlice"+s, ep, "31 is larger than max=30")
	testApp(t, p+"int 20; itxn_field GlobalNumUint; int 11; itxn_field GlobalNumByteSlice"+s, ep)

	testApp(t, p+"int 13; itxn_field LocalNumUint"+s, ep)
	testApp(t, p+"int 14; itxn_field LocalNumUint"+s, ep, "14 is larger than max=13")
	testApp(t, p+"int 13; itxn_field LocalNumByteSlice"+s, ep)
	testApp(t, p+"int 14; itxn_field LocalNumByteSlice"+s, ep, "14 is larger than max=13")

	testApp(t, p+"int 2; itxn_field ExtraProgramPages"+s, ep)
	testApp(t, p+"int 3; itxn_field ExtraProgramPages"+s, ep, "3 is larger than max=2")
}

// TestApplSubmission tests for checking of illegal appl transaction in form
// only.  Things where interactions between two different fields causes the
// error.  These are not exhaustive, but certainly demonstrate that WellFormed
// is getting a crack at the txn.
func TestApplSubmission(t *testing.T) {
	ep, tx, ledger := makeSampleEnv()
	ledger.NewApp(tx.Receiver, 888, basics.AppParams{})
	// Since the fee is moved first, fund the app
	ledger.NewAccount(ledger.ApplicationID().Address(), 50_000)

	ops := testProg(t, "int 1", AssemblerMaxVersion)
	approve := hex.EncodeToString(ops.Program)
	a := fmt.Sprintf("byte 0x%s; itxn_field ApprovalProgram;", approve)

	p := "itxn_begin; int appl; itxn_field TypeEnum;"
	s := ";itxn_submit; int 1"
	testApp(t, p+a+s, ep)

	// All zeros is v0, so we get a complaint, but that means lengths were ok.
	testApp(t, p+a+`int 600; bzero; itxn_field ApprovalProgram;
                  int 600; bzero; itxn_field ClearStateProgram;`+s, ep,
		"program version must be")

	testApp(t, p+`int 601; bzero; itxn_field ApprovalProgram;
                  int 600; bzero; itxn_field ClearStateProgram;`+s, ep, "too long")

	// WellFormed does the math based on the supplied ExtraProgramPages
	testApp(t, p+a+`int 1; itxn_field ExtraProgramPages
                  int 1200; bzero; itxn_field ApprovalProgram;
                  int 1200; bzero; itxn_field ClearStateProgram;`+s, ep,
		"program version must be")
	testApp(t, p+`int 1; itxn_field ExtraProgramPages
                  int 1200; bzero; itxn_field ApprovalProgram;
                  int 1201; bzero; itxn_field ClearStateProgram;`+s, ep, "too long")

	// Can't set epp when app id is given
	tx.ForeignApps = append(tx.ForeignApps, basics.AppIndex(7))
	testApp(t, p+`int 1; itxn_field ExtraProgramPages;
                  int 7; itxn_field ApplicationID`+s, ep, "immutable")

	testApp(t, p+"int 20; itxn_field GlobalNumUint; int 11; itxn_field GlobalNumByteSlice"+s,
		ep, "too large")
	testApp(t, p+"int 7; itxn_field LocalNumUint; int 7; itxn_field LocalNumByteSlice"+s,
		ep, "too large")
}

func TestInnerApplCreate(t *testing.T) {
	ep, tx, ledger := makeSampleEnv()
	ledger.NewApp(tx.Receiver, 888, basics.AppParams{})
	ledger.NewAccount(ledger.ApplicationID().Address(), 50_000)

	ops := testProg(t, "int 1", AssemblerMaxVersion)
	approve := "byte 0x" + hex.EncodeToString(ops.Program)

	testApp(t, `
itxn_begin
int appl;    itxn_field TypeEnum
`+approve+`; itxn_field ApprovalProgram
`+approve+`; itxn_field ClearStateProgram
int 1;       itxn_field GlobalNumUint
int 2;       itxn_field LocalNumByteSlice
int 3;       itxn_field LocalNumUint
itxn_submit
int 1
`, ep)
	// In testing, creating an app sets the "current app". So reset it.
	ledger.SetApp(888)

	testApp(t, `
int 889; app_params_get AppGlobalNumByteSlice; assert; int 0; ==; assert
`, ep, "invalid App reference")

	call := `
itxn_begin
int appl;              itxn_field TypeEnum
int 889;               itxn_field ApplicationID
itxn_submit
int 1
`
	// Can't call it either
	testApp(t, call, ep, "invalid App reference")

	tx.ForeignApps = []basics.AppIndex{basics.AppIndex(889)}
	testApp(t, `
int 889; app_params_get AppGlobalNumByteSlice; assert; int 0; ==; assert
int 889; app_params_get AppGlobalNumUint;      assert; int 1; ==; assert
int 889; app_params_get AppLocalNumByteSlice;  assert; int 2; ==; assert
int 889; app_params_get AppLocalNumUint;       assert; int 3; ==; assert
int 1
`, ep)

	// Call it (default OnComplete is NoOp)
	testApp(t, call, ep)

	testApp(t, `
itxn_begin
int appl;              itxn_field TypeEnum
int DeleteApplication; itxn_field OnCompletion
txn Applications 1;    itxn_field ApplicationID
itxn_submit
int 1
`, ep)

	// App is gone
	testApp(t, `
int 889; app_params_get AppGlobalNumByteSlice; !; assert; !; assert; int 1
`, ep)

	// Can't call it either
	testApp(t, call, ep, "No application")

}

func TestCreateOldAppFails(t *testing.T) {
	ep, tx, ledger := makeSampleEnv()
	ledger.NewApp(tx.Receiver, 888, basics.AppParams{})
	ledger.NewAccount(ledger.ApplicationID().Address(), 50_000)

	ops := testProg(t, "int 1", innerAppsEnabledVersion-1)
	approve := "byte 0x" + hex.EncodeToString(ops.Program)

	testApp(t, `
itxn_begin
int appl;    itxn_field TypeEnum
`+approve+`; itxn_field ApprovalProgram
`+approve+`; itxn_field ClearStateProgram
int 1;       itxn_field GlobalNumUint
int 2;       itxn_field LocalNumByteSlice
int 3;       itxn_field LocalNumUint
itxn_submit
int 1
`, ep, "program version must be >=")
}

func TestSelfReentrancy(t *testing.T) {
	ep, tx, ledger := makeSampleEnv()
	ledger.NewApp(tx.Receiver, 888, basics.AppParams{})
	ledger.NewAccount(ledger.ApplicationID().Address(), 50_000)

	testApp(t, `
itxn_begin
int appl;    itxn_field TypeEnum
int 888;     itxn_field ApplicationID
itxn_submit
int 1
`, ep, "attempt to re-enter 888")
}

func TestIndirectReentrancy(t *testing.T) {
	ep, tx, ledger := makeSampleEnv()
	call888 := testProg(t, `itxn_begin
int appl;    itxn_field TypeEnum
int 888;     itxn_field ApplicationID
itxn_submit
int 1
`, AssemblerMaxVersion)
	ledger.NewApp(tx.Receiver, 222, basics.AppParams{
		ApprovalProgram: call888.Program,
	})

	ledger.NewApp(tx.Receiver, 888, basics.AppParams{})
	ledger.NewAccount(ledger.ApplicationID().Address(), 50_000)
	tx.ForeignApps = []basics.AppIndex{basics.AppIndex(222)}
	testApp(t, `
itxn_begin
int appl;    itxn_field TypeEnum
int 222;     itxn_field ApplicationID
itxn_submit
int 1
`, ep, "attempt to re-enter 888")
}

// TestInnerBudgetIncrement ensures that an app can make a (nearly) empty inner
// app call in order to get 700 extra opcode budget.  Unfortunately, it costs a
// bit to create the call, and the app itself consumes a little, so it's more
// like 690 or so.
func TestInnerBudgetIncrement(t *testing.T) {
	ep, tx, ledger := makeSampleEnv()
	gasup := testProg(t, "pushint 1", AssemblerMaxVersion)
	ledger.NewApp(tx.Receiver, 222, basics.AppParams{
		ApprovalProgram: gasup.Program,
	})

	waste := `global CurrentApplicationAddress; keccak256; pop;`
	buy := `itxn_begin
int appl;    itxn_field TypeEnum
int 222;     itxn_field ApplicationID
itxn_submit;
`

	ledger.NewApp(tx.Receiver, 888, basics.AppParams{})
	ledger.NewAccount(ledger.ApplicationID().Address(), 50_000)
	tx.ForeignApps = []basics.AppIndex{basics.AppIndex(222)}
	testApp(t, strings.Repeat(waste, 5)+"int 1", ep)
	testApp(t, strings.Repeat(waste, 6)+"int 1", ep, "dynamic cost budget exceeded")
	testApp(t, strings.Repeat(waste, 6)+buy+"int 1", ep, "dynamic cost budget exceeded")
	testApp(t, buy+strings.Repeat(waste, 6)+"int 1", ep)
	testApp(t, buy+strings.Repeat(waste, 10)+"int 1", ep)
	testApp(t, buy+strings.Repeat(waste, 12)+"int 1", ep, "dynamic cost budget exceeded")
	testApp(t, buy+strings.Repeat(waste, 12)+"int 1", ep, "dynamic cost budget exceeded")
	testApp(t, buy+buy+strings.Repeat(waste, 12)+"int 1", ep)
}

// TestInnerTxIDs confirms that TxIDs are available and different
func TestInnerTxIDs(t *testing.T) {
	ep, tx, ledger := makeSampleEnv()
	txid := testProg(t, "txn TxID; log; int 1", AssemblerMaxVersion)
	ledger.NewApp(tx.Receiver, 222, basics.AppParams{
		ApprovalProgram: txid.Program,
	})
	ledger.NewApp(tx.Receiver, 888, basics.AppParams{})
	ledger.NewAccount(ledger.ApplicationID().Address(), 50_000)
	tx.ForeignApps = []basics.AppIndex{basics.AppIndex(222)}
	testApp(t, `
itxn_begin
int appl;    itxn_field TypeEnum
int 222;     itxn_field ApplicationID
itxn_submit;
itxn Logs 0

itxn_begin
int appl;    itxn_field TypeEnum
int 222;     itxn_field ApplicationID
itxn_submit;
itxn Logs 0

!=
`, ep)
}

// TestInnerGroupIDs confirms that GroupIDs are unset on size one inner groups,
// but set and unique on non-singletons
func TestInnerGroupIDs(t *testing.T) {
	ep, tx, ledger := makeSampleEnv()
	gid := testProg(t, "global GroupID; log; int 1", AssemblerMaxVersion)
	ledger.NewApp(tx.Receiver, 222, basics.AppParams{
		ApprovalProgram: gid.Program,
	})
	ledger.NewApp(tx.Receiver, 888, basics.AppParams{})
	ledger.NewAccount(ledger.ApplicationID().Address(), 50_000)
	tx.ForeignApps = []basics.AppIndex{basics.AppIndex(222)}

	// A single txn gets 0 group id
	testApp(t, `
itxn_begin
int appl;    itxn_field TypeEnum
int 222;     itxn_field ApplicationID
itxn_submit;
itxn Logs 0
global ZeroAddress
==
`, ep)

	// A double calls gets something else
	testApp(t, `
itxn_begin
int appl;    itxn_field TypeEnum
int 222;     itxn_field ApplicationID
itxn_next
int appl;    itxn_field TypeEnum
int 222;     itxn_field ApplicationID
itxn_submit;
itxn Logs 0
global ZeroAddress
!=
`, ep)

	// The "something else" is unique, despite two identical groups
	testApp(t, `
itxn_begin
int appl;    itxn_field TypeEnum
int 222;     itxn_field ApplicationID
itxn_next
int appl;    itxn_field TypeEnum
int 222;     itxn_field ApplicationID
itxn_submit;
itxn Logs 0

itxn_begin
int appl;    itxn_field TypeEnum
int 222;     itxn_field ApplicationID
itxn_next
int appl;    itxn_field TypeEnum
int 222;     itxn_field ApplicationID
itxn_submit;
itxn Logs 0

!=
`, ep)
}

// TestGtixn confirms access to itxn groups
func TestGtixn(t *testing.T) {
	ep, tx, ledger := makeSampleEnv()
	two := testProg(t, "byte 0x22; log; int 1", AssemblerMaxVersion)
	ledger.NewApp(tx.Receiver, 222, basics.AppParams{
		ApprovalProgram: two.Program,
	})
	three := testProg(t, "byte 0x33; log; int 1", AssemblerMaxVersion)
	ledger.NewApp(tx.Receiver, 333, basics.AppParams{
		ApprovalProgram: three.Program,
	})
	four := testProg(t, "byte 0x44; log; int 1", AssemblerMaxVersion)
	ledger.NewApp(tx.Receiver, 444, basics.AppParams{
		ApprovalProgram: four.Program,
	})

	ledger.NewApp(tx.Receiver, 888, basics.AppParams{})
	ledger.NewAccount(ledger.ApplicationID().Address(), 50_000)
	tx.ForeignApps = []basics.AppIndex{basics.AppIndex(222), basics.AppIndex(333), basics.AppIndex(444)}

	testApp(t, `
itxn_begin
int appl;    itxn_field TypeEnum
int 222;     itxn_field ApplicationID
itxn_next
int appl;    itxn_field TypeEnum
int 333;     itxn_field ApplicationID
itxn_submit;
gitxn 0 Logs 0
byte 0x22
==
assert

gitxna 1 Logs 0
byte 0x33
==
assert

itxn_begin
int appl;    itxn_field TypeEnum
int 444;     itxn_field ApplicationID
itxn_next
int appl;    itxn_field TypeEnum
int 222;     itxn_field ApplicationID
itxn_submit;

gitxn 0 Logs 0
byte 0x44
==
assert

gitxn 1 Logs 0
byte 0x22
==
assert

int 1
`, ep)

	// Confirm that two singletons don't get treated as a group
	testApp(t, `
itxn_begin
int appl;    itxn_field TypeEnum
int 222;     itxn_field ApplicationID
itxn_submit

itxn_begin
int appl;    itxn_field TypeEnum
int 333;     itxn_field ApplicationID
itxn_submit
gitxn 0 Logs 0
byte 0x33
==
assert
int 1
`, ep)
}

// TestGtxnLog confirms that gtxn can now access previous txn's Logs.
func TestGtxnLog(t *testing.T) {
	ep, tx, ledger := makeSampleEnv()
	two := testProg(t, "byte 0x22; log; int 1", AssemblerMaxVersion)
	ledger.NewApp(tx.Receiver, 222, basics.AppParams{
		ApprovalProgram: two.Program,
	})
	three := testProg(t, "gtxn 0 NumLogs; int 1; ==; assert; gtxna 0 Logs 0; byte 0x22; ==", AssemblerMaxVersion)
	ledger.NewApp(tx.Receiver, 333, basics.AppParams{
		ApprovalProgram: three.Program,
	})

	ledger.NewApp(tx.Receiver, 888, basics.AppParams{})
	ledger.NewAccount(ledger.ApplicationID().Address(), 50_000)
	tx.ForeignApps = []basics.AppIndex{basics.AppIndex(222), basics.AppIndex(333)}

	testApp(t, `itxn_begin
int appl;    itxn_field TypeEnum
int 222;     itxn_field ApplicationID
itxn_next
int appl;    itxn_field TypeEnum
int 333;     itxn_field ApplicationID
itxn_submit
int 1
`, ep)
}

// TestGtxnApps confirms that gtxn can now access previous txn's created app id.
func TestGtxnApps(t *testing.T) {
	ep, tx, ledger := makeSampleEnv()
	appcheck := testProg(t, `
gtxn 0 CreatedApplicationID; itob; log;
gtxn 1 CreatedApplicationID; itob; log;
int 1
`, AssemblerMaxVersion)
	ledger.NewApp(tx.Receiver, 222, basics.AppParams{
		ApprovalProgram: appcheck.Program,
	})

	ops := testProg(t, "int 1", AssemblerMaxVersion)

	ledger.NewApp(tx.Receiver, 888, basics.AppParams{})
	ledger.NewAccount(ledger.ApplicationID().Address(), 50_000)
	tx.ForeignApps = []basics.AppIndex{basics.AppIndex(222)}
	testApp(t, `itxn_begin
int appl;    itxn_field TypeEnum
	`+fmt.Sprintf("byte 0x%s; itxn_field ApprovalProgram;", hex.EncodeToString(ops.Program))+`
itxn_next
int appl;    itxn_field TypeEnum
	`+fmt.Sprintf("byte 0x%s; itxn_field ApprovalProgram;", hex.EncodeToString(ops.Program))+`
itxn_next
int appl;    itxn_field TypeEnum
int 222;     itxn_field ApplicationID
itxn_submit
itxn Logs 0
btoi
int 889
==
assert
gitxn 2 Logs 1
btoi
int 890
==
`, ep)
}

// TestGtxnAsa confirms that gtxn can now access previous txn's created asa id.
func TestGtxnAsa(t *testing.T) {
	ep, tx, ledger := makeSampleEnv()
	appcheck := testProg(t, `
gtxn 0 CreatedAssetID; itob; log;
gtxn 1 CreatedAssetID; itob; log;
int 1
`, AssemblerMaxVersion)
	ledger.NewApp(tx.Receiver, 222, basics.AppParams{
		ApprovalProgram: appcheck.Program,
	})

	ledger.NewApp(tx.Receiver, 888, basics.AppParams{})
	ledger.NewAccount(ledger.ApplicationID().Address(), 50_000)
	tx.ForeignApps = []basics.AppIndex{basics.AppIndex(222)}
	testApp(t, `itxn_begin
int acfg;    itxn_field TypeEnum
itxn_next
int acfg;    itxn_field TypeEnum
itxn_next
int appl;    itxn_field TypeEnum
int 222;     itxn_field ApplicationID
itxn_submit
itxn Logs 0
btoi
int 889
==
assert
gitxn 2 Logs 1
btoi
int 890
==
`, ep)
}
