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

package logic_test

import (
	"encoding/hex"
	"fmt"
	"strings"
	"testing"

	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/transactions"
	. "github.com/algorand/go-algorand/data/transactions/logic"
	"github.com/algorand/go-algorand/data/txntest"
	"github.com/algorand/go-algorand/protocol"

	"github.com/stretchr/testify/require"
)

func TestInnerTypesV5(t *testing.T) {
	v5, _, _ := MakeSampleEnvWithVersion(5)
	// not alllowed in v5
	TestApp(t, "itxn_begin; byte \"keyreg\"; itxn_field Type; itxn_submit; int 1;", v5, "keyreg is not a valid Type for itxn_field")
	TestApp(t, "itxn_begin; int keyreg; itxn_field TypeEnum; itxn_submit; int 1;", v5, "keyreg is not a valid Type for itxn_field")

	TestApp(t, "itxn_begin; byte \"appl\"; itxn_field Type; itxn_submit; int 1;", v5, "appl is not a valid Type for itxn_field")
	TestApp(t, "itxn_begin; int appl; itxn_field TypeEnum; itxn_submit; int 1;", v5, "appl is not a valid Type for itxn_field")
}

func TestCurrentInnerTypes(t *testing.T) {
	ep, tx, ledger := MakeSampleEnv()
	TestApp(t, "itxn_submit; int 1;", ep, "itxn_submit without itxn_begin")
	TestApp(t, "int pay; itxn_field TypeEnum; itxn_submit; int 1;", ep, "itxn_field without itxn_begin")
	TestApp(t, "itxn_begin; itxn_submit; int 1;", ep, "unknown tx type")
	// bad type
	TestApp(t, "itxn_begin; byte \"pya\"; itxn_field Type; itxn_submit; int 1;", ep, "pya is not a valid Type")
	// mixed up the int form for the byte form
	TestApp(t, Obfuscate("itxn_begin; int pay; itxn_field Type; itxn_submit; int 1;"), ep, "Type arg not a byte array")
	// or vice versa
	TestApp(t, Obfuscate("itxn_begin; byte \"pay\"; itxn_field TypeEnum; itxn_submit; int 1;"), ep, "not a uint64")

	// some bad types
	TestApp(t, "itxn_begin; int 42; itxn_field TypeEnum; itxn_submit; int 1;", ep, "42 is not a valid TypeEnum")
	TestApp(t, "itxn_begin; int 0; itxn_field TypeEnum; itxn_submit; int 1;", ep, "0 is not a valid TypeEnum")

	// "insufficient balance" because app account is charged fee
	// (defaults make these 0 pay|axfer to zero address, from app account)
	TestApp(t, "itxn_begin; byte \"pay\"; itxn_field Type; itxn_submit; int 1;", ep, "insufficient balance")
	TestApp(t, "itxn_begin; byte \"axfer\"; itxn_field Type; itxn_submit; int 1;", ep, "insufficient balance")
	TestApp(t, "itxn_begin; int pay; itxn_field TypeEnum; itxn_submit; int 1;", ep, "insufficient balance")
	TestApp(t, "itxn_begin; int axfer; itxn_field TypeEnum; itxn_submit; int 1;", ep, "insufficient balance")

	TestApp(t, "itxn_begin; byte \"acfg\"; itxn_field Type; itxn_submit; int 1;", ep, "insufficient balance")
	TestApp(t, "itxn_begin; byte \"afrz\"; itxn_field Type; itxn_submit; int 1;", ep, "insufficient balance")
	TestApp(t, "itxn_begin; int acfg; itxn_field TypeEnum; itxn_submit; int 1;", ep, "insufficient balance")
	TestApp(t, "itxn_begin; int afrz; itxn_field TypeEnum; itxn_submit; int 1;", ep, "insufficient balance")

	// allowed since v6
	TestApp(t, "itxn_begin; byte \"keyreg\"; itxn_field Type; itxn_submit; int 1;", ep, "insufficient balance")
	TestApp(t, "itxn_begin; int keyreg; itxn_field TypeEnum; itxn_submit; int 1;", ep, "insufficient balance")
	TestApp(t, "itxn_begin; byte \"appl\"; itxn_field Type; itxn_submit; int 1;", ep, "insufficient balance")
	TestApp(t, "itxn_begin; int appl; itxn_field TypeEnum; itxn_submit; int 1;", ep, "insufficient balance")

	// Establish 888 as the app id, and fund it.
	ledger.NewApp(tx.Receiver, 888, basics.AppParams{})
	ledger.NewAccount(basics.AppIndex(888).Address(), 200000)

	TestApp(t, "itxn_begin; byte \"pay\"; itxn_field Type; itxn_submit; int 1;", ep)
	TestApp(t, "itxn_begin; int pay; itxn_field TypeEnum; itxn_submit; int 1;", ep)
	// Can't submit because we haven't finished setup, but type passes itxn_field
	TestApp(t, "itxn_begin; byte \"axfer\"; itxn_field Type; int 1;", ep)
	TestApp(t, "itxn_begin; int axfer; itxn_field TypeEnum; int 1;", ep)
	TestApp(t, "itxn_begin; byte \"acfg\"; itxn_field Type; int 1;", ep)
	TestApp(t, "itxn_begin; int acfg; itxn_field TypeEnum; int 1;", ep)
	TestApp(t, "itxn_begin; byte \"afrz\"; itxn_field Type; int 1;", ep)
	TestApp(t, "itxn_begin; int afrz; itxn_field TypeEnum; int 1;", ep)
}

func TestFieldTypes(t *testing.T) {
	ep, _, _ := MakeSampleEnv()
	TestApp(t, "itxn_begin; byte \"pay\"; itxn_field Sender;", ep, "not an address")
	TestApp(t, Obfuscate("itxn_begin; int 7; itxn_field Receiver;"), ep, "not an address")
	TestApp(t, "itxn_begin; byte \"\"; itxn_field CloseRemainderTo;", ep, "not an address")
	TestApp(t, "itxn_begin; byte \"\"; itxn_field AssetSender;", ep, "not an address")
	// can't really tell if it's an addres, so 32 bytes gets further
	TestApp(t, "itxn_begin; byte \"01234567890123456789012345678901\"; itxn_field AssetReceiver;",
		ep, "invalid Account reference")
	// but a b32 string rep is not an account
	TestApp(t, "itxn_begin; byte \"GAYTEMZUGU3DOOBZGAYTEMZUGU3DOOBZGAYTEMZUGU3DOOBZGAYZIZD42E\"; itxn_field AssetCloseTo;",
		ep, "not an address")

	TestApp(t, Obfuscate("itxn_begin; byte \"pay\"; itxn_field Fee;"), ep, "not a uint64")
	TestApp(t, Obfuscate("itxn_begin; byte 0x01; itxn_field Amount;"), ep, "not a uint64")
	TestApp(t, Obfuscate("itxn_begin; byte 0x01; itxn_field XferAsset;"), ep, "not a uint64")
	TestApp(t, Obfuscate("itxn_begin; byte 0x01; itxn_field AssetAmount;"), ep, "not a uint64")

}

func appAddr(id int) basics.Address {
	return basics.AppIndex(id).Address()
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

	ep, tx, ledger := MakeSampleEnv()
	ledger.NewApp(tx.Receiver, 888, basics.AppParams{})
	TestApp(t, "txn Sender; balance; int 0; ==;", ep)
	TestApp(t, "txn Sender; txn Accounts 1; int 100"+pay, ep, "unauthorized")
	TestApp(t, "global CurrentApplicationAddress; txn Accounts 1; int 100"+pay, ep,
		"insufficient balance")
	ledger.NewAccount(appAddr(888), 1000000)

	// You might NewExpect this to fail because of min balance issue
	// (receiving account only gets 100 microalgos).  It does not fail at
	// this level, instead, we must be certain that the existing min
	// balance check in eval.transaction() properly notices and fails
	// the transaction later.  This fits with the model that we check
	// min balances once at the end of each "top-level" transaction.
	TestApp(t, "global CurrentApplicationAddress; txn Accounts 1; int 100"+pay, ep)

	// 100 of 1000000 spent, plus MinTxnFee in our fake protocol is 1001
	TestApp(t, "global CurrentApplicationAddress; balance; int 998899; ==", ep)
	TestApp(t, "txn Receiver; balance; int 100; ==", ep)

	close := `
  itxn_begin
  int pay;      itxn_field TypeEnum
  txn Receiver; itxn_field CloseRemainderTo
  itxn_submit
  int 1
`
	TestApp(t, close, ep)
	TestApp(t, "global CurrentApplicationAddress; balance; !", ep)
	// Receiver got most of the algos (except 1001 for fee)
	TestApp(t, "txn Receiver; balance; int 997998; ==", ep)
}

func TestAppAssetOptIn(t *testing.T) {
	ep, tx, ledger := MakeSampleEnv()
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
	TestApp(t, axfer, ep, "invalid Asset reference")
	tx.ForeignAssets = append(tx.ForeignAssets, 25)
	TestApp(t, axfer, ep, "not opted in") // app account not opted in
	optin := `
itxn_begin
int axfer; itxn_field TypeEnum;
int 25;    itxn_field XferAsset;
int 0;     itxn_field AssetAmount;
global CurrentApplicationAddress; itxn_field AssetReceiver;
itxn_submit
int 1
`
	TestApp(t, optin, ep, "does not exist")
	// Asset 25
	ledger.NewAsset(tx.Sender, 25, basics.AssetParams{
		Total:     10,
		UnitName:  "x",
		AssetName: "Cross",
	})
	TestApp(t, optin, ep)

	TestApp(t, axfer, ep, "insufficient balance") // opted in, but balance=0

	// Fund the app account with the asset
	ledger.NewHolding(basics.AppIndex(888).Address(), 25, 5, false)
	TestApp(t, axfer, ep)
	TestApp(t, axfer, ep)
	TestApp(t, axfer, ep, "insufficient balance") // balance = 1, tried to move 2)
	TestApp(t, "global CurrentApplicationAddress; int 25; asset_holding_get AssetBalance; assert; int 1; ==", ep)

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
	TestApp(t, close, ep)
	TestApp(t, "global CurrentApplicationAddress; int 25; asset_holding_get AssetBalance; !; assert; !", ep)
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

	ep, tx, ledger := MakeSampleEnv()
	ledger.NewApp(tx.Receiver, 888, basics.AppParams{})
	TestApp(t, "txn Sender; balance; int 0; ==;", ep)
	TestApp(t, "txn Sender; txn Accounts 1; int 100"+pay, ep, "unauthorized")
	ledger.NewAccount(tx.Sender, 120+ep.Proto.MinTxnFee)
	ledger.Rekey(tx.Sender, basics.AppIndex(888).Address())
	TestApp(t, "txn Sender; txn Accounts 1; int 100"+pay+"; int 1", ep)
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

	ep, tx, ledger := MakeSampleEnv()
	ledger.NewApp(tx.Receiver, 888, basics.AppParams{})
	TestApp(t, "txn Sender; balance; int 0; ==;", ep)
	TestApp(t, "txn Sender; txn Accounts 1; int 100"+payAndUnkey, ep, "unauthorized")
	ledger.NewAccount(tx.Sender, 120+3*ep.Proto.MinTxnFee)
	ledger.Rekey(tx.Sender, basics.AppIndex(888).Address())
	TestApp(t, "txn Sender; txn Accounts 1; int 100"+payAndUnkey+"; int 1", ep)
	// now rekeyed back to original
	TestApp(t, "txn Sender; txn Accounts 1; int 100"+payAndUnkey, ep, "unauthorized")
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

	ep, tx, ledger := MakeSampleEnv()
	ledger.NewApp(tx.Receiver, 888, basics.AppParams{})
	tx.Accounts = append(tx.Accounts, appAddr(888))
	TestApp(t, "txn Accounts 1; int 100"+pay, ep, "insufficient balance")
	ledger.NewAccount(appAddr(888), 1000000)
	TestApp(t, "txn Accounts 1; int 100"+pay+"int 1", ep)
	TestApp(t, "global CurrentApplicationAddress; balance; int 998899; ==", ep)
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

	ep, tx, ledger := MakeSampleEnv()
	ledger.NewApp(tx.Receiver, 888, basics.AppParams{})
	ledger.NewAsset(tx.Receiver, 777, basics.AssetParams{}) // not in foreign-assets of sample
	ledger.NewAsset(tx.Receiver, 77, basics.AssetParams{})  // in foreign-assets of sample
	TestApp(t, "txn Sender; int 777; asset_holding_get AssetBalance; assert; int 0; ==;", ep,
		"invalid Asset reference") // 777 not in foreign-assets
	TestApp(t, "txn Sender; int 77; asset_holding_get AssetBalance; assert; int 0; ==;", ep,
		"assert failed") // because Sender not opted-in
	TestApp(t, "global CurrentApplicationAddress; int 77; asset_holding_get AssetBalance; assert; int 0; ==;", ep,
		"assert failed") // app account not opted in

	ledger.NewAccount(appAddr(888), 10000) // plenty for fees
	ledger.NewHolding(appAddr(888), 77, 3000, false)
	TestApp(t, "global CurrentApplicationAddress; int 77; asset_holding_get AssetBalance; assert; int 3000; ==;", ep)

	TestApp(t, "txn Sender; txn Accounts 1; int 100"+axfer, ep, "unauthorized")
	TestApp(t, "global CurrentApplicationAddress; txn Accounts 0; int 100"+axfer, ep,
		fmt.Sprintf("Receiver (%s) not opted in", tx.Sender)) // txn.Sender (receiver of the axfer) isn't opted in
	TestApp(t, "global CurrentApplicationAddress; txn Accounts 1; int 100000"+axfer, ep,
		"insufficient balance")

	// Temporarily remove from ForeignAssets to ensure App Account
	// doesn't get some sort of free pass to send arbitrary assets.
	save := tx.ForeignAssets
	tx.ForeignAssets = []basics.AssetIndex{6, 10}
	TestApp(t, "global CurrentApplicationAddress; txn Accounts 1; int 100000"+axfer, ep,
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
	TestApp(t, "global CurrentApplicationAddress; txn Accounts 1; int 100"+noid+"int 1", ep,
		fmt.Sprintf("Sender (%s) not opted in to 0", appAddr(888)))

	TestApp(t, "global CurrentApplicationAddress; txn Accounts 1; int 100"+axfer+"int 1", ep)

	// 100 of 3000 spent
	TestApp(t, "global CurrentApplicationAddress; int 77; asset_holding_get AssetBalance; assert; int 2900; ==", ep)
	TestApp(t, "txn Accounts 1; int 77; asset_holding_get AssetBalance; assert; int 100; ==", ep)
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

	ep, tx, ledger := MakeSampleEnv()
	ledger.NewApp(tx.Receiver, 888, basics.AppParams{})
	TestApp(t, "txn Sender; balance; int 0; ==;", ep)
	TestApp(t, "txn Sender; txn Accounts 1; int 100"+pay, ep, "unauthorized")
	TestApp(t, "global CurrentApplicationAddress; txn Accounts 1; int 100"+pay, ep,
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

	ep, tx, ledger := MakeSampleEnvWithVersion(5)
	ledger.NewApp(tx.Receiver, 888, basics.AppParams{})
	// Assemble a good program, then change the field to a bad one
	ops := TestProg(t, "global CurrentApplicationAddress; txn Accounts 1; int 100"+pay, 5)
	ops.Program[len(ops.Program)-2] = byte(RekeyTo)
	TestAppBytes(t, ops.Program, ep, "invalid itxn_field RekeyTo")
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

	ep, tx, ledger := MakeSampleEnv()
	ledger.NewApp(tx.Receiver, 888, basics.AppParams{})
	ops := TestProg(t, "global CurrentApplicationAddress; txn Accounts 1; int 100"+pay, AssemblerMaxVersion)
	ops.Program[len(ops.Program)-2] = byte(FirstValid)
	TestAppBytes(t, ops.Program, ep, "invalid itxn_field FirstValid")
}

func TestNumInnerShallow(t *testing.T) {
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

	ep, tx, ledger := MakeSampleEnv()
	ledger.NewApp(tx.Receiver, 888, basics.AppParams{})
	ledger.NewAccount(appAddr(888), 1000000)
	TestApp(t, pay+";int 1", ep)
	TestApp(t, pay+pay+";int 1", ep)
	TestApp(t, pay+pay+pay+";int 1", ep)
	TestApp(t, pay+pay+pay+pay+";int 1", ep)
	// In the sample proto, MaxInnerTransactions = 4
	TestApp(t, pay+pay+pay+pay+pay+";int 1", ep, "too many inner transactions")
}

// TestNumInnerPooled ensures that inner call limits are pooled across app calls
// in a group.
func TestNumInnerPooled(t *testing.T) {
	pay := `
  itxn_begin
  int 1
  itxn_field Amount
  txn Accounts 0
  itxn_field Receiver
  int pay
  itxn_field TypeEnum
  itxn_submit
`

	tx := txntest.Txn{
		Type: protocol.ApplicationCallTx,
	}.SignedTxn()
	ledger := MakeLedger(nil)
	ledger.NewApp(tx.Txn.Receiver, 888, basics.AppParams{})
	ledger.NewAccount(appAddr(888), 1000000)
	short := pay + ";int 1"
	long := pay + pay + pay + pay + pay + ";int 1"
	// First two just replicate the non-pooled test
	one := MakeSampleTxnGroup(tx)
	TestApps(t, []string{short, ""}, one, LogicVersion, ledger)
	TestApps(t, []string{short, ""}, one, LogicVersion, ledger)
	TestApps(t, []string{short, ""}, one, LogicVersion, ledger)
	TestApps(t, []string{short, ""}, one, LogicVersion, ledger)
	TestApps(t, []string{short, ""}, one, LogicVersion, ledger)
	TestApps(t, []string{short, ""}, one, LogicVersion, ledger)
	TestApps(t, []string{long, ""}, one, LogicVersion, ledger,
		NewExpect(0, "too many inner transactions"))

	// Now try pooling. But it won't work, because in `one`, only the first txn
	// is an appcall.
	TestApps(t, []string{long, short}, one, LogicVersion, ledger,
		NewExpect(0, "too many inner transactions"))
	TestApps(t, []string{short, long}, one, LogicVersion, ledger,
		NewExpect(1, "too many inner transactions"))

	// Now show pooling works, whether the first txn is heavy, or the second (but not both)
	two := MakeSampleTxnGroup(tx)
	two[1].Txn.Type = protocol.ApplicationCallTx
	TestApps(t, []string{short, long}, two, LogicVersion, ledger)
	TestApps(t, []string{long, short}, two, LogicVersion, ledger)
	TestApps(t, []string{long, long}, two, LogicVersion, ledger,
		NewExpect(1, "too many inner transactions"))

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
	ep, tx, ledger := MakeSampleEnv()
	ledger.NewApp(tx.Receiver, 888, basics.AppParams{})
	TestApp(t, create, ep, "insufficient balance")
	// Give it enough for fee.  Recall that we don't check min balance at this level.
	ledger.NewAccount(appAddr(888), MakeTestProto().MinTxnFee)
	TestApp(t, create, ep)
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
  int 5000
  ==
`
	ep, tx, ledger := MakeSampleEnv()
	ledger.NewApp(tx.Receiver, 888, basics.AppParams{})
	// Give it enough for fees.  Recall that we don't check min balance at this level.
	ledger.NewAccount(appAddr(888), 12*MakeTestProto().MinTxnFee)
	TestApp(t, create, ep)

	freeze := `
  itxn_begin
  int afrz                    ; itxn_field TypeEnum
  int 5000                    ; itxn_field FreezeAsset
  txn ApplicationArgs 0; btoi ; itxn_field FreezeAssetFrozen
  txn Accounts 1              ; itxn_field FreezeAssetAccount
  itxn_submit
  int 1
`
	TestApp(t, freeze, ep, "invalid Asset reference")
	tx.ForeignAssets = []basics.AssetIndex{basics.AssetIndex(5000)}
	tx.ApplicationArgs = [][]byte{{0x01}}
	TestApp(t, freeze, ep, "does not hold Asset")
	ledger.NewHolding(tx.Receiver, 5000, 55, false)
	TestApp(t, freeze, ep)
	holding, err := ledger.AssetHolding(tx.Receiver, 5000)
	require.NoError(t, err)
	require.Equal(t, true, holding.Frozen)
	tx.ApplicationArgs = [][]byte{{0x00}}
	TestApp(t, freeze, ep)
	holding, err = ledger.AssetHolding(tx.Receiver, 5000)
	require.NoError(t, err)
	require.Equal(t, false, holding.Frozen)
}

func TestFieldSetting(t *testing.T) {
	ep, tx, ledger := MakeSampleEnv()
	ledger.NewApp(tx.Receiver, 888, basics.AppParams{})
	ledger.NewAccount(appAddr(888), 10*MakeTestProto().MinTxnFee)
	TestApp(t, "itxn_begin; int 500; bzero; itxn_field Note; int 1", ep)
	TestApp(t, "itxn_begin; int 501; bzero; itxn_field Note; int 1", ep,
		"Note may not exceed")

	TestApp(t, "itxn_begin; int 32; bzero; itxn_field VotePK; int 1", ep)
	TestApp(t, "itxn_begin; int 31; bzero; itxn_field VotePK; int 1", ep,
		"VotePK must be 32")

	TestApp(t, "itxn_begin; int 32; bzero; itxn_field SelectionPK; int 1", ep)
	TestApp(t, "itxn_begin; int 33; bzero; itxn_field SelectionPK; int 1", ep,
		"SelectionPK must be 32")

	TestApp(t, "itxn_begin; int 32; bzero; itxn_field RekeyTo; int 1", ep)
	TestApp(t, "itxn_begin; int 31; bzero; itxn_field RekeyTo; int 1", ep,
		"not an address")

	TestApp(t, "itxn_begin; int 6; bzero; itxn_field ConfigAssetUnitName; int 1", ep)
	TestApp(t, "itxn_begin; int 7; bzero; itxn_field ConfigAssetUnitName; int 1", ep,
		"value is too long")

	TestApp(t, "itxn_begin; int 12; bzero; itxn_field ConfigAssetName; int 1", ep)
	TestApp(t, "itxn_begin; int 13; bzero; itxn_field ConfigAssetName; int 1", ep,
		"value is too long")
}

func TestInnerGroup(t *testing.T) {
	ep, tx, ledger := MakeSampleEnv()
	ledger.NewApp(tx.Receiver, 888, basics.AppParams{})
	// Need both fees and both payments
	ledger.NewAccount(appAddr(888), 999+2*MakeTestProto().MinTxnFee)
	pay := `
int pay;    itxn_field TypeEnum;
int 500;    itxn_field Amount;
txn Sender; itxn_field Receiver;
`
	TestApp(t, "itxn_begin"+pay+"itxn_next"+pay+"itxn_submit; int 1", ep,
		"insufficient balance")

	// NewAccount overwrites the existing balance
	ledger.NewAccount(appAddr(888), 1000+2*MakeTestProto().MinTxnFee)
	TestApp(t, "itxn_begin"+pay+"itxn_next"+pay+"itxn_submit; int 1", ep)
}

func TestInnerFeePooling(t *testing.T) {
	ep, tx, ledger := MakeSampleEnv()
	ledger.NewApp(tx.Receiver, 888, basics.AppParams{})
	ledger.NewAccount(appAddr(888), 50_000)
	pay := `
int pay;    itxn_field TypeEnum;
int 500;    itxn_field Amount;
txn Sender; itxn_field Receiver;
`
	// Force the first fee to 3, but the second will default to 2*fee-3 = 2002-3
	TestApp(t, "itxn_begin"+
		pay+
		"int 3; itxn_field Fee;"+
		"itxn_next"+
		pay+
		"itxn_submit; itxn Fee; int 1999; ==", ep)

	// Same first, but force the second too low
	TestApp(t, "itxn_begin"+
		pay+
		"int 3; itxn_field Fee;"+
		"itxn_next"+
		pay+
		"int 1998; itxn_field Fee;"+
		"itxn_submit; int 1", ep, "fee too small")

	// Overpay in first itxn, the second will default to less
	TestApp(t, "itxn_begin"+
		pay+
		"int 2000; itxn_field Fee;"+
		"itxn_next"+
		pay+
		"itxn_submit; itxn Fee; int 2; ==", ep)

	// Same first, but force the second too low
	TestApp(t, "itxn_begin"+
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
	ep, tx, _ := MakeSampleEnv()

	p := "itxn_begin;"
	s := "; int 1"

	TestApp(t, p+"int 31; itxn_field ApplicationID"+s, ep,
		"invalid App reference")
	tx.ForeignApps = append(tx.ForeignApps, 31)
	TestApp(t, p+"int 31; itxn_field ApplicationID"+s, ep)

	TestApp(t, p+"int 0; itxn_field OnCompletion"+s, ep)
	TestApp(t, p+"int 1; itxn_field OnCompletion"+s, ep)
	TestApp(t, p+"int 2; itxn_field OnCompletion"+s, ep)
	TestApp(t, p+"int 3; itxn_field OnCompletion"+s, ep)
	TestApp(t, p+"int 4; itxn_field OnCompletion"+s, ep)
	TestApp(t, p+"int 5; itxn_field OnCompletion"+s, ep)
	TestApp(t, p+"int 6; itxn_field OnCompletion"+s, ep, "6 is larger than max=5")
	TestApp(t, p+"int NoOp; itxn_field OnCompletion"+s, ep)
	TestApp(t, p+"int OptIn; itxn_field OnCompletion"+s, ep)
	TestApp(t, p+"int CloseOut; itxn_field OnCompletion"+s, ep)
	TestApp(t, p+"int ClearState; itxn_field OnCompletion"+s, ep)
	TestApp(t, p+"int UpdateApplication; itxn_field OnCompletion"+s, ep)
	TestApp(t, p+"int DeleteApplication; itxn_field OnCompletion"+s, ep)

	TestApp(t, p+"int 800; bzero; itxn_field ApplicationArgs"+s, ep)
	TestApp(t, p+"int 801; bzero; itxn_field ApplicationArgs", ep,
		"length too long")
	TestApp(t, p+"int 401; bzero; dup; itxn_field ApplicationArgs; itxn_field ApplicationArgs", ep,
		"length too long")

	TestApp(t, p+strings.Repeat("byte 0x11; itxn_field ApplicationArgs;", 12)+s, ep)
	TestApp(t, p+strings.Repeat("byte 0x11; itxn_field ApplicationArgs;", 13)+s, ep,
		"too many application args")

	TestApp(t, p+strings.Repeat("int 32; bzero; itxn_field Accounts;", 3)+s, ep,
		"invalid Account reference")
	tx.Accounts = append(tx.Accounts, basics.Address{})
	TestApp(t, fmt.Sprintf(p+"%s"+s,
		strings.Repeat("int 32; bzero; itxn_field Accounts;", 3)), ep)
	TestApp(t, fmt.Sprintf(p+"%s"+s,
		strings.Repeat("int 32; bzero; itxn_field Accounts;", 4)), ep,
		"too many foreign accounts")

	TestApp(t, p+strings.Repeat("int 621; itxn_field Applications;", 5)+s, ep,
		"invalid App reference")
	tx.ForeignApps = append(tx.ForeignApps, basics.AppIndex(621))
	TestApp(t, p+strings.Repeat("int 621; itxn_field Applications;", 5)+s, ep)
	TestApp(t, p+strings.Repeat("int 621; itxn_field Applications;", 6)+s, ep,
		"too many foreign apps")

	TestApp(t, p+strings.Repeat("int 621; itxn_field Assets;", 6)+s, ep,
		"invalid Asset reference")
	tx.ForeignAssets = append(tx.ForeignAssets, basics.AssetIndex(621))
	TestApp(t, p+strings.Repeat("int 621; itxn_field Assets;", 6)+s, ep)
	TestApp(t, p+strings.Repeat("int 621; itxn_field Assets;", 7)+s, ep,
		"too many foreign assets")

	TestApp(t, p+"int 2700; bzero; itxn_field ApprovalProgram"+s, ep)
	TestApp(t, p+"int 2701; bzero; itxn_field ApprovalProgram"+s, ep,
		"may not exceed 2700")
	TestApp(t, p+"int 2700; bzero; itxn_field ClearStateProgram"+s, ep)
	TestApp(t, p+"int 2701; bzero; itxn_field ClearStateProgram"+s, ep,
		"may not exceed 2700")

	TestApp(t, p+"int 30; itxn_field GlobalNumUint"+s, ep)
	TestApp(t, p+"int 31; itxn_field GlobalNumUint"+s, ep, "31 is larger than max=30")
	TestApp(t, p+"int 30; itxn_field GlobalNumByteSlice"+s, ep)
	TestApp(t, p+"int 31; itxn_field GlobalNumByteSlice"+s, ep, "31 is larger than max=30")
	TestApp(t, p+"int 20; itxn_field GlobalNumUint; int 11; itxn_field GlobalNumByteSlice"+s, ep)

	TestApp(t, p+"int 13; itxn_field LocalNumUint"+s, ep)
	TestApp(t, p+"int 14; itxn_field LocalNumUint"+s, ep, "14 is larger than max=13")
	TestApp(t, p+"int 13; itxn_field LocalNumByteSlice"+s, ep)
	TestApp(t, p+"int 14; itxn_field LocalNumByteSlice"+s, ep, "14 is larger than max=13")

	TestApp(t, p+"int 2; itxn_field ExtraProgramPages"+s, ep)
	TestApp(t, p+"int 3; itxn_field ExtraProgramPages"+s, ep, "3 is larger than max=2")
}

// TestApplSubmission tests for checking of illegal appl transaction in form
// only.  Things where interactions between two different fields causes the
// error.  These are not exhaustive, but certainly demonstrate that WellFormed
// is getting a crack at the txn.
func TestApplSubmission(t *testing.T) {
	ep, tx, ledger := MakeSampleEnv()
	ledger.NewApp(tx.Receiver, 888, basics.AppParams{})
	// Since the fee is moved first, fund the app
	ledger.NewAccount(appAddr(888), 50_000)

	ops := TestProg(t, "int 1", AssemblerMaxVersion)
	approve := hex.EncodeToString(ops.Program)
	a := fmt.Sprintf("byte 0x%s; itxn_field ApprovalProgram;", approve)

	p := "itxn_begin; int appl; itxn_field TypeEnum;"
	s := ";itxn_submit; int 1"
	TestApp(t, p+a+s, ep)

	// All zeros is v0, so we get a complaint, but that means lengths were ok.
	TestApp(t, p+a+`int 600; bzero; itxn_field ApprovalProgram;
                  int 600; bzero; itxn_field ClearStateProgram;`+s, ep,
		"program version must be")

	TestApp(t, p+`int 601; bzero; itxn_field ApprovalProgram;
                  int 600; bzero; itxn_field ClearStateProgram;`+s, ep, "too long")

	// WellFormed does the math based on the supplied ExtraProgramPages
	TestApp(t, p+a+`int 1; itxn_field ExtraProgramPages
                  int 1200; bzero; itxn_field ApprovalProgram;
                  int 1200; bzero; itxn_field ClearStateProgram;`+s, ep,
		"program version must be")
	TestApp(t, p+`int 1; itxn_field ExtraProgramPages
                  int 1200; bzero; itxn_field ApprovalProgram;
                  int 1201; bzero; itxn_field ClearStateProgram;`+s, ep, "too long")

	// Can't set epp when app id is given
	tx.ForeignApps = append(tx.ForeignApps, basics.AppIndex(7))
	TestApp(t, p+`int 1; itxn_field ExtraProgramPages;
                  int 7; itxn_field ApplicationID`+s, ep, "immutable")

	TestApp(t, p+"int 20; itxn_field GlobalNumUint; int 11; itxn_field GlobalNumByteSlice"+s,
		ep, "too large")
	TestApp(t, p+"int 7; itxn_field LocalNumUint; int 7; itxn_field LocalNumByteSlice"+s,
		ep, "too large")
}

func TestInnerApplCreate(t *testing.T) {
	ep, tx, ledger := MakeSampleEnv()
	ledger.NewApp(tx.Receiver, 888, basics.AppParams{})
	ledger.NewAccount(appAddr(888), 50_000)

	ops := TestProg(t, "int 1", AssemblerMaxVersion)
	approve := "byte 0x" + hex.EncodeToString(ops.Program)

	TestApp(t, `
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

	TestApp(t, `
int 5000; app_params_get AppGlobalNumByteSlice; assert; int 0; ==; assert
`, ep, "invalid App reference")

	call := `
itxn_begin
int appl;              itxn_field TypeEnum
int 5000;               itxn_field ApplicationID
itxn_submit
int 1
`
	// Can't call it either
	TestApp(t, call, ep, "invalid App reference")

	tx.ForeignApps = []basics.AppIndex{basics.AppIndex(5000)}
	TestApp(t, `
int 5000; app_params_get AppGlobalNumByteSlice; assert; int 0; ==; assert
int 5000; app_params_get AppGlobalNumUint;      assert; int 1; ==; assert
int 5000; app_params_get AppLocalNumByteSlice;  assert; int 2; ==; assert
int 5000; app_params_get AppLocalNumUint;       assert; int 3; ==; assert
int 1
`, ep)

	// Call it (default OnComplete is NoOp)
	TestApp(t, call, ep)

	TestApp(t, `
itxn_begin
int appl;              itxn_field TypeEnum
int DeleteApplication; itxn_field OnCompletion
txn Applications 1;    itxn_field ApplicationID
itxn_submit
int 1
`, ep)

	// App is gone
	TestApp(t, `
int 5000; app_params_get AppGlobalNumByteSlice; !; assert; !; assert; int 1
`, ep)

	// Can't call it either
	TestApp(t, call, ep, "No application")

}

func TestCreateOldAppFails(t *testing.T) {
	ep, tx, ledger := MakeSampleEnv()
	ledger.NewApp(tx.Receiver, 888, basics.AppParams{})
	ledger.NewAccount(appAddr(888), 50_000)

	ops := TestProg(t, "int 1", InnerAppsEnabledVersion-1)
	approve := "byte 0x" + hex.EncodeToString(ops.Program)

	TestApp(t, `
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
	ep, tx, ledger := MakeSampleEnv()
	ledger.NewApp(tx.Receiver, 888, basics.AppParams{})
	ledger.NewAccount(appAddr(888), 50_000)

	TestApp(t, `
itxn_begin
int appl;    itxn_field TypeEnum
int 888;     itxn_field ApplicationID
itxn_submit
int 1
`, ep, "attempt to self-call")
}

func TestIndirectReentrancy(t *testing.T) {
	ep, tx, ledger := MakeSampleEnv()
	call888 := TestProg(t, `itxn_begin
int appl;    itxn_field TypeEnum
int 888;     itxn_field ApplicationID
itxn_submit
int 1
`, AssemblerMaxVersion)
	ledger.NewApp(tx.Receiver, 222, basics.AppParams{
		ApprovalProgram: call888.Program,
	})

	ledger.NewApp(tx.Receiver, 888, basics.AppParams{})
	ledger.NewAccount(appAddr(888), 50_000)
	tx.ForeignApps = []basics.AppIndex{basics.AppIndex(222)}
	TestApp(t, `
itxn_begin
int appl;    itxn_field TypeEnum
int 222;     itxn_field ApplicationID
int 888;     itxn_field Applications
itxn_submit
int 1
`, ep, "attempt to re-enter 888")
}

// TestInnerAppID ensures that inner app properly sees its AppId. This seems
// needlessly picky to test, but the appID used to be stored outside the cx.
func TestInnerAppID(t *testing.T) {
	ep, tx, ledger := MakeSampleEnv()
	logID := TestProg(t, `global CurrentApplicationID; itob; log; int 1`, AssemblerMaxVersion)
	ledger.NewApp(tx.Receiver, 222, basics.AppParams{
		ApprovalProgram: logID.Program,
	})

	ledger.NewApp(tx.Receiver, 888, basics.AppParams{})
	ledger.NewAccount(appAddr(888), 50_000)
	tx.ForeignApps = []basics.AppIndex{basics.AppIndex(222)}
	TestApp(t, `
itxn_begin
int appl;    itxn_field TypeEnum
int 222;     itxn_field ApplicationID
itxn_submit
itxn Logs 0
btoi
int 222
==
`, ep)
}

// TestInnerBudgetIncrement ensures that an app can make a (nearly) empty inner
// app call in order to get 700 extra opcode budget.  Unfortunately, it costs a
// bit to create the call, and the app itself consumes 1, so it ends up being
// about 690 (see next test).
func TestInnerBudgetIncrement(t *testing.T) {
	ep, tx, ledger := MakeSampleEnv()
	gasup := TestProg(t, "pushint 1", AssemblerMaxVersion)
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
	ledger.NewAccount(appAddr(888), 50_000)
	tx.ForeignApps = []basics.AppIndex{basics.AppIndex(222)}
	TestApp(t, strings.Repeat(waste, 5)+"int 1", ep)
	TestApp(t, strings.Repeat(waste, 6)+"int 1", ep, "dynamic cost budget exceeded")
	TestApp(t, strings.Repeat(waste, 6)+buy+"int 1", ep, "dynamic cost budget exceeded")
	TestApp(t, buy+strings.Repeat(waste, 6)+"int 1", ep)
	TestApp(t, buy+strings.Repeat(waste, 10)+"int 1", ep)
	TestApp(t, buy+strings.Repeat(waste, 12)+"int 1", ep, "dynamic cost budget exceeded")
	TestApp(t, buy+strings.Repeat(waste, 12)+"int 1", ep, "dynamic cost budget exceeded")
	TestApp(t, buy+buy+strings.Repeat(waste, 12)+"int 1", ep)
}

func TestIncrementCheck(t *testing.T) {
	ep, tx, ledger := MakeSampleEnv()
	gasup := TestProg(t, "pushint 1", AssemblerMaxVersion)
	ledger.NewApp(tx.Receiver, 222, basics.AppParams{
		ApprovalProgram: gasup.Program,
	})

	source := `
// 698, not 699, because intcblock happens first
global OpcodeBudget; int 698; ==; assert
// "buy" more
itxn_begin
int appl;    itxn_field TypeEnum
int 222;     itxn_field ApplicationID
itxn_submit;
global OpcodeBudget; int 1387; ==; assert
itxn_begin
int appl;    itxn_field TypeEnum
int 222;     itxn_field ApplicationID
itxn_submit;
global OpcodeBudget; int 2076; ==; assert
int 1
`

	ledger.NewApp(tx.Receiver, 888, basics.AppParams{})
	ledger.NewAccount(appAddr(888), 50_000)
	tx.ForeignApps = []basics.AppIndex{basics.AppIndex(222)}
	TestApp(t, source, ep)
}

// TestInnerTxIDs confirms that TxIDs are available and different
func TestInnerTxIDs(t *testing.T) {
	ep, tx, ledger := MakeSampleEnv()
	txid := TestProg(t, "txn TxID; log; int 1", AssemblerMaxVersion)
	ledger.NewApp(tx.Receiver, 222, basics.AppParams{
		ApprovalProgram: txid.Program,
	})
	ledger.NewApp(tx.Receiver, 888, basics.AppParams{})
	ledger.NewAccount(appAddr(888), 50_000)
	tx.ForeignApps = []basics.AppIndex{basics.AppIndex(222)}
	TestApp(t, `
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
	ep, tx, ledger := MakeSampleEnv()
	gid := TestProg(t, "global GroupID; log; int 1", AssemblerMaxVersion)
	ledger.NewApp(tx.Receiver, 222, basics.AppParams{
		ApprovalProgram: gid.Program,
	})
	ledger.NewApp(tx.Receiver, 888, basics.AppParams{})
	ledger.NewAccount(appAddr(888), 50_000)
	tx.ForeignApps = []basics.AppIndex{basics.AppIndex(222)}

	// A single txn gets 0 group id
	TestApp(t, `
itxn_begin
int appl;    itxn_field TypeEnum
int 222;     itxn_field ApplicationID
itxn_submit;
itxn Logs 0
global ZeroAddress
==
`, ep)

	// A double calls gets something else
	TestApp(t, `
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
	TestApp(t, `
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
	ep, tx, ledger := MakeSampleEnv()
	two := TestProg(t, "byte 0x22; log; int 1", AssemblerMaxVersion)
	ledger.NewApp(tx.Receiver, 222, basics.AppParams{
		ApprovalProgram: two.Program,
	})
	three := TestProg(t, "byte 0x33; log; int 1", AssemblerMaxVersion)
	ledger.NewApp(tx.Receiver, 333, basics.AppParams{
		ApprovalProgram: three.Program,
	})
	four := TestProg(t, "byte 0x44; log; int 1", AssemblerMaxVersion)
	ledger.NewApp(tx.Receiver, 444, basics.AppParams{
		ApprovalProgram: four.Program,
	})

	ledger.NewApp(tx.Receiver, 888, basics.AppParams{})
	ledger.NewAccount(appAddr(888), 50_000)
	tx.ForeignApps = []basics.AppIndex{basics.AppIndex(222), basics.AppIndex(333), basics.AppIndex(444)}

	TestApp(t, `
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
	TestApp(t, `
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
	ep, tx, ledger := MakeSampleEnv()
	two := TestProg(t, "byte 0x22; log; int 1", AssemblerMaxVersion)
	ledger.NewApp(tx.Receiver, 222, basics.AppParams{
		ApprovalProgram: two.Program,
	})
	three := TestProg(t, "gtxn 0 NumLogs; int 1; ==; assert; gtxna 0 Logs 0; byte 0x22; ==", AssemblerMaxVersion)
	ledger.NewApp(tx.Receiver, 333, basics.AppParams{
		ApprovalProgram: three.Program,
	})

	ledger.NewApp(tx.Receiver, 888, basics.AppParams{})
	ledger.NewAccount(appAddr(888), 50_000)
	tx.ForeignApps = []basics.AppIndex{basics.AppIndex(222), basics.AppIndex(333)}

	TestApp(t, `itxn_begin
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
	ep, tx, ledger := MakeSampleEnv()
	appcheck := TestProg(t, `
gtxn 0 CreatedApplicationID; itob; log;
gtxn 1 CreatedApplicationID; itob; log;
int 1
`, AssemblerMaxVersion)
	ledger.NewApp(tx.Receiver, 222, basics.AppParams{
		ApprovalProgram: appcheck.Program,
	})

	ops := TestProg(t, "int 1", AssemblerMaxVersion)

	ledger.NewApp(tx.Receiver, 888, basics.AppParams{})
	ledger.NewAccount(appAddr(888), 50_000)
	tx.ForeignApps = []basics.AppIndex{basics.AppIndex(222)}
	TestApp(t, `itxn_begin
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
int 5000
==
assert
gitxn 2 Logs 1
btoi
int 5001
==
`, ep)
}

// TestGtxnAsa confirms that gtxn can now access previous txn's created asa id.
func TestGtxnAsa(t *testing.T) {
	ep, tx, ledger := MakeSampleEnv()
	appcheck := TestProg(t, `
gtxn 0 CreatedAssetID; itob; log;
gtxn 1 CreatedAssetID; itob; log;
int 1
`, AssemblerMaxVersion)
	ledger.NewApp(tx.Receiver, 222, basics.AppParams{
		ApprovalProgram: appcheck.Program,
	})

	ledger.NewApp(tx.Receiver, 888, basics.AppParams{})
	ledger.NewAccount(appAddr(888), 50_000)
	tx.ForeignApps = []basics.AppIndex{basics.AppIndex(222)}
	TestApp(t, `itxn_begin
int acfg;    itxn_field TypeEnum
itxn_next
int acfg;    itxn_field TypeEnum
itxn_next
int appl;    itxn_field TypeEnum
int 222;     itxn_field ApplicationID
itxn_submit
itxn Logs 0
btoi
int 5000
==
assert
gitxn 2 Logs 1
btoi
int 5001
==
`, ep)
}

// TestCallerGlobals checks that a called app can see its caller.
func TestCallerGlobals(t *testing.T) {
	ep, tx, ledger := MakeSampleEnv()
	globals := TestProg(t, fmt.Sprintf(`
global CallerApplicationID
int 888
==
global CallerApplicationAddress
addr %s
==
&&
`, basics.AppIndex(888).Address()), AssemblerMaxVersion)
	ledger.NewApp(tx.Receiver, 222, basics.AppParams{
		ApprovalProgram: globals.Program,
	})

	ledger.NewApp(tx.Receiver, 888, basics.AppParams{})
	ledger.NewAccount(appAddr(888), 50_000)
	tx.ForeignApps = []basics.AppIndex{basics.AppIndex(222)}
	TestApp(t, `itxn_begin
int appl;    itxn_field TypeEnum
int 222;     itxn_field ApplicationID
itxn_submit
int 1
`, ep)
}

// TestNumInnerDeep ensures that inner call limits apply to inner calls of inner
// transactions.
func TestNumInnerDeep(t *testing.T) {
	pay := `
  itxn_begin
  int 1
  itxn_field Amount
  txn Accounts 0
  itxn_field Receiver
  int pay
  itxn_field TypeEnum
  itxn_submit
`

	tx := txntest.Txn{
		Type:          protocol.ApplicationCallTx,
		ApplicationID: 888,
		ForeignApps:   []basics.AppIndex{basics.AppIndex(222)},
	}.SignedTxnWithAD()
	require.Equal(t, 888, int(tx.Txn.ApplicationID))
	ledger := MakeLedger(nil)

	pay3 := TestProg(t, pay+pay+pay+"int 1;", AssemblerMaxVersion).Program
	ledger.NewApp(tx.Txn.Receiver, 222, basics.AppParams{
		ApprovalProgram: pay3,
	})

	ledger.NewApp(tx.Txn.Receiver, 888, basics.AppParams{})
	ledger.NewAccount(appAddr(888), 1_000_000)

	callpay3 := `itxn_begin
int appl;    itxn_field TypeEnum
int 222;     itxn_field ApplicationID
itxn_submit
`
	txg := []transactions.SignedTxnWithAD{tx}
	ep := NewAppEvalParams(txg, MakeTestProto(), &transactions.SpecialAddresses{}, 0)
	ep.Ledger = ledger
	TestApp(t, callpay3+"int 1", ep, "insufficient balance") // inner contract needs money

	ledger.NewAccount(appAddr(222), 1_000_000)
	TestApp(t, callpay3+"int 1", ep)
	TestApp(t, callpay3+callpay3+"int 1", ep, "too many inner transactions")
}

// TestCreateAndUse checks that an ASA can be created in an inner app, and then
// used.  This was not allowed until v6, because of the strict adherence to the
// foreign-arrays rules.
func TestCreateAndUse(t *testing.T) {
	axfer := `
  itxn_begin
   int acfg;    itxn_field TypeEnum
   int 10;      itxn_field ConfigAssetTotal
   byte "Gold"; itxn_field ConfigAssetName
  itxn_submit

  itxn_begin
   int axfer;           itxn_field TypeEnum
   itxn CreatedAssetID; itxn_field XferAsset
   txn Accounts 0;      itxn_field AssetReceiver
  itxn_submit

  int 1
`

	// First testing in axfer
	ep, tx, ledger := MakeSampleEnv()
	ledger.NewApp(tx.Receiver, 888, basics.AppParams{})
	ledger.NewAccount(appAddr(888), 4*MakeTestProto().MinTxnFee)
	TestApp(t, axfer, ep)

	ep.Proto = MakeTestProtoV(CreatedResourcesVersion - 1)
	TestApp(t, axfer, ep, "invalid Asset reference")

	balance := `
  itxn_begin
  int acfg;    itxn_field TypeEnum
  int 10;      itxn_field ConfigAssetTotal
  byte "Gold"; itxn_field ConfigAssetName
  itxn_submit

  // txn Sender is not opted-in, as it's the app account that made the asset
  // At some point, we should short-circuit so this does not go to disk.
  txn Sender
  itxn CreatedAssetID
  asset_holding_get AssetBalance
  int 0
  ==
  assert
  int 0
  ==
  assert

  // App account owns all the newly made gold
  global CurrentApplicationAddress
  itxn CreatedAssetID
  asset_holding_get AssetBalance
  assert
  int 10
  ==
  assert

  int 1
`

	// Now as in asset balance opcode
	ep, tx, ledger = MakeSampleEnv()
	ledger.NewApp(tx.Receiver, 888, basics.AppParams{})
	ledger.NewAccount(appAddr(888), 4*MakeTestProto().MinTxnFee)
	TestApp(t, balance, ep)

	ep.Proto = MakeTestProtoV(CreatedResourcesVersion - 1)
	TestApp(t, balance, ep, "invalid Asset reference")

	appcall := `
  itxn_begin
  int acfg;    itxn_field TypeEnum
  int 10;      itxn_field ConfigAssetTotal
  byte "Gold"; itxn_field ConfigAssetName
  itxn_submit

  itxn_begin
  int appl;            itxn_field TypeEnum
  int 888;			   itxn_field ApplicationID
  itxn CreatedAssetID; itxn_field Assets
  itxn_submit

  int 1
`

	// Now as ForeigAsset
	ep, tx, ledger = MakeSampleEnv()
	ledger.NewApp(tx.Receiver, 888, basics.AppParams{})
	ledger.NewApp(tx.Receiver, 888, basics.AppParams{})
	ledger.NewAccount(appAddr(888), 4*MakeTestProto().MinTxnFee)
	// It gets passed the Assets setting
	TestApp(t, appcall, ep, "attempt to self-call")

	// Appcall is isn't allowed pre-CreatedResourcesVersion, because same
	// version allowed inner app calls
	// ep.Proto = MakeTestProtoV(CreatedResourcesVersion - 1)
	// TestApp(t, appcall, ep, "invalid Asset reference")
}
