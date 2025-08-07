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

package logic_test

import (
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"
	"testing"

	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/transactions"
	. "github.com/algorand/go-algorand/data/transactions/logic"
	"github.com/algorand/go-algorand/data/txntest"
	"github.com/algorand/go-algorand/protocol"
	"github.com/algorand/go-algorand/test/partitiontest"

	"github.com/stretchr/testify/require"
)

func TestInnerTypesV5(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	v5, _, _ := MakeSampleEnvWithVersion(5)
	// not alllowed in v5
	TestApp(t, "itxn_begin; byte \"keyreg\"; itxn_field Type; itxn_submit; int 1;", v5, "keyreg is not a valid Type for itxn_field")
	TestApp(t, "itxn_begin; int keyreg; itxn_field TypeEnum; itxn_submit; int 1;", v5, "keyreg is not a valid Type for itxn_field")

	TestApp(t, "itxn_begin; byte \"appl\"; itxn_field Type; itxn_submit; int 1;", v5, "appl is not a valid Type for itxn_field")
	TestApp(t, "itxn_begin; int appl; itxn_field TypeEnum; itxn_submit; int 1;", v5, "appl is not a valid Type for itxn_field")
}

func TestCurrentInnerTypes(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	ep, tx, ledger := MakeSampleEnv()
	TestApp(t, "itxn_submit; int 1;", ep, "itxn_submit without itxn_begin")
	TestApp(t, "int pay; itxn_field TypeEnum; itxn_submit; int 1;", ep, "itxn_field without itxn_begin")
	TestApp(t, "itxn_begin; itxn_submit; int 1;", ep, "unknown tx type")
	// bad type
	TestApp(t, "itxn_begin; byte \"pya\"; itxn_field Type; itxn_submit; int 1;", ep, "pya is not a valid Type")
	// mixed up the int form for the byte form
	TestApp(t, NoTrack("itxn_begin; int pay; itxn_field Type; itxn_submit; int 1;"), ep, "Type arg not a byte array")
	// or vice versa
	TestApp(t, NoTrack("itxn_begin; byte \"pay\"; itxn_field TypeEnum; itxn_submit; int 1;"), ep, "not a uint64")

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
	TestApp(t, "itxn_begin; int acfg; itxn_field TypeEnum; itxn_submit; int 1;", ep, "insufficient balance")

	// allowed since v6
	TestApp(t, "itxn_begin; byte \"keyreg\"; itxn_field Type; itxn_submit; int 1;", ep, "insufficient balance")
	TestApp(t, "itxn_begin; int keyreg; itxn_field TypeEnum; itxn_submit; int 1;", ep, "insufficient balance")
	// caught before inner evaluation, because id=0 and bad program
	TestApp(t, "itxn_begin; byte \"appl\"; itxn_field Type; itxn_submit; int 1;", ep, "invalid program (empty)")
	TestApp(t, "itxn_begin; int appl; itxn_field TypeEnum; itxn_submit; int 1;", ep, "invalid program (empty)")

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
	partitiontest.PartitionTest(t)
	t.Parallel()

	ep, _, _ := MakeSampleEnv()
	// Use NoTrack to skip assembly errors
	TestApp(t, NoTrack("itxn_begin; byte \"pay\"; itxn_field Sender;"), ep, "not an address")
	TestApp(t, NoTrack("itxn_begin; int 7; itxn_field Receiver;"), ep, "not an address")
	TestApp(t, NoTrack("itxn_begin; byte \"\"; itxn_field CloseRemainderTo;"), ep, "not an address")
	TestApp(t, NoTrack("itxn_begin; byte \"\"; itxn_field AssetSender;"), ep, "not an address")
	// can't really tell if it's an addres, so 32 bytes gets further
	TestApp(t, "itxn_begin; byte \"01234567890123456789012345678901\"; itxn_field AssetReceiver; int 1",
		ep, "unavailable Account")
	// but a b32 string rep is not an account
	TestApp(t, NoTrack("itxn_begin; byte \"GAYTEMZUGU3DOOBZGAYTEMZUGU3DOOBZGAYTEMZUGU3DOOBZGAYZIZD42E\"; itxn_field AssetCloseTo;"),
		ep, "not an address")

	TestApp(t, NoTrack("itxn_begin; byte \"pay\"; itxn_field Fee;"), ep, "not a uint64")
	TestApp(t, NoTrack("itxn_begin; byte 0x01; itxn_field Amount;"), ep, "not a uint64")
	TestApp(t, NoTrack("itxn_begin; byte 0x01; itxn_field XferAsset;"), ep, "not a uint64")
	TestApp(t, NoTrack("itxn_begin; byte 0x01; itxn_field AssetAmount;"), ep, "not a uint64")

	// get coverage on uintMaxed()
	TestApp(t, NoTrack("itxn_begin; byte \"pay\"; itxn_field ExtraProgramPages;"), ep, "not a uint64")
	// get coverage on bool()
	TestApp(t, NoTrack("itxn_begin; byte \"pay\"; itxn_field Nonparticipation;"), ep, "not a uint64")
}

func TestFieldLimits(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	ep, _, _ := MakeSampleEnv()

	intProgram := "itxn_begin; int %d; itxn_field %s; int 1"
	goodInt := func(field string, value interface{}) {
		TestApp(t, fmt.Sprintf(intProgram, value, field), ep)
	}
	badInt := func(field string, value interface{}) {
		// error messages are different for different fields, just use a space
		// to indicate there should be an error, it will surely match any error.
		TestApp(t, NoTrack(fmt.Sprintf(intProgram, value, field)), ep, " ")
	}
	testInt := func(field string, max int) {
		goodInt(field, 1)
		goodInt(field, max)
		badInt(field, max+1)
	}
	testBool := func(field string) {
		goodInt(field, 0)
		goodInt(field, 1)
		badInt(field, 2)
	}
	bytesProgram := "itxn_begin; byte %#v; itxn_field %s; int 1"
	goodBytes := func(field string, value string) {
		TestApp(t, fmt.Sprintf(bytesProgram, value, field), ep)
	}
	badBytes := func(field string, value string) {
		// error messages are different for different fields, just use a space
		// to indicate there should be an error, it will surely match any error.
		TestApp(t, NoTrack(fmt.Sprintf(bytesProgram, value, field)), ep, " ")
	}
	testBytes := func(field string, maxLen int) {
		goodBytes(field, "")
		goodBytes(field, strings.Repeat("a", maxLen))
		badBytes(field, strings.Repeat("a", maxLen+1))
	}

	// header
	badInt("TypeEnum", 0)
	testInt("TypeEnum", len(TxnTypeNames)-1)
	//keyreg
	testBool("Nonparticipation")
	//acfg
	goodInt("ConfigAssetTotal", 1)
	goodInt("ConfigAssetTotal", uint64(1<<63))
	goodInt("ConfigAssetDecimals", 0)
	testInt("ConfigAssetDecimals", int(ep.Proto.MaxAssetDecimals))
	testBool("ConfigAssetDefaultFrozen")
	testBytes("ConfigAssetUnitName", ep.Proto.MaxAssetUnitNameBytes)
	testBytes("ConfigAssetName", ep.Proto.MaxAssetNameBytes)
	testBytes("ConfigAssetURL", ep.Proto.MaxAssetURLBytes)
	//afrz
	testBool("FreezeAssetFrozen")
	// appl
	testInt("OnCompletion", len(OnCompletionNames)-1)
	testInt("LocalNumUint", int(ep.Proto.MaxLocalSchemaEntries))
	testInt("LocalNumByteSlice", int(ep.Proto.MaxLocalSchemaEntries))
	testInt("GlobalNumUint", int(ep.Proto.MaxGlobalSchemaEntries))
	testInt("GlobalNumByteSlice", int(ep.Proto.MaxGlobalSchemaEntries))
	testInt("ExtraProgramPages", int(ep.Proto.MaxExtraAppProgramPages))
}

func appAddr(id int) basics.Address {
	return basics.AppIndex(id).Address()
}

func TestAppPay(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

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

	// v5 added inners
	TestLogicRange(t, 5, 0, func(t *testing.T, ep *EvalParams, tx *transactions.Transaction, ledger *Ledger) {
		test := func(source string, problem ...string) {
			TestApp(t, source, ep, problem...)
		}
		ledger.NewApp(tx.Receiver, 888, basics.AppParams{})
		test("txn Sender; balance; int 0; ==;")
		test("txn Sender; txn Accounts 1; int 100"+pay, "unauthorized")
		test("global CurrentApplicationAddress; txn Accounts 1; int 100"+pay,
			"insufficient balance")
		ledger.NewAccount(appAddr(888), 1000000)

		// You might NewExpect this to fail because of min balance issue
		// (receiving account only gets 100 microalgos).  It does not fail at
		// this level, instead, we must be certain that the existing min
		// balance check in eval.transaction() properly notices and fails
		// the transaction later.  This fits with the model that we check
		// min balances once at the end of each "top-level" transaction.
		test("global CurrentApplicationAddress; txn Accounts 1; int 100" + pay)

		// 100 of 1000000 spent, plus MinTxnFee in our fake protocol is 1001
		test("global CurrentApplicationAddress; balance; int 998899; ==")
		test("txn Receiver; balance; int 100; ==")

		close := `
  itxn_begin
  int pay;      itxn_field TypeEnum
  txn Receiver; itxn_field CloseRemainderTo
  itxn_submit
  int 1
`
		test(close)
		test("global CurrentApplicationAddress; balance; !")
		// Receiver got most of the algos (except 1001 for fee)
		test("txn Receiver; balance; int 997998; ==")
	})
}

func TestAppAssetOptIn(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	// v5 added inners
	TestLogicRange(t, 5, 0, func(t *testing.T, ep *EvalParams, tx *transactions.Transaction, ledger *Ledger) {
		test := func(source string, problem ...string) {
			t.Helper()
			TestApp(t, source, ep, problem...)
		}

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
		test(axfer, "unavailable Asset 25")
		tx.ForeignAssets = append(tx.ForeignAssets, 25)
		test(axfer, "not opted in") // app account not opted in
		optin := `
itxn_begin
int axfer; itxn_field TypeEnum;
int 25;    itxn_field XferAsset;
int 0;     itxn_field AssetAmount;
global CurrentApplicationAddress; itxn_field AssetReceiver;
itxn_submit
int 1
`
		test(optin, "does not exist")
		// Asset 25
		ledger.NewAsset(tx.Sender, 25, basics.AssetParams{
			Total:     10,
			UnitName:  "x",
			AssetName: "Cross",
		})
		test(optin)

		test(axfer, "insufficient balance") // opted in, but balance=0

		// Fund the app account with the asset
		ledger.NewHolding(basics.AppIndex(888).Address(), 25, 5, false)
		test(axfer)
		test(axfer)
		test(axfer, "insufficient balance") // balance = 1, tried to move 2)
		test("global CurrentApplicationAddress; int 25; asset_holding_get AssetBalance; assert; int 1; ==")

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
		test(close)
		test("global CurrentApplicationAddress; int 25; asset_holding_get AssetBalance; !; assert; !")
	})
}

func TestRekeyPay(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	pay := `
  itxn_begin
  itxn_field Amount
  itxn_field Receiver
  itxn_field Sender
  int pay
  itxn_field TypeEnum
  itxn_submit
`

	// v5 added inners
	TestLogicRange(t, 5, 0, func(t *testing.T, ep *EvalParams, tx *transactions.Transaction, ledger *Ledger) {
		ledger.NewApp(tx.Receiver, 888, basics.AppParams{})
		TestApp(t, "txn Sender; txn Accounts 1; int 100"+pay, ep, "unauthorized")
		ledger.NewAccount(tx.Sender, 120+ep.Proto.MinTxnFee)
		ledger.Rekey(tx.Sender, basics.AppIndex(888).Address())
		TestApp(t, "txn Sender; txn Accounts 1; int 100"+pay+"; int 1", ep)
		// Note that the Sender would fail min balance check if we did it here.
		// It seems proper to wait until end of txn though.
		// See explanation in cowRoundState's Perform()
	})
}

func TestRekeyBack(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

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

	// v6 added inner rekey
	TestLogicRange(t, 6, 0, func(t *testing.T, ep *EvalParams, tx *transactions.Transaction, ledger *Ledger) {
		ledger.NewApp(tx.Receiver, 888, basics.AppParams{})
		TestApp(t, "txn Sender; balance; int 0; ==;", ep)
		TestApp(t, "txn Sender; txn Accounts 1; int 100"+payAndUnkey, ep, "unauthorized")
		ledger.NewAccount(tx.Sender, 120+3*ep.Proto.MinTxnFee)
		ledger.Rekey(tx.Sender, basics.AppIndex(888).Address())
		TestApp(t, "txn Sender; txn Accounts 1; int 100"+payAndUnkey+"; int 1", ep)
		// now rekeyed back to original
		TestApp(t, "txn Sender; txn Accounts 1; int 100"+payAndUnkey, ep, "unauthorized")
	})
}

// TestRekeyInnerGroup ensures that in an inner group, if an account is
// rekeyed, it can not be used (by the previously owning app) later in the
// group.
func TestRekeyInnerGroup(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	rekeyAndUse := `
  itxn_begin
   // pay 0 to the zero address, and rekey a junk addr
   int pay;  itxn_field TypeEnum
   global ZeroAddress; byte 0x01; b|; itxn_field RekeyTo
  itxn_next
   // try to perform the same 0 pay, but fail because tx0 gave away control
   int pay;  itxn_field TypeEnum
  itxn_submit
  int 1
`

	// v6 added inner rekey
	TestLogicRange(t, 6, 0, func(t *testing.T, ep *EvalParams, tx *transactions.Transaction, ledger *Ledger) {
		ledger.NewApp(tx.Receiver, 888, basics.AppParams{})
		// fund the app account
		ledger.NewAccount(basics.AppIndex(888).Address(), 1_000_000)
		TestApp(t, rekeyAndUse, ep, "unauthorized AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAVIOOBQA")
	})
}

func TestDefaultSender(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	pay := `
  itxn_begin
  itxn_field Amount
  itxn_field Receiver
  int pay
  itxn_field TypeEnum
  itxn_submit
`

	// v5 added inners
	TestLogicRange(t, 5, 0, func(t *testing.T, ep *EvalParams, tx *transactions.Transaction, ledger *Ledger) {
		ledger.NewApp(tx.Receiver, 888, basics.AppParams{})
		tx.Accounts = append(tx.Accounts, appAddr(888))
		TestApp(t, "txn Accounts 1; int 100"+pay, ep, "insufficient balance")
		ledger.NewAccount(appAddr(888), 1000000)
		TestApp(t, "txn Accounts 1; int 100"+pay+"int 1", ep)
		TestApp(t, "global CurrentApplicationAddress; balance; int 998899; ==", ep)
	})
}

func TestAppAxfer(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	closeWithClawback := `
  itxn_begin
  int axfer        ; itxn_field TypeEnum
  txn Sender       ; itxn_field AssetSender
  txn Sender       ; itxn_field AssetCloseTo
  itxn_submit
`
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

	// v5 added inners
	TestLogicRange(t, 5, 0, func(t *testing.T, ep *EvalParams, tx *transactions.Transaction, ledger *Ledger) {
		test := func(source string, problem ...string) {
			t.Helper()
			TestApp(t, source, ep, problem...)
		}

		test(closeWithClawback, "cannot close asset by clawback")

		ledger.NewApp(tx.Receiver, 888, basics.AppParams{})
		ledger.NewAsset(tx.Receiver, 777, basics.AssetParams{}) // not in foreign-assets of sample
		ledger.NewAsset(tx.Receiver, 77, basics.AssetParams{})  // in foreign-assets of sample
		test("txn Sender; int 777; asset_holding_get AssetBalance; assert; int 0; ==;",
			"unavailable Asset 777") // 777 not in foreign-assets
		test("txn Sender; int 77; asset_holding_get AssetBalance; assert; int 0; ==;",
			"assert failed") // because Sender not opted-in
		test("global CurrentApplicationAddress; int 77; asset_holding_get AssetBalance; assert; int 0; ==;",
			"assert failed") // app account not opted in

		ledger.NewAccount(appAddr(888), 10000) // plenty for fees

		// It should be possible to send 0 amount of an asset (existing
		// or not) to any account but ourself. Regardless of being opted in
		test("global CurrentApplicationAddress; txn Accounts 1; int 0" + axfer + "int 1")
		holding, err := ledger.AssetHolding(appAddr(888), 77)
		require.ErrorContains(t, err, "no asset 77 for account")
		require.Equal(t, uint64(0), holding.Amount)

		ledger.NewHolding(appAddr(888), 77, 3000, false)
		test("global CurrentApplicationAddress; int 77; asset_holding_get AssetBalance; assert; int 3000; ==;")

		test("txn Sender; txn Accounts 1; int 100"+axfer, "unauthorized")
		test("global CurrentApplicationAddress; txn Accounts 0; int 100"+axfer,
			fmt.Sprintf("Receiver (%s) not opted in", tx.Sender)) // txn.Sender (receiver of the axfer) isn't opted in
		test("global CurrentApplicationAddress; txn Accounts 1; int 100000"+axfer,
			"insufficient balance")

		// Temporarily remove from ForeignAssets to ensure App Account
		// doesn't get some sort of free pass to send arbitrary assets.
		save := tx.ForeignAssets
		tx.ForeignAssets = []basics.AssetIndex{6, 10}
		test("global CurrentApplicationAddress; txn Accounts 1; int 100000"+axfer,
			"unavailable Asset 77")
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

		// Here, the XferAsset is never set, so it is defaulted to 0. Therefore
		// v8 and below had no opportunity to complain about the inavailability
		// of the implied holding. Of course, there is no 0 asset, so the axfer
		// is going to fail anyway, but to keep the behavior consistent, v9
		// allows the zero asset (and zero account) in `requireHolding`.
		test("global CurrentApplicationAddress; txn Accounts 1; int 100"+noid+"int 1",
			"asset ID cannot be zero")

		test("global CurrentApplicationAddress; txn Accounts 1; int 100" + axfer + "int 1")

		// 100 of 3000 spent
		test("global CurrentApplicationAddress; int 77; asset_holding_get AssetBalance; assert; int 2900; ==")
		test("txn Accounts 1; int 77; asset_holding_get AssetBalance; assert; int 100; ==")
	})
}

func TestInnerAppl(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	appl := `
  itxn_begin
   int appl;   itxn_field TypeEnum
   int 56						// present in ForeignApps of sample txn
   itxn_field ApplicationID
  itxn_submit
  int 1
`

	// v6 added inner appls
	TestLogicRange(t, 6, 0, func(t *testing.T, ep *EvalParams, tx *transactions.Transaction, ledger *Ledger) {
		// Establish 888 as the app id, and fund it.
		ledger.NewApp(tx.Receiver, 888, basics.AppParams{})
		ledger.NewAccount(basics.AppIndex(888).Address(), 200000)

		ops := TestProg(t, "int 1", 5)
		ledger.NewApp(basics.Address{0x01}, 56, basics.AppParams{ApprovalProgram: ops.Program})
		TestApp(t, appl, ep)
	})
}

// TestExtraFields tests that the inner txn fields are not allowed to be set for
// different transaction type than the one submitted.
func TestExtraFields(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

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
	TestApp(t, "global CurrentApplicationAddress; txn Accounts 1; int 100"+pay, ep,
		"non-zero fields for type axfer")
}

func TestBadFieldV5(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

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
	partitiontest.PartitionTest(t)
	t.Parallel()

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

// TestInnerValidity logs fv and lv fields that are handled oddly (valid
// rounds are copied) so we can check if they are correct.
func TestInnerValidity(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()
	ep, tx, ledger := MakeSampleEnv()
	tx.GenesisHash = crypto.Digest{0x01, 0x02, 0x03}
	logger := TestProg(t, `
txn FirstValid; itob; log;
txn LastValid; itob; log;
int 1`, AssemblerMaxVersion)
	ledger.NewApp(tx.Receiver, 222, basics.AppParams{
		ApprovalProgram: logger.Program,
	})

	ledger.NewAccount(appAddr(888), 50_000)
	tx.ForeignApps = []basics.AppIndex{basics.AppIndex(222)}
	TestApp(t, `
itxn_begin
int appl;    itxn_field TypeEnum
int 222;     itxn_field ApplicationID
itxn_submit
itxn Logs 0; btoi; txn FirstValid; ==; assert
itxn Logs 1; btoi; txn LastValid; ==; assert
itxn FirstValid; txn FirstValid; ==; assert
itxn LastValid; txn LastValid; ==; assert
int 1
`, ep)

}

func TestNumInnerShallow(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

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
	ep.Proto.EnableInnerTransactionPooling = false
	ledger.NewApp(tx.Receiver, 888, basics.AppParams{})
	ledger.NewAccount(appAddr(888), 1000000)
	TestApp(t, pay+";int 1", ep)
	TestApp(t, pay+pay+";int 1", ep)
	TestApp(t, pay+pay+pay+";int 1", ep)
	TestApp(t, pay+pay+pay+pay+";int 1", ep)
	// In the sample proto, MaxInnerTransactions = 4
	TestApp(t, pay+pay+pay+pay+pay+";int 1", ep, "too many inner transactions")

	ep, tx, ledger = MakeSampleEnv()
	ledger.NewApp(tx.Receiver, 888, basics.AppParams{})
	ledger.NewAccount(appAddr(888), 1000000)
	TestApp(t, pay+";int 1", ep)
	TestApp(t, pay+pay+";int 1", ep)
	TestApp(t, pay+pay+pay+";int 1", ep)
	TestApp(t, pay+pay+pay+pay+";int 1", ep)
	// In the sample proto, MaxInnerTransactions = 4, but when pooling you get
	// MaxTxGroupSize (here, 8) * that.
	TestApp(t, pay+pay+pay+pay+pay+";int 1", ep)
	TestApp(t, strings.Repeat(pay, 32)+";int 1", ep)
	TestApp(t, strings.Repeat(pay, 33)+";int 1", ep, "too many inner transactions")
}

// TestNumInnerPooled ensures that inner call limits are pooled across app calls
// in a group.
func TestNumInnerPooled(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

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
	ledger := NewLedger(nil)
	ledger.NewApp(tx.Txn.Receiver, 888, basics.AppParams{})
	ledger.NewAccount(appAddr(888), 1000000)
	short := pay + ";int 1"
	long := strings.Repeat(pay, 17) + ";int 1" // More than half allowed

	grp := MakeSampleTxnGroup(tx)
	TestApps(t, []string{short, ""}, grp, LogicVersion, ledger)
	TestApps(t, []string{short, short}, grp, LogicVersion, ledger)
	TestApps(t, []string{long, ""}, grp, LogicVersion, ledger)
	TestApps(t, []string{short, long}, grp, LogicVersion, ledger)
	TestApps(t, []string{long, short}, grp, LogicVersion, ledger)
	TestApps(t, []string{long, long}, grp, LogicVersion, ledger,
		Exp(1, "too many inner transactions"))
	grp = append(grp, grp[0])
	TestApps(t, []string{short, long, long}, grp, LogicVersion, ledger,
		Exp(2, "too many inner transactions"))
	TestApps(t, []string{long, long, long}, grp, LogicVersion, ledger,
		Exp(1, "too many inner transactions"))
}

func TestAssetCreate(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	create := `
  itxn_begin
   int acfg;                   itxn_field TypeEnum
   int 1000000;                itxn_field ConfigAssetTotal
   int 3;                      itxn_field ConfigAssetDecimals
   byte "oz";                  itxn_field ConfigAssetUnitName
   byte "Gold";                itxn_field ConfigAssetName
   byte "https://gold.rush/";  itxn_field ConfigAssetURL

   // set all the addresses to something checkable
   byte 0x01; int 31; bzero; concat; itxn_field ConfigAssetManager;
   byte 0x02; int 31; bzero; concat; itxn_field ConfigAssetClawback;
   byte 0x03; int 31; bzero; concat; itxn_field ConfigAssetFreeze;
   byte 0x04; int 31; bzero; concat; itxn_field ConfigAssetReserve;

   byte 0x05; int 31; bzero; concat; itxn_field ConfigAssetMetadataHash;
  itxn_submit
  int 1
`
	// v5 added inners
	TestLogicRange(t, 5, 0, func(t *testing.T, ep *EvalParams, tx *transactions.Transaction, ledger *Ledger) {
		ledger.NewApp(tx.Receiver, 888, basics.AppParams{})
		TestApp(t, create, ep, "insufficient balance")
		// Give it enough for fee.  Recall that we don't check min balance at this level.
		ledger.NewAccount(appAddr(888), MakeTestProto().MinTxnFee)
		TestApp(t, create, ep)
		assetID := basics.AssetIndex(ledger.Counter() - 1)
		app, _, err := ledger.AssetParams(assetID)
		require.NoError(t, err)
		require.Equal(t, app.Manager, basics.Address{0x01})
		require.Equal(t, app.Clawback, basics.Address{0x02})
		require.Equal(t, app.Freeze, basics.Address{0x03})
		require.Equal(t, app.Reserve, basics.Address{0x04})

		require.Equal(t, app.MetadataHash, [32]byte{0x05})
	})
}

func TestAssetFreeze(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

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
	freeze := `
  itxn_begin
  int afrz                    ; itxn_field TypeEnum
  int 5000                    ; itxn_field FreezeAsset
  txn ApplicationArgs 0; btoi ; itxn_field FreezeAssetFrozen
  txn Accounts 1              ; itxn_field FreezeAssetAccount
  itxn_submit
  int 1
`
	missingFreezeAccount := `
  itxn_begin
  int afrz       ; itxn_field TypeEnum
  int 5000       ; itxn_field FreezeAsset
  itxn_submit
`
	missingAssetID := `
  itxn_begin
  int afrz       ; itxn_field TypeEnum
  itxn_submit
`
	// v5 added inners
	TestLogicRange(t, 5, 0, func(t *testing.T, ep *EvalParams, tx *transactions.Transaction, ledger *Ledger) {
		ledger.NewApp(tx.Receiver, 888, basics.AppParams{})
		// Give it enough for fees.  Recall that we don't check min balance at this level.
		ledger.NewAccount(appAddr(888), 12*MakeTestProto().MinTxnFee)
		TestApp(t, create, ep)

		TestApp(t, freeze, ep, "unavailable Asset 5000")
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

		// Malformed
		TestApp(t, missingFreezeAccount, ep, "freeze account cannot be empty")
		TestApp(t, missingAssetID, ep, "asset ID cannot be zero")
	})
}

func TestKeyReg(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	keyreg := `
  store 6 // StateProofPK
  store 5 // SelectionPK
  store 4 // VotePK
  store 3 // Nonparticipation
  store 2 // VoteKeyDilution
  store 1 // VoteLast
  store 0 // VoteFirst

  itxn_begin
  global CurrentApplicationAddress; itxn_field Sender
  int keyreg; itxn_field TypeEnum
  load 0; itxn_field VoteFirst
  load 1; itxn_field VoteLast
  load 2; itxn_field VoteKeyDilution
  load 3; itxn_field Nonparticipation
  load 4; itxn_field VotePK
  load 5; itxn_field SelectionPK
  load 6; itxn_field StateProofPK
  itxn_submit

  itxn TypeEnum
  int keyreg
  ==
  itxn VoteFirst
  load 0
  ==
  &&
  itxn VoteLast
  load 1
  ==
  &&
  itxn VoteKeyDilution
  load 2
  ==
  &&
  itxn Nonparticipation
  load 3
  ==
  &&
  itxn VotePK
  load 4
  ==
  &&
  itxn SelectionPK
  load 5
  ==
  &&
  itxn StateProofPK
  load 6
  ==
  &&
`

	t.Run("nonparticipating", func(t *testing.T) {
		t.Parallel()
		params := `
  int 0 // VoteFirst
  int 0 // VoteLast
  int 0 // VoteKeyDilution
  int 1 // Nonparticipation
  int 32; bzero // VotePK
  int 32; bzero // SelectionPK
  int 64; bzero // StateProofPK
`
		ep, tx, ledger := MakeSampleEnv()
		ledger.NewApp(tx.Receiver, 888, basics.AppParams{})
		ledger.NewAccount(appAddr(888), ep.Proto.MinTxnFee)
		TestApp(t, params+keyreg, ep)
	})

	t.Run("offline", func(t *testing.T) {
		t.Parallel()
		params := `
  int 0 // VoteFirst
  int 0 // VoteLast
  int 0 // VoteKeyDilution
  int 0 // Nonparticipation
  int 32; bzero // VotePK
  int 32; bzero // SelectionPK
  int 64; bzero // StateProofPK
`
		ep, tx, ledger := MakeSampleEnv()
		ledger.NewApp(tx.Receiver, 888, basics.AppParams{})
		ledger.NewAccount(appAddr(888), ep.Proto.MinTxnFee)
		TestApp(t, params+keyreg, ep)
	})

	t.Run("online without StateProofPK", func(t *testing.T) {
		t.Parallel()
		params := `
  int 100 // VoteFirst
  int 200 // VoteLast
  int 10 // VoteKeyDilution
  int 0 // Nonparticipation
  int 32; bzero; int 0; int 1; setbyte // VotePK
  int 32; bzero; int 0; int 2; setbyte // SelectionPK
  int 64; bzero // StateProofPK
`
		ep, tx, ledger := MakeSampleEnv()
		ep.Proto.EnableStateProofKeyregCheck = false
		ledger.NewApp(tx.Receiver, 888, basics.AppParams{})
		ledger.NewAccount(appAddr(888), ep.Proto.MinTxnFee)
		TestApp(t, params+keyreg, ep)
	})

	t.Run("online with StateProofPK", func(t *testing.T) {
		t.Parallel()
		params := `
  int 100 // VoteFirst
  int 16777315 // VoteLast
  int 10 // VoteKeyDilution
  int 0 // Nonparticipation
  int 32; bzero; int 0; int 1; setbyte // VotePK
  int 32; bzero; int 0; int 2; setbyte // SelectionPK
  int 64; bzero; int 0; int 3; setbyte // StateProofPK
`
		ep, tx, ledger := MakeSampleEnv()
		ep.Proto.EnableStateProofKeyregCheck = true
		ep.Proto.MaxKeyregValidPeriod = ((1 << 16) * 256) - 1 // 2^16 StateProof keys times StateProofInterval (interval)
		ledger.NewApp(tx.Receiver, 888, basics.AppParams{})
		ledger.NewAccount(appAddr(888), ep.Proto.MinTxnFee)
		TestApp(t, params+keyreg, ep)
	})

	t.Run("online with StateProofPK and too long validity period", func(t *testing.T) {
		t.Parallel()
		params := `
  int 100 // VoteFirst
  int 16777316 // VoteLast
  int 10 // VoteKeyDilution
  int 0 // Nonparticipation
  int 32; bzero; int 0; int 1; setbyte // VotePK
  int 32; bzero; int 0; int 2; setbyte // SelectionPK
  int 64; bzero; int 0; int 3; setbyte // StateProofPK
`
		ep, tx, ledger := MakeSampleEnv()
		ep.Proto.EnableStateProofKeyregCheck = true
		ep.Proto.MaxKeyregValidPeriod = ((1 << 16) * 256) - 1 // 2^16 StateProof keys times StateProofInterval (interval)
		ledger.NewApp(tx.Receiver, 888, basics.AppParams{})
		ledger.NewAccount(appAddr(888), ep.Proto.MinTxnFee)
		TestApp(t, params+keyreg, ep, "validity period for keyreg transaction is too long") // VoteLast is +1 over the limit
	})
}

func TestFieldSetting(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

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

	TestApp(t, "itxn_begin; int 64; bzero; itxn_field StateProofPK; int 1", ep)
	TestApp(t, "itxn_begin; int 63; bzero; itxn_field StateProofPK; int 1", ep,
		"StateProofPK must be 64")
	TestApp(t, "itxn_begin; int 65; bzero; itxn_field StateProofPK; int 1", ep,
		"StateProofPK must be 64")

	TestApp(t, "itxn_begin; int 0; itxn_field Nonparticipation; int 1", ep)
	TestApp(t, "itxn_begin; int 1; itxn_field Nonparticipation; int 1", ep)
	TestApp(t, NoTrack("itxn_begin; int 2; itxn_field Nonparticipation; int 1"), ep,
		"boolean is neither 1 nor 0")

	TestApp(t, "itxn_begin; int 32; bzero; itxn_field RekeyTo; int 1", ep)
	TestApp(t, "itxn_begin; int 31; bzero; itxn_field RekeyTo; int 1", ep,
		"not an address")

	TestApp(t, "itxn_begin; int 6; bzero; itxn_field ConfigAssetUnitName; int 1", ep)
	TestApp(t, NoTrack("itxn_begin; int 6; itxn_field ConfigAssetUnitName; int 1"), ep,
		"not a byte array")
	TestApp(t, "itxn_begin; int 7; bzero; itxn_field ConfigAssetUnitName; int 1", ep,
		"value is too long")

	TestApp(t, "itxn_begin; int 12; bzero; itxn_field ConfigAssetName; int 1", ep)
	TestApp(t, "itxn_begin; int 13; bzero; itxn_field ConfigAssetName; int 1", ep,
		"value is too long")
}

func TestInnerGroup(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	ep, tx, ledger := MakeSampleEnv()
	ep.FeeCredit = nil // default sample env starts at 401

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
	TestApp(t, "itxn_begin; itxn_begin"+pay+"itxn_next"+pay+"itxn_submit; int 1", ep,
		"itxn_begin without itxn_submit")
	TestApp(t, "itxn_next"+pay+"itxn_next"+pay+"itxn_submit; int 1", ep,
		"itxn_next without itxn_begin")
}

func TestInnerFeePooling(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	ep, tx, ledger := MakeSampleEnv()
	ep.FeeCredit = nil // default sample env starts at 401

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

	// Same as first, but force the second too low
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

	// Test that overpay in first inner group is available in second inner group
	// also ensure only exactly the _right_ amount of credit is available.
	TestApp(t, "itxn_begin"+
		pay+
		"int 2002; itxn_field Fee;"+ // double pay
		"itxn_next"+
		pay+
		"int 1001; itxn_field Fee;"+ // regular pay
		"itxn_submit;"+
		// At beginning of second group, we should have 1 minfee of credit
		"itxn_begin"+
		pay+
		"int 0; itxn_field Fee;"+ // free, due to credit
		"itxn_next"+
		pay+
		"itxn_submit; itxn Fee; int 1001; ==", // second one should have to pay
		ep)

}

// TestApplCreation is only determining what appl transactions can be
// constructed not what can be submitted, so it tests what "bad" fields cause
// immediate failures.
func TestApplCreation(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	ep, tx, _ := MakeSampleEnv()

	p := "itxn_begin;"
	s := "; int 1"

	TestApp(t, p+"int 31; itxn_field ApplicationID"+s, ep, "unavailable App 31")
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
		"unavailable Account")
	tx.Accounts = append(tx.Accounts, basics.Address{})
	TestApp(t, fmt.Sprintf(p+"%s"+s,
		strings.Repeat("int 32; bzero; itxn_field Accounts;", 3)), ep)
	TestApp(t, fmt.Sprintf(p+"%s"+s,
		strings.Repeat("int 32; bzero; itxn_field Accounts;", 4)), ep,
		"too many foreign accounts")

	TestApp(t, p+strings.Repeat("int 621; itxn_field Applications;", 5)+s, ep,
		"unavailable App 621")
	tx.ForeignApps = append(tx.ForeignApps, basics.AppIndex(621))
	TestApp(t, p+strings.Repeat("int 621; itxn_field Applications;", 5)+s, ep)
	TestApp(t, p+strings.Repeat("int 621; itxn_field Applications;", 6)+s, ep,
		"too many foreign apps")

	TestApp(t, p+strings.Repeat("int 621; itxn_field Assets;", 6)+s, ep,
		"unavailable Asset 621")
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

// TestBigApplCreation focues on testing the new fields that allow constructing big programs.
func TestBigApplCreation(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	p := "itxn_begin;"
	s := "; int 1"

	// Recall that in test proto, max possible program size is 2700, because
	// MaxAppProgramLen:   900
	// MaxExtraAppProgramPages: 2

	// First, test normal accummulation
	for _, pgm := range []string{"Approval", "ClearState"} {
		t.Run(pgm, func(t *testing.T) {
			t.Parallel()

			ep, _, _ := MakeSampleEnv()

			basic := "itxn_field " + pgm + "Program"
			pages := "itxn_field " + pgm + "ProgramPages"
			TestApp(t, p+`int 1000; bzero; `+pages+`
                  int 1000; bzero; `+pages+`
                  int 700; bzero; `+pages+`
                 `+s, ep)
			TestApp(t, p+`int 1000; bzero; `+pages+`
                  int 1000; bzero; `+pages+`
                  int 701; bzero; `+pages+`
                 `+s, ep, "may not exceed 2700")

			// Test the basic ApprovalProgram field resets
			TestApp(t, p+`int 1000; bzero; `+pages+`
                  int 100; bzero; `+basic+`
                  int 1000; bzero; `+pages+`
                  int 701; bzero; `+pages+`
                 `+s, ep)
			// Test that the 100 of the Approval program stayed around
			TestApp(t, p+`int 1000; bzero; `+pages+`
                  int 100; bzero; `+basic+`
                  int 1000; bzero; `+pages+`
                  int 1000; bzero; `+pages+`
                  int 600; bzero; `+pages+`
                 `+s, ep)
			TestApp(t, p+`int 1000; bzero; `+pages+`
                  int 100; bzero; `+basic+`
                  int 1000; bzero; `+pages+`
                  int 1000; bzero; `+pages+`
                  int 601; bzero; `+pages+`
                 `+s, ep, "may not exceed 2700")
		})
	}
}

// TestApplSubmission tests for checking of illegal appl transaction in form
// only.  Things where interactions between two different fields causes the
// error.  These are not exhaustive, but certainly demonstrate that
// transactions.WellFormed is getting a crack at the txn.
func TestApplSubmission(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	ep, tx, ledger := MakeSampleEnv()
	ledger.NewApp(tx.Receiver, 888, basics.AppParams{})
	// Since the fee is moved first, fund the app
	ledger.NewAccount(appAddr(888), 50_000)

	ops := TestProg(t, "int 1", AssemblerMaxVersion)
	approve := hex.EncodeToString(ops.Program)
	a := fmt.Sprintf("byte 0x%s; itxn_field ApprovalProgram;", approve)

	p := "itxn_begin; int appl; itxn_field TypeEnum;"
	s := ";itxn_submit; int 1"
	TestApp(t, p+a+s, ep, "ClearStateProgram: invalid program (empty)")

	a += fmt.Sprintf("byte 0x%s; itxn_field ClearStateProgram;", approve)

	// All zeros is v0, so we get a complaint, but that means lengths were ok when set.
	TestApp(t, p+a+`int 600; bzero; itxn_field ApprovalProgram;
                  int 600; bzero; itxn_field ClearStateProgram;`+s, ep,
		"inner app call with version v0 < v4")

	TestApp(t, p+`int 601; bzero; itxn_field ApprovalProgram;
                  int 600; bzero; itxn_field ClearStateProgram;`+s, ep, "too long")

	// WellFormed does the math based on the supplied ExtraProgramPages
	TestApp(t, p+a+`int 1; itxn_field ExtraProgramPages
                  int 1200; bzero; itxn_field ApprovalProgram;
                  int 1200; bzero; itxn_field ClearStateProgram;`+s, ep,
		"inner app call with version v0 < v4")
	TestApp(t, p+`int 1; itxn_field ExtraProgramPages
                  int 1200; bzero; itxn_field ApprovalProgram;
                  int 1201; bzero; itxn_field ClearStateProgram;`+s, ep, "too long")

	// Can't set epp when app id is given
	tx.ForeignApps = append(tx.ForeignApps, basics.AppIndex(7))
	TestApp(t, p+`int 1; itxn_field ExtraProgramPages;
                  int 7; itxn_field ApplicationID`+s, ep, "immutable")

	TestApp(t, p+a+"int 20; itxn_field GlobalNumUint; int 11; itxn_field GlobalNumByteSlice"+s,
		ep, "too large")
	TestApp(t, p+a+"int 7; itxn_field LocalNumUint; int 7; itxn_field LocalNumByteSlice"+s,
		ep, "too large")
}

func TestInnerApplCreate(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	TestLogicRange(t, 6, 0, func(t *testing.T, ep *EvalParams, tx *transactions.Transaction, ledger *Ledger) {
		v := ep.Proto.LogicSigVersion
		ledger.NewApp(tx.Receiver, 888, basics.AppParams{})
		ledger.NewAccount(appAddr(888), 50_000)

		ops := TestProg(t, "int 50", v)
		approve := "byte 0x" + hex.EncodeToString(ops.Program)

		test := func(source string, problems ...string) {
			t.Helper()
			TestApp(t, source, ep, problems...)
		}

		test(`
itxn_begin
int appl;    itxn_field TypeEnum
` + approve + `; itxn_field ApprovalProgram
` + approve + `; itxn_field ClearStateProgram
int 1;       itxn_field GlobalNumUint
int 2;       itxn_field LocalNumByteSlice
int 3;       itxn_field LocalNumUint
itxn_submit
int 1
`)

		test("int 5000; app_params_get AppGlobalNumByteSlice; assert; int 0; ==; assert",
			"unavailable App 5000")

		call := `
itxn_begin
int appl;    itxn_field TypeEnum
int 5000;    itxn_field ApplicationID
itxn_submit
int 1
`
		// Can't call it either
		test(call, "unavailable App 5000")

		tx.ForeignApps = []basics.AppIndex{basics.AppIndex(5000)}
		test(`
int 5000; app_params_get AppGlobalNumByteSlice; assert; int 0; ==; assert
int 5000; app_params_get AppGlobalNumUint;      assert; int 1; ==; assert
int 5000; app_params_get AppLocalNumByteSlice;  assert; int 2; ==; assert
int 5000; app_params_get AppLocalNumUint;       assert; int 3; ==; assert
int 1
`)
		if v >= 12 {
			// Version starts at 0
			test(`int 5000; app_params_get AppVersion; assert; !`)
		}

		// Call it (default OnComplete is NoOp)
		test(call)

		update := `
itxn_begin
int appl;    itxn_field TypeEnum
int 5000;    itxn_field ApplicationID
` + approve + `; itxn_field ApprovalProgram
` + approve + `; itxn_field ClearStateProgram
int UpdateApplication; itxn_field OnCompletion
itxn_submit
int 1
`
		test(update)

		if v >= 12 {
			// Version starts at 0
			test(`int 5000; app_params_get AppVersion; assert; int 1; ==`)
		}

		test(`
itxn_begin
int appl;              itxn_field TypeEnum
int DeleteApplication; itxn_field OnCompletion
txn Applications 1;    itxn_field ApplicationID
itxn_submit
int 1
`)

		// App is gone
		test("int 5000; app_params_get AppGlobalNumByteSlice; !; assert; !; assert; int 1")

		// Can't call it either
		test(call, "no app 5000")

	})
}

func TestCreateOldAppErrs(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	ep, tx, ledger := MakeSampleEnv()
	ledger.NewApp(tx.Receiver, 888, basics.AppParams{})
	ledger.NewAccount(appAddr(888), 50_000)

	three := "byte 0x" + hex.EncodeToString(TestProg(t, "int 1", 3).Program)

	TestApp(t, `
itxn_begin
int appl;    itxn_field TypeEnum
`+three+`; itxn_field ApprovalProgram
`+three+`; itxn_field ClearStateProgram
itxn_submit
int 1
`, ep, "inner app call with version v3 < v4")

	four := "byte 0x" + hex.EncodeToString(TestProg(t, "int 1", 4).Program)

	TestApp(t, `
itxn_begin
int appl;    itxn_field TypeEnum
`+four+`; itxn_field ApprovalProgram
`+four+`; itxn_field ClearStateProgram
itxn_submit
int 1
`, ep)

	// Version synch is only enforced for v6 and up, since it was a new rule when 6 came out.
	five := "byte 0x" + hex.EncodeToString(TestProg(t, "int 1", 5).Program)
	six := "byte 0x" + hex.EncodeToString(TestProg(t, "int 1", 6).Program)

	TestApp(t, `
itxn_begin
int appl;    itxn_field TypeEnum
`+four+`; itxn_field ApprovalProgram
`+five+`; itxn_field ClearStateProgram
itxn_submit
int 1
`, ep)

	TestApp(t, `
itxn_begin
int appl;    itxn_field TypeEnum
`+six+`; itxn_field ApprovalProgram
`+five+`; itxn_field ClearStateProgram
itxn_submit
int 1
`, ep, "program version mismatch")

	TestApp(t, `
itxn_begin
int appl;    itxn_field TypeEnum
`+five+`; itxn_field ApprovalProgram
`+six+`; itxn_field ClearStateProgram
itxn_submit
int 1
`, ep, "program version mismatch")

}

func TestSelfReentrancy(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

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
	partitiontest.PartitionTest(t)
	t.Parallel()

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
	partitiontest.PartitionTest(t)
	t.Parallel()

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
	partitiontest.PartitionTest(t)
	t.Parallel()

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
	partitiontest.PartitionTest(t)
	t.Parallel()

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
	partitiontest.PartitionTest(t)
	t.Parallel()

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
itxn_submit

itxn TxID
itxn Logs 0
==

itxn Logs 0

itxn_begin
int appl;    itxn_field TypeEnum
int 222;     itxn_field ApplicationID
itxn_submit

itxn Logs 0
!=
&&

itxn TxID
itxn Logs 0
==
&&
`, ep)

	TestApp(t, `
itxn_begin
int appl;    itxn_field TypeEnum
int 222;     itxn_field ApplicationID
itxn_next
int appl;    itxn_field TypeEnum
int 222;     itxn_field ApplicationID
itxn_submit

gitxn 0 Logs 0
gitxn 1 Logs 0
!=

gitxn 0 Logs 0
gitxn 0 TxID
==
&&

gitxn 1 Logs 0
gitxn 1 TxID
==
&&

gitxn 1 Logs 0
gitxn 0 Logs 0

itxn_begin
int appl;    itxn_field TypeEnum
int 222;     itxn_field ApplicationID
itxn_next
int appl;    itxn_field TypeEnum
int 222;     itxn_field ApplicationID
itxn_submit

gitxn 0 Logs 0
!=

gitxn 1 Logs 0
uncover 2
!=
&&
&&

gitxn 0 Logs 0
gitxn 0 TxID
==
&&

gitxn 1 Logs 0
gitxn 1 TxID
==
&&
`, ep)
}

// TestInnerGroupIDs confirms that GroupIDs are unset on size one inner groups,
// but set and unique on non-singletons
func TestInnerGroupIDs(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

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

// TestTxIDAndGroupIDCalculation tests that the TxIDs reported with `txn TxID` and group IDs
// reported with `global GroupID` are correct for top-level and inner transactions
func TestTxIDAndGroupIDCalculation(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	withoutGroupID := func(txn transactions.Transaction) transactions.Transaction {
		txn.Group = crypto.Digest{}
		return txn
	}

	type actualInfo struct {
		txn          transactions.Transaction
		claimedTxID  []byte
		claimedGroup []byte
	}

	type expectedInfo struct {
		expectedTxID  transactions.Txid
		expectedGroup crypto.Digest
	}

	// this test performs a 3-level fanout of transactions:
	//
	// Parent
	// ├─ Child A
	// │  ├── atomic group
	// │  ├─ Grandchild A-A
	// │  ├─ Grandchild A-B
	// │  ├── atomic group
	// │  ├─ Grandchild A-C
	// │  ├─ Grandchild A-D
	// ├─ Child B
	// │  ├── atomic group
	// │  ├─ Grandchild B-A
	// │  ├─ Grandchild B-B
	// │  ├── atomic group
	// │  ├─ Grandchild B-C
	// │  ├─ Grandchild B-D
	//
	// When linearized, we use the following breadth-first search ordering:
	// Parent, Child A, Child B, Grandchild A-A, Grandchild A-B, Grandchild A-C, Grandchild A-D,
	//   Grandchild B-A, Grandchild B-B, Grandchild B-C, Grandchild B-D

	// verifyTxIDs takes the linear ordering of transactions and their claimed TxIDs and GroupIDs in
	// the txnInfo array and verifies that the claimed IDs are correct
	verifyTxIDs := func(t *testing.T, unified bool, actual [11]actualInfo) {
		parentIndex := 0
		childAIndex := 1
		childBIndex := 2
		grandchildAAIndex := 3
		grandchildABIndex := 4
		grandchildACIndex := 5
		grandchildADIndex := 6
		grandchildBAIndex := 7
		grandchildBBIndex := 8
		grandchildBCIndex := 9
		grandchildBDIndex := 10

		var expected [11]expectedInfo

		parentTxID := actual[parentIndex].txn.ID()
		require.Equal(t, transactions.Txid{0x7c, 0x68, 0xa2, 0xfd, 0xcc, 0xd4, 0x1b, 0x17, 0xc4, 0xc1, 0x8a, 0x2, 0xf6, 0x2f, 0x6a, 0x85, 0xce, 0x7a, 0x71, 0xe0, 0x60, 0x9a, 0xb9, 0x85, 0xa2, 0x39, 0xc7, 0x78, 0x83, 0x41, 0xf2, 0x2}, parentTxID)
		expected[parentIndex].expectedTxID = parentTxID

		childAtxn := actual[childAIndex].txn
		childAtxid := childAtxn.InnerID(parentTxID, 0)
		require.Equal(t, transactions.Txid{0x6f, 0x8, 0xf1, 0x5f, 0xfc, 0xa5, 0x4a, 0x58, 0x6c, 0xc0, 0x80, 0x13, 0xb4, 0xb4, 0x4c, 0x19, 0x68, 0x5a, 0x66, 0xfc, 0xef, 0xe2, 0xed, 0x3c, 0xbd, 0xd5, 0x54, 0x8c, 0xb9, 0x28, 0xd0, 0x72}, childAtxid)
		expected[childAIndex].expectedTxID = childAtxid

		childBtxn := actual[childBIndex].txn
		childBtxid := childBtxn.InnerID(parentTxID, 1)
		require.Equal(t, transactions.Txid{0xcc, 0x6f, 0x61, 0xbd, 0xd5, 0x76, 0x92, 0xa0, 0x56, 0x8d, 0x45, 0xbc, 0x2c, 0x95, 0x9d, 0xe4, 0x41, 0x29, 0x2d, 0x9c, 0xd1, 0x4, 0xbb, 0xa7, 0x52, 0x63, 0x9a, 0xe3, 0x22, 0xa9, 0xf0, 0xc5}, childBtxid)
		expected[childBIndex].expectedTxID = childBtxid

		var gcAAtxid, gcABtxid, gcACtxid, gcADtxid, gcBAtxid, gcBBtxid, gcBCtxid, gcBDtxid transactions.Txid
		var gcAABgroup, gcACDgroup, gcBABgroup, gcBCDgroup crypto.Digest

		if unified {
			gcAAtxid = actual[grandchildAAIndex].txn.InnerID(childAtxid, 0)
			require.Equal(t, transactions.Txid{0x6a, 0xef, 0x5f, 0x69, 0x2b, 0xce, 0xfc, 0x5b, 0x43, 0xa, 0x23, 0x79, 0x52, 0x49, 0xc7, 0x40, 0x66, 0x29, 0xf0, 0xbe, 0x4, 0x48, 0xe4, 0x55, 0x48, 0x8, 0x53, 0xdc, 0xb, 0x8c, 0x22, 0x48}, gcAAtxid)
			gcABtxid = actual[grandchildABIndex].txn.InnerID(childAtxid, 1)
			require.Equal(t, transactions.Txid{0xd4, 0x5d, 0xf0, 0xd8, 0x24, 0x15, 0x75, 0xfc, 0xea, 0x1d, 0x5f, 0x60, 0xd4, 0x77, 0x94, 0xe4, 0xb8, 0x48, 0xbd, 0x40, 0x2d, 0xf2, 0x82, 0x8d, 0x88, 0xd5, 0xaf, 0xd0, 0xa3, 0x29, 0x63, 0xd3}, gcABtxid)
			gcAABgroup = crypto.HashObj(transactions.TxGroup{
				TxGroupHashes: []crypto.Digest{
					crypto.Digest(withoutGroupID(actual[grandchildAAIndex].txn).InnerID(childAtxid, 0)),
					crypto.Digest(withoutGroupID(actual[grandchildABIndex].txn).InnerID(childAtxid, 1)),
				},
			})
			require.Equal(t, crypto.Digest{0xb4, 0x0, 0x71, 0x2a, 0xee, 0x7f, 0x4, 0x20, 0x55, 0xf8, 0xf9, 0x8f, 0xaf, 0x12, 0x82, 0x57, 0x2, 0x45, 0xe9, 0x16, 0x45, 0x22, 0xc3, 0x22, 0xfb, 0x1a, 0x23, 0x4d, 0x78, 0xfe, 0xa1, 0x42}, gcAABgroup)

			gcACtxid = actual[grandchildACIndex].txn.InnerID(childAtxid, 2)
			require.Equal(t, transactions.Txid{0xb3, 0xb1, 0xac, 0xbe, 0x41, 0x5, 0x32, 0x9f, 0x8d, 0x22, 0x5, 0x5, 0xfe, 0x2d, 0x3, 0xb5, 0x7e, 0xcd, 0x8e, 0xbc, 0x8d, 0xf, 0x63, 0x89, 0xca, 0xa7, 0xe1, 0xdf, 0x82, 0x89, 0xd0, 0x71}, gcACtxid)
			gcADtxid = actual[grandchildADIndex].txn.InnerID(childAtxid, 3)
			require.Equal(t, transactions.Txid{0xc6, 0x8, 0x14, 0xd, 0x8f, 0xf0, 0xcf, 0xb1, 0xf4, 0x52, 0xb0, 0x3f, 0xd9, 0x15, 0x28, 0xba, 0x1c, 0xed, 0xb6, 0x8c, 0x62, 0x5e, 0x5e, 0x77, 0xde, 0xd, 0xdc, 0x26, 0xc7, 0x80, 0xbe, 0x82}, gcADtxid)
			gcACDgroup = crypto.HashObj(transactions.TxGroup{
				TxGroupHashes: []crypto.Digest{
					crypto.Digest(withoutGroupID(actual[grandchildACIndex].txn).InnerID(childAtxid, 2)),
					crypto.Digest(withoutGroupID(actual[grandchildADIndex].txn).InnerID(childAtxid, 3)),
				},
			})
			require.Equal(t, crypto.Digest{0x45, 0xce, 0x49, 0xe6, 0xa6, 0xbe, 0xa7, 0x4d, 0xb1, 0x66, 0x5d, 0xaa, 0xf6, 0xf0, 0xda, 0x78, 0x77, 0x3d, 0x6f, 0x97, 0x65, 0xd7, 0x27, 0x1, 0x82, 0x6a, 0x2c, 0xe0, 0x4c, 0xd8, 0x3b, 0x2}, gcACDgroup)

			gcBAtxid = actual[grandchildBAIndex].txn.InnerID(childBtxid, 0)
			require.Equal(t, transactions.Txid{0x13, 0x3c, 0x92, 0xab, 0x12, 0xee, 0x1c, 0xf0, 0x24, 0xd1, 0x76, 0x2e, 0x7a, 0x56, 0xcb, 0xef, 0x45, 0x19, 0x42, 0xce, 0xe5, 0x6f, 0xbc, 0xaa, 0xb3, 0x17, 0x5e, 0x59, 0x18, 0x64, 0x9e, 0xe4}, gcBAtxid)
			gcBBtxid = actual[grandchildBBIndex].txn.InnerID(childBtxid, 1)
			require.Equal(t, transactions.Txid{0x6c, 0x44, 0x79, 0x59, 0x22, 0x51, 0x5a, 0x79, 0xfe, 0xd3, 0x7c, 0xbc, 0xc4, 0x68, 0xac, 0x32, 0x77, 0x61, 0x89, 0xd0, 0xbb, 0xbd, 0xaa, 0x8d, 0xeb, 0xd4, 0x2, 0xe8, 0xd6, 0x45, 0x50, 0xf6}, gcBBtxid)
			gcBABgroup = crypto.HashObj(transactions.TxGroup{
				TxGroupHashes: []crypto.Digest{
					crypto.Digest(withoutGroupID(actual[grandchildBAIndex].txn).InnerID(childBtxid, 0)),
					crypto.Digest(withoutGroupID(actual[grandchildBBIndex].txn).InnerID(childBtxid, 1)),
				},
			})
			require.Equal(t, crypto.Digest{0x48, 0x7c, 0x9, 0x76, 0xbc, 0x43, 0x65, 0x7a, 0x1d, 0xdc, 0xfb, 0x68, 0x47, 0x12, 0x8b, 0x80, 0xd2, 0xdd, 0xff, 0x22, 0x1b, 0xe1, 0x89, 0xcc, 0xb5, 0xb3, 0x94, 0xa4, 0x49, 0x63, 0xd8, 0x10}, gcBABgroup)

			gcBCtxid = actual[grandchildBCIndex].txn.InnerID(childBtxid, 2)
			require.Equal(t, transactions.Txid{0x77, 0x48, 0x58, 0x4d, 0x94, 0x14, 0x7a, 0xf3, 0x75, 0x7f, 0x1e, 0x4d, 0xd5, 0x8, 0x21, 0x55, 0x47, 0x69, 0x67, 0x59, 0xd2, 0x48, 0xe6, 0x92, 0x1b, 0xf5, 0xae, 0x1, 0x10, 0xbe, 0x29, 0x5a}, gcBCtxid)
			gcBDtxid = actual[grandchildBDIndex].txn.InnerID(childBtxid, 3)
			require.Equal(t, transactions.Txid{0xcd, 0x15, 0x47, 0x3f, 0x42, 0xf5, 0x9c, 0x4a, 0x11, 0xa4, 0xe3, 0x92, 0x30, 0xf, 0x97, 0x1d, 0x3b, 0x1, 0x7, 0xbc, 0x1f, 0x3f, 0xcc, 0x9d, 0x43, 0x5b, 0xb2, 0xa4, 0x15, 0x8b, 0x89, 0x4e}, gcBDtxid)
			gcBCDgroup = crypto.HashObj(transactions.TxGroup{
				TxGroupHashes: []crypto.Digest{
					crypto.Digest(withoutGroupID(actual[grandchildBCIndex].txn).InnerID(childBtxid, 2)),
					crypto.Digest(withoutGroupID(actual[grandchildBDIndex].txn).InnerID(childBtxid, 3)),
				},
			})
			require.Equal(t, crypto.Digest{0x96, 0x90, 0x1, 0x64, 0x24, 0xa5, 0xda, 0x4, 0x3d, 0xd, 0x40, 0xc9, 0xf6, 0xfa, 0xc3, 0xa6, 0x26, 0x19, 0xd3, 0xf0, 0xb7, 0x28, 0x87, 0xf8, 0x5a, 0xd1, 0xa7, 0xbc, 0x1d, 0xad, 0x8b, 0xfc}, gcBCDgroup)
		} else {
			// these calculations are "wrong," but they're here to maintain backwards compatability with the original implementation

			gcAAtxid = actual[grandchildAAIndex].txn.InnerID(childAtxn.ID(), 0)
			require.Equal(t, transactions.Txid{0xb5, 0xa, 0x16, 0x90, 0x78, 0x21, 0xf6, 0x96, 0x1b, 0x9c, 0x72, 0x5e, 0xf4, 0x8b, 0xe7, 0xb8, 0x2b, 0xd, 0x74, 0xd4, 0x71, 0xa2, 0x43, 0xb0, 0xfc, 0x19, 0xbc, 0x1c, 0xda, 0x95, 0x8f, 0xd0}, gcAAtxid)
			gcABtxid = actual[grandchildABIndex].txn.InnerID(childAtxn.ID(), 1)
			require.Equal(t, transactions.Txid{0xb3, 0x9, 0x9e, 0x95, 0x79, 0xe4, 0xe4, 0x58, 0xed, 0xee, 0x1b, 0xdb, 0x21, 0x7, 0x0, 0x7b, 0x35, 0xfc, 0x19, 0xef, 0xd6, 0x61, 0xde, 0x9b, 0xf3, 0x1b, 0x4a, 0x84, 0xa, 0xa, 0x7, 0x42}, gcABtxid)
			gcAABgroup = crypto.HashObj(transactions.TxGroup{
				TxGroupHashes: []crypto.Digest{
					crypto.Digest(withoutGroupID(actual[grandchildAAIndex].txn).InnerID(childAtxn.ID(), 0)),
					crypto.Digest(withoutGroupID(actual[grandchildABIndex].txn).InnerID(childAtxn.ID(), 0)),
				},
			})
			require.Equal(t, crypto.Digest{0xbc, 0xd8, 0xa1, 0xff, 0x96, 0xd4, 0x2b, 0x39, 0xc3, 0x1e, 0x9b, 0x26, 0xf3, 0xc, 0x78, 0x18, 0x83, 0x40, 0xe0, 0xf0, 0xa5, 0xeb, 0xc3, 0x63, 0xc8, 0xac, 0xec, 0xdb, 0x1, 0x36, 0xf9, 0xa}, gcAABgroup)

			gcACtxid = actual[grandchildACIndex].txn.InnerID(childAtxn.ID(), 2)
			require.Equal(t, transactions.Txid{0xf5, 0x62, 0x52, 0xc, 0xe7, 0x4b, 0x49, 0x11, 0xd9, 0x96, 0xdb, 0x7b, 0xdc, 0x43, 0xf0, 0x89, 0x82, 0x65, 0xa9, 0x40, 0xc1, 0x1b, 0x6a, 0x5, 0x50, 0xd6, 0x96, 0x29, 0x6d, 0xe8, 0x23, 0x21}, gcACtxid)
			gcADtxid = actual[grandchildADIndex].txn.InnerID(childAtxn.ID(), 3)
			require.Equal(t, transactions.Txid{0xb2, 0x0, 0x9c, 0xae, 0x29, 0x18, 0x71, 0x19, 0xa1, 0xae, 0x82, 0x4a, 0x1d, 0xb2, 0x75, 0xaa, 0xe7, 0xbc, 0x1f, 0xcd, 0xd3, 0x9e, 0x48, 0xbb, 0x57, 0xc7, 0xbc, 0xf3, 0xab, 0xba, 0xf8, 0x3e}, gcADtxid)
			gcACDgroup = crypto.HashObj(transactions.TxGroup{
				TxGroupHashes: []crypto.Digest{
					crypto.Digest(withoutGroupID(actual[grandchildACIndex].txn).InnerID(childAtxn.ID(), 2)),
					crypto.Digest(withoutGroupID(actual[grandchildADIndex].txn).InnerID(childAtxn.ID(), 2)),
				},
			})
			require.Equal(t, crypto.Digest{0x72, 0x6d, 0xad, 0x41, 0x1c, 0x6b, 0x71, 0x1d, 0x4a, 0xe8, 0xf8, 0x82, 0x7, 0xf6, 0x37, 0xb9, 0x5d, 0x80, 0xc7, 0xf8, 0x86, 0x2d, 0xd5, 0xa1, 0x16, 0x29, 0x77, 0xc9, 0x44, 0xf7, 0x0, 0xb2}, gcACDgroup)

			gcBAtxid = actual[grandchildBAIndex].txn.InnerID(childBtxn.ID(), 0)
			require.Equal(t, transactions.Txid{0xb5, 0xa, 0x16, 0x90, 0x78, 0x21, 0xf6, 0x96, 0x1b, 0x9c, 0x72, 0x5e, 0xf4, 0x8b, 0xe7, 0xb8, 0x2b, 0xd, 0x74, 0xd4, 0x71, 0xa2, 0x43, 0xb0, 0xfc, 0x19, 0xbc, 0x1c, 0xda, 0x95, 0x8f, 0xd0}, gcBAtxid)
			gcBBtxid = actual[grandchildBBIndex].txn.InnerID(childBtxn.ID(), 1)
			require.Equal(t, transactions.Txid{0xb3, 0x9, 0x9e, 0x95, 0x79, 0xe4, 0xe4, 0x58, 0xed, 0xee, 0x1b, 0xdb, 0x21, 0x7, 0x0, 0x7b, 0x35, 0xfc, 0x19, 0xef, 0xd6, 0x61, 0xde, 0x9b, 0xf3, 0x1b, 0x4a, 0x84, 0xa, 0xa, 0x7, 0x42}, gcBBtxid)
			gcBABgroup = crypto.HashObj(transactions.TxGroup{
				TxGroupHashes: []crypto.Digest{
					crypto.Digest(withoutGroupID(actual[grandchildBAIndex].txn).InnerID(childBtxn.ID(), 0)),
					crypto.Digest(withoutGroupID(actual[grandchildBBIndex].txn).InnerID(childBtxn.ID(), 0)),
				},
			})
			require.Equal(t, crypto.Digest{0xbc, 0xd8, 0xa1, 0xff, 0x96, 0xd4, 0x2b, 0x39, 0xc3, 0x1e, 0x9b, 0x26, 0xf3, 0xc, 0x78, 0x18, 0x83, 0x40, 0xe0, 0xf0, 0xa5, 0xeb, 0xc3, 0x63, 0xc8, 0xac, 0xec, 0xdb, 0x1, 0x36, 0xf9, 0xa}, gcBABgroup)

			gcBCtxid = actual[grandchildBCIndex].txn.InnerID(childBtxn.ID(), 2)
			require.Equal(t, transactions.Txid{0xf5, 0x62, 0x52, 0xc, 0xe7, 0x4b, 0x49, 0x11, 0xd9, 0x96, 0xdb, 0x7b, 0xdc, 0x43, 0xf0, 0x89, 0x82, 0x65, 0xa9, 0x40, 0xc1, 0x1b, 0x6a, 0x5, 0x50, 0xd6, 0x96, 0x29, 0x6d, 0xe8, 0x23, 0x21}, gcBCtxid)
			gcBDtxid = actual[grandchildBDIndex].txn.InnerID(childBtxn.ID(), 3)
			require.Equal(t, transactions.Txid{0xb2, 0x0, 0x9c, 0xae, 0x29, 0x18, 0x71, 0x19, 0xa1, 0xae, 0x82, 0x4a, 0x1d, 0xb2, 0x75, 0xaa, 0xe7, 0xbc, 0x1f, 0xcd, 0xd3, 0x9e, 0x48, 0xbb, 0x57, 0xc7, 0xbc, 0xf3, 0xab, 0xba, 0xf8, 0x3e}, gcBDtxid)
			gcBCDgroup = crypto.HashObj(transactions.TxGroup{
				TxGroupHashes: []crypto.Digest{
					crypto.Digest(withoutGroupID(actual[grandchildBCIndex].txn).InnerID(childBtxn.ID(), 2)),
					crypto.Digest(withoutGroupID(actual[grandchildBDIndex].txn).InnerID(childBtxn.ID(), 2)),
				},
			})
			require.Equal(t, crypto.Digest{0x72, 0x6d, 0xad, 0x41, 0x1c, 0x6b, 0x71, 0x1d, 0x4a, 0xe8, 0xf8, 0x82, 0x7, 0xf6, 0x37, 0xb9, 0x5d, 0x80, 0xc7, 0xf8, 0x86, 0x2d, 0xd5, 0xa1, 0x16, 0x29, 0x77, 0xc9, 0x44, 0xf7, 0x0, 0xb2}, gcBCDgroup)
		}

		expected[grandchildAAIndex] = expectedInfo{
			expectedTxID:  gcAAtxid,
			expectedGroup: gcAABgroup,
		}
		expected[grandchildABIndex] = expectedInfo{
			expectedTxID:  gcABtxid,
			expectedGroup: gcAABgroup,
		}
		expected[grandchildACIndex] = expectedInfo{
			expectedTxID:  gcACtxid,
			expectedGroup: gcACDgroup,
		}
		expected[grandchildADIndex] = expectedInfo{
			expectedTxID:  gcADtxid,
			expectedGroup: gcACDgroup,
		}
		expected[grandchildBAIndex] = expectedInfo{
			expectedTxID:  gcBAtxid,
			expectedGroup: gcBABgroup,
		}
		expected[grandchildBBIndex] = expectedInfo{
			expectedTxID:  gcBBtxid,
			expectedGroup: gcBABgroup,
		}
		expected[grandchildBCIndex] = expectedInfo{
			expectedTxID:  gcBCtxid,
			expectedGroup: gcBCDgroup,
		}
		expected[grandchildBDIndex] = expectedInfo{
			expectedTxID:  gcBDtxid,
			expectedGroup: gcBCDgroup,
		}

		for i := range actual {
			require.Equal(t, expected[i].expectedTxID[:], actual[i].claimedTxID, fmt.Sprintf("index=%d", i))
			require.Equal(t, expected[i].expectedGroup[:], actual[i].claimedGroup, fmt.Sprintf("index=%d", i))
			require.Equal(t, expected[i].expectedGroup, actual[i].txn.Group, fmt.Sprintf("index=%d", i))
		}
	}

	parentAppID := basics.AppIndex(888)
	childAppID := basics.AppIndex(222)
	grandchildAppID := basics.AppIndex(333)

	grandchildSource := `
txn TxID
log

global GroupID
log

int 1
`

	childSource := `
txn TxID
log

global GroupID
log

itxn_begin
int appl;    itxn_field TypeEnum
int 333;     itxn_field ApplicationID
itxn_next
int appl;    itxn_field TypeEnum
int 333;     itxn_field ApplicationID
itxn_submit

itxn_begin
int appl;    itxn_field TypeEnum
int 333;     itxn_field ApplicationID
itxn_next
int appl;    itxn_field TypeEnum
int 333;     itxn_field ApplicationID
itxn_submit

int 1
`

	parentSource := `
txn TxID
log

global GroupID
log

itxn_begin
int appl;    itxn_field TypeEnum
int 222;     itxn_field ApplicationID
int 333;     itxn_field Applications
itxn_submit

itxn_begin
int appl;    itxn_field TypeEnum
int 222;     itxn_field ApplicationID
int 333;     itxn_field Applications
itxn_submit

int 1
`

	for _, unified := range []bool{true, false} {
		t.Run(fmt.Sprintf("unified=%t", unified), func(t *testing.T) {
			t.Parallel()
			ep, parentTx, ledger := MakeSampleEnv()
			ep.Proto.UnifyInnerTxIDs = unified

			// Whenever MakeSampleEnv() is changed to create a different
			// transaction, we must reverse those changes here, so that the
			// historic test is correct.
			parentTx.Type = protocol.PaymentTx
			parentTx.Boxes = nil
			ep.FeeCredit = nil // else inner's fee will change

			parentTx.ApplicationID = parentAppID
			parentTx.ForeignApps = []basics.AppIndex{
				childAppID,
				grandchildAppID,
			}

			grandchild := TestProg(t, grandchildSource, AssemblerMaxVersion)
			ledger.NewApp(parentTx.Receiver, grandchildAppID, basics.AppParams{
				ApprovalProgram: grandchild.Program,
			})

			child := TestProg(t, childSource, AssemblerMaxVersion)
			ledger.NewApp(parentTx.Receiver, childAppID, basics.AppParams{
				ApprovalProgram: child.Program,
			})
			ledger.NewAccount(childAppID.Address(), 50_000)

			ledger.NewApp(parentTx.Receiver, parentAppID, basics.AppParams{})
			ledger.NewAccount(parentAppID.Address(), 50_000)

			parentEd, _ := TestApp(t, parentSource, ep)

			require.Len(t, parentEd.Logs, 2)
			require.Len(t, parentEd.InnerTxns, 2)

			childA := parentEd.InnerTxns[0]
			require.Len(t, childA.EvalDelta.Logs, 2)
			require.Len(t, childA.EvalDelta.InnerTxns, 4)

			childB := parentEd.InnerTxns[1]
			require.Len(t, childB.EvalDelta.Logs, 2)
			require.Len(t, childB.EvalDelta.InnerTxns, 4)

			gcAA := childA.EvalDelta.InnerTxns[0]
			require.Len(t, gcAA.EvalDelta.Logs, 2)
			require.Len(t, gcAA.EvalDelta.InnerTxns, 0)

			gcAB := childA.EvalDelta.InnerTxns[1]
			require.Len(t, gcAB.EvalDelta.Logs, 2)
			require.Len(t, gcAB.EvalDelta.InnerTxns, 0)

			gcAC := childA.EvalDelta.InnerTxns[2]
			require.Len(t, gcAC.EvalDelta.Logs, 2)
			require.Len(t, gcAC.EvalDelta.InnerTxns, 0)

			gcAD := childA.EvalDelta.InnerTxns[3]
			require.Len(t, gcAD.EvalDelta.Logs, 2)
			require.Len(t, gcAD.EvalDelta.InnerTxns, 0)

			gcBA := childB.EvalDelta.InnerTxns[0]
			require.Len(t, gcBA.EvalDelta.Logs, 2)
			require.Len(t, gcBA.EvalDelta.InnerTxns, 0)

			gcBB := childB.EvalDelta.InnerTxns[1]
			require.Len(t, gcBB.EvalDelta.Logs, 2)
			require.Len(t, gcBB.EvalDelta.InnerTxns, 0)

			gcBC := childB.EvalDelta.InnerTxns[2]
			require.Len(t, gcBC.EvalDelta.Logs, 2)
			require.Len(t, gcBC.EvalDelta.InnerTxns, 0)

			gcBD := childB.EvalDelta.InnerTxns[3]
			require.Len(t, gcBD.EvalDelta.Logs, 2)
			require.Len(t, gcBD.EvalDelta.InnerTxns, 0)

			toVerify := [...]actualInfo{
				{
					txn:          *parentTx,
					claimedTxID:  []byte(parentEd.Logs[0]),
					claimedGroup: []byte(parentEd.Logs[1]),
				},
				{
					txn:          childA.Txn,
					claimedTxID:  []byte(childA.EvalDelta.Logs[0]),
					claimedGroup: []byte(childA.EvalDelta.Logs[1]),
				},
				{
					txn:          childB.Txn,
					claimedTxID:  []byte(childB.EvalDelta.Logs[0]),
					claimedGroup: []byte(childB.EvalDelta.Logs[1]),
				},
				{
					txn:          gcAA.Txn,
					claimedTxID:  []byte(gcAA.EvalDelta.Logs[0]),
					claimedGroup: []byte(gcAA.EvalDelta.Logs[1]),
				},
				{
					txn:          gcAB.Txn,
					claimedTxID:  []byte(gcAB.EvalDelta.Logs[0]),
					claimedGroup: []byte(gcAB.EvalDelta.Logs[1]),
				},
				{
					txn:          gcAC.Txn,
					claimedTxID:  []byte(gcAC.EvalDelta.Logs[0]),
					claimedGroup: []byte(gcAC.EvalDelta.Logs[1]),
				},
				{
					txn:          gcAD.Txn,
					claimedTxID:  []byte(gcAD.EvalDelta.Logs[0]),
					claimedGroup: []byte(gcAD.EvalDelta.Logs[1]),
				},
				{
					txn:          gcBA.Txn,
					claimedTxID:  []byte(gcBA.EvalDelta.Logs[0]),
					claimedGroup: []byte(gcBA.EvalDelta.Logs[1]),
				},
				{
					txn:          gcBB.Txn,
					claimedTxID:  []byte(gcBB.EvalDelta.Logs[0]),
					claimedGroup: []byte(gcBB.EvalDelta.Logs[1]),
				},
				{
					txn:          gcBC.Txn,
					claimedTxID:  []byte(gcBC.EvalDelta.Logs[0]),
					claimedGroup: []byte(gcBC.EvalDelta.Logs[1]),
				},
				{
					txn:          gcBD.Txn,
					claimedTxID:  []byte(gcBD.EvalDelta.Logs[0]),
					claimedGroup: []byte(gcBD.EvalDelta.Logs[1]),
				},
			}

			verifyTxIDs(t, unified, toVerify)
		})
	}
}

// TestInnerTxIDCalculation tests that the TxIDs reported with `itxn TxID` and `gitxn X TxID` are
// correct for inner transactions
func TestInnerTxIDCalculation(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	type actualInfo struct {
		txn         transactions.Transaction
		claimedTxID []byte
	}

	// this test performs a 3-level fanout of transactions:
	//
	// Parent
	// ├─ Child A
	// │  ├── atomic group
	// │  ├─ Grandchild A-A
	// │  ├─ Grandchild A-B
	// │  ├── atomic group
	// │  ├─ Grandchild A-C
	// │  ├─ Grandchild A-D
	// ├─ Child B
	// │  ├── atomic group
	// │  ├─ Grandchild B-A
	// │  ├─ Grandchild B-B
	// │  ├── atomic group
	// │  ├─ Grandchild B-C
	// │  ├─ Grandchild B-D
	//
	// When linearized, we use the following breadth-first search ordering:
	// Parent, Child A, Child B, Grandchild A-A, Grandchild A-B, Grandchild A-C, Grandchild A-D,
	//   Grandchild B-A, Grandchild B-B, Grandchild B-C, Grandchild B-D

	// verifyTxIDs takes the linear ordering of transactions and their claimed TxIDs in the txnInfo
	// array and verifies that the claimed IDs are correct
	verifyTxIDs := func(t *testing.T, unified bool, actual [11]actualInfo) {
		parentIndex := 0
		childAIndex := 1
		childBIndex := 2
		grandchildAAIndex := 3
		grandchildABIndex := 4
		grandchildACIndex := 5
		grandchildADIndex := 6
		grandchildBAIndex := 7
		grandchildBBIndex := 8
		grandchildBCIndex := 9
		grandchildBDIndex := 10

		var expected [11]transactions.Txid

		parentTxID := actual[parentIndex].txn.ID()
		require.Equal(t, transactions.Txid{0x7c, 0x68, 0xa2, 0xfd, 0xcc, 0xd4, 0x1b, 0x17, 0xc4, 0xc1, 0x8a, 0x2, 0xf6, 0x2f, 0x6a, 0x85, 0xce, 0x7a, 0x71, 0xe0, 0x60, 0x9a, 0xb9, 0x85, 0xa2, 0x39, 0xc7, 0x78, 0x83, 0x41, 0xf2, 0x2}, parentTxID)
		// leave expected[parentIndex] as the zero value since we don't want to test it

		childAtxn := actual[childAIndex].txn
		childBtxn := actual[childBIndex].txn

		var childAtxid, childBtxid, gcAAtxid, gcABtxid, gcACtxid, gcADtxid, gcBAtxid, gcBBtxid, gcBCtxid, gcBDtxid transactions.Txid

		if unified {
			childAtxid = childAtxn.InnerID(parentTxID, 0)
			require.Equal(t, transactions.Txid{0x6f, 0x8, 0xf1, 0x5f, 0xfc, 0xa5, 0x4a, 0x58, 0x6c, 0xc0, 0x80, 0x13, 0xb4, 0xb4, 0x4c, 0x19, 0x68, 0x5a, 0x66, 0xfc, 0xef, 0xe2, 0xed, 0x3c, 0xbd, 0xd5, 0x54, 0x8c, 0xb9, 0x28, 0xd0, 0x72}, childAtxid)
			childBtxid = childBtxn.InnerID(parentTxID, 1)
			require.Equal(t, transactions.Txid{0xcc, 0x6f, 0x61, 0xbd, 0xd5, 0x76, 0x92, 0xa0, 0x56, 0x8d, 0x45, 0xbc, 0x2c, 0x95, 0x9d, 0xe4, 0x41, 0x29, 0x2d, 0x9c, 0xd1, 0x4, 0xbb, 0xa7, 0x52, 0x63, 0x9a, 0xe3, 0x22, 0xa9, 0xf0, 0xc5}, childBtxid)

			gcAAtxid = actual[grandchildAAIndex].txn.InnerID(childAtxid, 0)
			require.Equal(t, transactions.Txid{0x6a, 0xef, 0x5f, 0x69, 0x2b, 0xce, 0xfc, 0x5b, 0x43, 0xa, 0x23, 0x79, 0x52, 0x49, 0xc7, 0x40, 0x66, 0x29, 0xf0, 0xbe, 0x4, 0x48, 0xe4, 0x55, 0x48, 0x8, 0x53, 0xdc, 0xb, 0x8c, 0x22, 0x48}, gcAAtxid)
			gcABtxid = actual[grandchildABIndex].txn.InnerID(childAtxid, 1)
			require.Equal(t, transactions.Txid{0xd4, 0x5d, 0xf0, 0xd8, 0x24, 0x15, 0x75, 0xfc, 0xea, 0x1d, 0x5f, 0x60, 0xd4, 0x77, 0x94, 0xe4, 0xb8, 0x48, 0xbd, 0x40, 0x2d, 0xf2, 0x82, 0x8d, 0x88, 0xd5, 0xaf, 0xd0, 0xa3, 0x29, 0x63, 0xd3}, gcABtxid)

			gcACtxid = actual[grandchildACIndex].txn.InnerID(childAtxid, 2)
			require.Equal(t, transactions.Txid{0xb3, 0xb1, 0xac, 0xbe, 0x41, 0x5, 0x32, 0x9f, 0x8d, 0x22, 0x5, 0x5, 0xfe, 0x2d, 0x3, 0xb5, 0x7e, 0xcd, 0x8e, 0xbc, 0x8d, 0xf, 0x63, 0x89, 0xca, 0xa7, 0xe1, 0xdf, 0x82, 0x89, 0xd0, 0x71}, gcACtxid)
			gcADtxid = actual[grandchildADIndex].txn.InnerID(childAtxid, 3)
			require.Equal(t, transactions.Txid{0xc6, 0x8, 0x14, 0xd, 0x8f, 0xf0, 0xcf, 0xb1, 0xf4, 0x52, 0xb0, 0x3f, 0xd9, 0x15, 0x28, 0xba, 0x1c, 0xed, 0xb6, 0x8c, 0x62, 0x5e, 0x5e, 0x77, 0xde, 0xd, 0xdc, 0x26, 0xc7, 0x80, 0xbe, 0x82}, gcADtxid)

			gcBAtxid = actual[grandchildBAIndex].txn.InnerID(childBtxid, 0)
			require.Equal(t, transactions.Txid{0x13, 0x3c, 0x92, 0xab, 0x12, 0xee, 0x1c, 0xf0, 0x24, 0xd1, 0x76, 0x2e, 0x7a, 0x56, 0xcb, 0xef, 0x45, 0x19, 0x42, 0xce, 0xe5, 0x6f, 0xbc, 0xaa, 0xb3, 0x17, 0x5e, 0x59, 0x18, 0x64, 0x9e, 0xe4}, gcBAtxid)
			gcBBtxid = actual[grandchildBBIndex].txn.InnerID(childBtxid, 1)
			require.Equal(t, transactions.Txid{0x6c, 0x44, 0x79, 0x59, 0x22, 0x51, 0x5a, 0x79, 0xfe, 0xd3, 0x7c, 0xbc, 0xc4, 0x68, 0xac, 0x32, 0x77, 0x61, 0x89, 0xd0, 0xbb, 0xbd, 0xaa, 0x8d, 0xeb, 0xd4, 0x2, 0xe8, 0xd6, 0x45, 0x50, 0xf6}, gcBBtxid)

			gcBCtxid = actual[grandchildBCIndex].txn.InnerID(childBtxid, 2)
			require.Equal(t, transactions.Txid{0x77, 0x48, 0x58, 0x4d, 0x94, 0x14, 0x7a, 0xf3, 0x75, 0x7f, 0x1e, 0x4d, 0xd5, 0x8, 0x21, 0x55, 0x47, 0x69, 0x67, 0x59, 0xd2, 0x48, 0xe6, 0x92, 0x1b, 0xf5, 0xae, 0x1, 0x10, 0xbe, 0x29, 0x5a}, gcBCtxid)
			gcBDtxid = actual[grandchildBDIndex].txn.InnerID(childBtxid, 3)
			require.Equal(t, transactions.Txid{0xcd, 0x15, 0x47, 0x3f, 0x42, 0xf5, 0x9c, 0x4a, 0x11, 0xa4, 0xe3, 0x92, 0x30, 0xf, 0x97, 0x1d, 0x3b, 0x1, 0x7, 0xbc, 0x1f, 0x3f, 0xcc, 0x9d, 0x43, 0x5b, 0xb2, 0xa4, 0x15, 0x8b, 0x89, 0x4e}, gcBDtxid)
		} else {
			// these calculations are "wrong," but they're here to maintain backwards compatability with the original implementation

			childAtxid = childAtxn.ID()
			require.Equal(t, transactions.Txid{0xc9, 0xa4, 0x41, 0xff, 0x9c, 0x62, 0x40, 0x6e, 0x63, 0xd9, 0x5, 0x19, 0x3b, 0x32, 0x43, 0x3d, 0xba, 0x80, 0x9f, 0xa3, 0xe4, 0xed, 0x2f, 0xa4, 0x19, 0x2b, 0x3f, 0x21, 0x96, 0xe2, 0xec, 0x21}, childAtxid)
			childBtxid = childBtxn.ID()
			require.Equal(t, transactions.Txid{0xc9, 0xa4, 0x41, 0xff, 0x9c, 0x62, 0x40, 0x6e, 0x63, 0xd9, 0x5, 0x19, 0x3b, 0x32, 0x43, 0x3d, 0xba, 0x80, 0x9f, 0xa3, 0xe4, 0xed, 0x2f, 0xa4, 0x19, 0x2b, 0x3f, 0x21, 0x96, 0xe2, 0xec, 0x21}, childBtxid)

			gcAAtxid = actual[grandchildAAIndex].txn.InnerID(parentTxID, 0)
			require.Equal(t, transactions.Txid{0x9e, 0xfb, 0xb7, 0x5f, 0x2b, 0x9a, 0x59, 0x5f, 0xce, 0x3c, 0x90, 0x60, 0x66, 0x40, 0x4e, 0x80, 0x81, 0x90, 0x79, 0x51, 0xd2, 0x8f, 0xfe, 0xbf, 0x71, 0x76, 0x23, 0xc8, 0xd8, 0xb0, 0x28, 0x7d}, gcAAtxid)
			gcABtxid = actual[grandchildABIndex].txn.InnerID(parentTxID, 1)
			require.Equal(t, transactions.Txid{0x91, 0x9d, 0xdc, 0x8, 0xde, 0x4e, 0x86, 0xe8, 0xba, 0xa3, 0x2, 0xf6, 0x7, 0xe9, 0x1a, 0x6, 0x63, 0xe9, 0x46, 0xa8, 0xe4, 0xa1, 0x3e, 0xd3, 0x3e, 0xa4, 0x5c, 0xcb, 0xc0, 0xc5, 0x40, 0x55}, gcABtxid)

			// because of caching, these are the same :(
			gcACtxid = gcAAtxid
			gcADtxid = gcABtxid

			gcBAtxid = actual[grandchildBAIndex].txn.InnerID(parentTxID, 1)
			require.Equal(t, transactions.Txid{0x91, 0x9d, 0xdc, 0x8, 0xde, 0x4e, 0x86, 0xe8, 0xba, 0xa3, 0x2, 0xf6, 0x7, 0xe9, 0x1a, 0x6, 0x63, 0xe9, 0x46, 0xa8, 0xe4, 0xa1, 0x3e, 0xd3, 0x3e, 0xa4, 0x5c, 0xcb, 0xc0, 0xc5, 0x40, 0x55}, gcBAtxid)
			gcBBtxid = actual[grandchildBBIndex].txn.InnerID(parentTxID, 2)
			require.Equal(t, transactions.Txid{0xa6, 0x90, 0x75, 0xf9, 0x20, 0x15, 0xd7, 0xf5, 0xa2, 0xca, 0xaa, 0x4b, 0x55, 0xdf, 0x8e, 0xa9, 0x97, 0xd8, 0x62, 0xc9, 0xb8, 0xdf, 0xc2, 0x8f, 0x9c, 0x60, 0x67, 0x2a, 0xdb, 0x27, 0xaa, 0x4d}, gcBBtxid)

			gcBCtxid = gcBAtxid
			gcBDtxid = gcBBtxid
		}

		expected[childBIndex] = childBtxid
		expected[childAIndex] = childAtxid
		expected[grandchildAAIndex] = gcAAtxid
		expected[grandchildABIndex] = gcABtxid
		expected[grandchildACIndex] = gcACtxid
		expected[grandchildADIndex] = gcADtxid
		expected[grandchildBAIndex] = gcBAtxid
		expected[grandchildBBIndex] = gcBBtxid
		expected[grandchildBCIndex] = gcBCtxid
		expected[grandchildBDIndex] = gcBDtxid

		for i := range actual {
			if i == 0 {
				// don't test parent TxID
				continue
			}
			require.Equal(t, expected[i][:], actual[i].claimedTxID, fmt.Sprintf("index=%d", i))
		}
	}

	parentAppID := basics.AppIndex(888)
	childAppID := basics.AppIndex(222)
	grandchildAppID := basics.AppIndex(333)

	grandchildSource := "int 1"
	childSource := `
itxn_begin
int appl;    itxn_field TypeEnum
int 333;     itxn_field ApplicationID
itxn_next
int appl;    itxn_field TypeEnum
int 333;     itxn_field ApplicationID
itxn_submit

gitxn 0 TxID
log
gitxn 1 TxID
log

itxn_begin
int appl;    itxn_field TypeEnum
int 333;     itxn_field ApplicationID
itxn_next
int appl;    itxn_field TypeEnum
int 333;     itxn_field ApplicationID
itxn_submit

gitxn 0 TxID
log
gitxn 1 TxID
log

int 1
`
	parentSource := `
itxn_begin
int appl;    itxn_field TypeEnum
int 222;     itxn_field ApplicationID
int 333;     itxn_field Applications
itxn_submit

itxn TxID
log

itxn_begin
int appl;    itxn_field TypeEnum
int 222;     itxn_field ApplicationID
int 333;     itxn_field Applications
itxn_submit

itxn TxID
log

int 1
`

	for _, unified := range []bool{true, false} {
		t.Run(fmt.Sprintf("unified=%t", unified), func(t *testing.T) {
			t.Parallel()
			ep, parentTx, ledger := MakeSampleEnv()
			ep.Proto.UnifyInnerTxIDs = unified

			// Whenever MakeSampleEnv() is changed to create a different
			// transaction, we must reverse those changes here, so that the
			// historic test is correct.
			parentTx.Type = protocol.PaymentTx
			parentTx.Boxes = nil
			ep.FeeCredit = nil // else inner's fee will change

			parentTx.ApplicationID = parentAppID
			parentTx.ForeignApps = []basics.AppIndex{
				childAppID,
				grandchildAppID,
			}

			grandchild := TestProg(t, grandchildSource, AssemblerMaxVersion)
			ledger.NewApp(parentTx.Receiver, grandchildAppID, basics.AppParams{
				ApprovalProgram: grandchild.Program,
			})

			child := TestProg(t, childSource, AssemblerMaxVersion)
			ledger.NewApp(parentTx.Receiver, childAppID, basics.AppParams{
				ApprovalProgram: child.Program,
			})
			ledger.NewAccount(childAppID.Address(), 50_000)

			ledger.NewApp(parentTx.Receiver, parentAppID, basics.AppParams{})
			ledger.NewAccount(parentAppID.Address(), 50_000)

			parentEd, _ := TestApp(t, parentSource, ep)

			require.Len(t, parentEd.Logs, 2)
			require.Len(t, parentEd.InnerTxns, 2)

			childA := parentEd.InnerTxns[0]
			require.Len(t, childA.EvalDelta.Logs, 4)
			require.Len(t, childA.EvalDelta.InnerTxns, 4)

			childB := parentEd.InnerTxns[1]
			require.Len(t, childB.EvalDelta.Logs, 4)
			require.Len(t, childB.EvalDelta.InnerTxns, 4)

			gcAA := childA.EvalDelta.InnerTxns[0]
			require.Len(t, gcAA.EvalDelta.Logs, 0)
			require.Len(t, gcAA.EvalDelta.InnerTxns, 0)

			gcAB := childA.EvalDelta.InnerTxns[1]
			require.Len(t, gcAB.EvalDelta.Logs, 0)
			require.Len(t, gcAB.EvalDelta.InnerTxns, 0)

			gcAC := childA.EvalDelta.InnerTxns[2]
			require.Len(t, gcAC.EvalDelta.Logs, 0)
			require.Len(t, gcAC.EvalDelta.InnerTxns, 0)

			gcAD := childA.EvalDelta.InnerTxns[3]
			require.Len(t, gcAD.EvalDelta.Logs, 0)
			require.Len(t, gcAD.EvalDelta.InnerTxns, 0)

			gcBA := childB.EvalDelta.InnerTxns[0]
			require.Len(t, gcBA.EvalDelta.Logs, 0)
			require.Len(t, gcBA.EvalDelta.InnerTxns, 0)

			gcBB := childB.EvalDelta.InnerTxns[1]
			require.Len(t, gcBB.EvalDelta.Logs, 0)
			require.Len(t, gcBB.EvalDelta.InnerTxns, 0)

			gcBC := childB.EvalDelta.InnerTxns[2]
			require.Len(t, gcBC.EvalDelta.Logs, 0)
			require.Len(t, gcBC.EvalDelta.InnerTxns, 0)

			gcBD := childB.EvalDelta.InnerTxns[3]
			require.Len(t, gcBD.EvalDelta.Logs, 0)
			require.Len(t, gcBD.EvalDelta.InnerTxns, 0)

			toVerify := [...]actualInfo{
				{
					txn: *parentTx,
					// leave claimedTxID as the zero value since we don't want to test it
				},
				{
					txn:         childA.Txn,
					claimedTxID: []byte(parentEd.Logs[0]),
				},
				{
					txn:         childB.Txn,
					claimedTxID: []byte(parentEd.Logs[1]),
				},
				{
					txn:         gcAA.Txn,
					claimedTxID: []byte(childA.EvalDelta.Logs[0]),
				},
				{
					txn:         gcAB.Txn,
					claimedTxID: []byte(childA.EvalDelta.Logs[1]),
				},
				{
					txn:         gcAC.Txn,
					claimedTxID: []byte(childA.EvalDelta.Logs[2]),
				},
				{
					txn:         gcAD.Txn,
					claimedTxID: []byte(childA.EvalDelta.Logs[3]),
				},
				{
					txn:         gcBA.Txn,
					claimedTxID: []byte(childB.EvalDelta.Logs[0]),
				},
				{
					txn:         gcBB.Txn,
					claimedTxID: []byte(childB.EvalDelta.Logs[1]),
				},
				{
					txn:         gcBC.Txn,
					claimedTxID: []byte(childB.EvalDelta.Logs[2]),
				},
				{
					txn:         gcBD.Txn,
					claimedTxID: []byte(childB.EvalDelta.Logs[3]),
				},
			}

			verifyTxIDs(t, unified, toVerify)
		})
	}
}

func TestInnerTxIDCaching(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	parentAppID := basics.AppIndex(888)
	childAppID := basics.AppIndex(222)

	for _, unified := range []bool{true, false} {
		t.Run(fmt.Sprintf("unified=%t", unified), func(t *testing.T) {
			t.Parallel()
			ep, parentTx, ledger := MakeSampleEnv()
			ep.Proto.UnifyInnerTxIDs = unified

			shouldIDsBeEqual := byte(1)
			if unified {
				shouldIDsBeEqual = 0
			}

			parentTx.ApplicationID = parentAppID
			parentTx.ForeignApps = []basics.AppIndex{childAppID}
			parentTx.ApplicationArgs = [][]byte{{shouldIDsBeEqual}}

			child := TestProg(t, "int 1", AssemblerMaxVersion)
			ledger.NewApp(parentTx.Receiver, childAppID, basics.AppParams{
				ApprovalProgram: child.Program,
			})
			ledger.NewAccount(childAppID.Address(), 50_000)

			ledger.NewApp(parentTx.Receiver, parentAppID, basics.AppParams{})
			ledger.NewAccount(parentAppID.Address(), 50_000)

			// does `gitxn 0 TxID` hit the cache for `gtxn 0 TxID`?
			TestApp(t, `
gtxn 0 TxID
txn TxID
==
assert

itxn_begin
int appl;    itxn_field TypeEnum
int 222;     itxn_field ApplicationID
itxn_next
int appl;    itxn_field TypeEnum
int 222;     itxn_field ApplicationID
itxn_submit

gitxn 0 TxID
gtxn 0 TxID
==
txn ApplicationArgs 0
btoi
==
`, ep)

			// does `gtxn 0 TxID` hit the cache for `gitxn 0 TxID`?
			TestApp(t, `
itxn_begin
int appl;    itxn_field TypeEnum
int 222;     itxn_field ApplicationID
itxn_next
int appl;    itxn_field TypeEnum
int 222;     itxn_field ApplicationID
itxn_submit

gitxn 0 TxID
gtxn 0 TxID
==
txn ApplicationArgs 0
btoi
==
`, ep)

			// does the cache for `gitxn 0 TxID` reset after another inner executes?
			TestApp(t, `
itxn_begin
int appl;    itxn_field TypeEnum
int 222;     itxn_field ApplicationID
itxn_next
int appl;    itxn_field TypeEnum
int 222;     itxn_field ApplicationID
itxn_submit

gitxn 0 TxID

itxn_begin
int appl;    itxn_field TypeEnum
int 222;     itxn_field ApplicationID
itxn_next
int appl;    itxn_field TypeEnum
int 222;     itxn_field ApplicationID
itxn_submit

gitxn 0 TxID
==
txn ApplicationArgs 0
btoi
==
`, ep)
		})
	}
}

// TestGtixn confirms access to itxn groups
func TestGtixn(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

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
	tx.ForeignApps = []basics.AppIndex{222, 333, 444}

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

int 0
gitxnas 1 Logs
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
	partitiontest.PartitionTest(t)
	t.Parallel()

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
	tx.ForeignApps = []basics.AppIndex{222, 333}

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
	partitiontest.PartitionTest(t)
	t.Parallel()

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
	`+fmt.Sprintf("byte 0x%s", hex.EncodeToString(ops.Program))+`
dup
itxn_field ApprovalProgram;
itxn_field ClearStateProgram;
itxn_next
int appl;    itxn_field TypeEnum
	`+fmt.Sprintf("byte 0x%s;", hex.EncodeToString(ops.Program))+`
dup
itxn_field ApprovalProgram;
itxn_field ClearStateProgram;
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
	partitiontest.PartitionTest(t)
	t.Parallel()

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
	partitiontest.PartitionTest(t)
	t.Parallel()

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
	partitiontest.PartitionTest(t)
	t.Parallel()

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

	ep, tx, ledger := MakeSampleEnv()

	tx.Type = protocol.ApplicationCallTx
	tx.ApplicationID = 888
	tx.ForeignApps = []basics.AppIndex{basics.AppIndex(222)}

	ledger.NewApp(tx.Receiver, 222, basics.AppParams{
		ApprovalProgram: TestProg(t, pay+pay+pay+"int 1;", AssemblerMaxVersion).Program,
	})

	ledger.NewApp(tx.Receiver, 888, basics.AppParams{})
	ledger.NewAccount(appAddr(888), 1_000_000)

	callpay3 := `itxn_begin
int appl;    itxn_field TypeEnum
int 222;     itxn_field ApplicationID
itxn_submit
`
	TestApp(t, callpay3+"int 1", ep, "insufficient balance") // inner contract needs money

	ledger.NewAccount(appAddr(222), 1_000_000)
	TestApp(t, callpay3+"int 1", ep)
	// Each use of callpay3 is 4 inners total, so 8 is ok. (32 allowed in test ep)
	TestApp(t, strings.Repeat(callpay3, 8)+"int 1", ep)
	TestApp(t, strings.Repeat(callpay3, 9)+"int 1", ep, "too many inner transactions")
}

// TestCreateAndUse checks that an ASA can be created in an inner app, and then
// used.  This was not allowed until v6, because of the strict adherence to the
// foreign-arrays rules.
func TestCreateAndUse(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	axfer := `
  itxn_begin
   int acfg;    itxn_field TypeEnum
   int 10;      itxn_field ConfigAssetTotal
   byte "Gold"; itxn_field ConfigAssetName
  itxn_submit

  itxn_begin
   int axfer;           itxn_field TypeEnum
   itxn CreatedAssetID; itxn_field XferAsset
   txn Sender;          itxn_field AssetReceiver
  itxn_submit

  int 1
`

	// First testing use in axfer, start at v5 so that the failure is tested
	TestLogicRange(t, 5, 0, func(t *testing.T, ep *EvalParams, tx *transactions.Transaction, ledger *Ledger) {
		v := ep.Proto.LogicSigVersion
		test := func(source string, problems ...string) {
			t.Helper()
			TestApp(t, source, ep, problems...)
		}

		ledger.NewApp(tx.Receiver, 888, basics.AppParams{})
		ledger.NewAccount(appAddr(888), 4*MakeTestProto().MinTxnFee)

		if v < CreatedResourcesVersion {
			test(axfer, "unavailable Asset")
		} else {
			test(axfer)
		}
	})

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

	// Now test use in asset balance opcode, over the same range
	TestLogicRange(t, 5, 0, func(t *testing.T, ep *EvalParams, tx *transactions.Transaction, ledger *Ledger) {
		v := ep.Proto.LogicSigVersion
		test := func(source string, problems ...string) {
			t.Helper()
			TestApp(t, source, ep, problems...)
		}

		ledger.NewApp(tx.Receiver, 888, basics.AppParams{})
		ledger.NewAccount(appAddr(888), 4*MakeTestProto().MinTxnFee)

		if v < CreatedResourcesVersion {
			test(balance, "unavailable Asset "+strconv.Itoa(FirstTestID))
		} else {
			test(balance)
		}
	})

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

	// Now as ForeignAsset (starts in v6, when inner app calls allowed)
	TestLogicRange(t, 6, 0, func(t *testing.T, ep *EvalParams, tx *transactions.Transaction, ledger *Ledger) {
		test := func(source string, problems ...string) {
			TestApp(t, source, ep, problems...)
		}

		ledger.NewApp(tx.Receiver, 888, basics.AppParams{})
		ledger.NewApp(tx.Receiver, 888, basics.AppParams{})
		ledger.NewAccount(appAddr(888), 4*MakeTestProto().MinTxnFee)
		// It gets passed the Assets setting
		test(appcall, "attempt to self-call")
		// Appcall is isn't allowed pre-6, so there's no point in this loop
		// checking v5.
	})
}

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

func hexProgram(t *testing.T, source string, v uint64) string {
	return "0x" + hex.EncodeToString(TestProg(t, source, v).Program)
}

// TestCreateAndSeeApp checks that an app can be created in an inner txn, and then
// the address for it can be looked up.
func TestCreateSeeApp(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	TestLogicRange(t, CreatedResourcesVersion, 0, func(t *testing.T, ep *EvalParams, tx *transactions.Transaction, ledger *Ledger) {
		ledger.NewApp(tx.Receiver, 888, basics.AppParams{})
		ledger.NewAccount(appAddr(888), 1*MakeTestProto().MinTxnFee)
		createAndUse := `
  itxn_begin
   int appl;     itxn_field TypeEnum
   byte	` + hexProgram(t, main(""), 5) + `; dup; itxn_field ApprovalProgram; itxn_field ClearStateProgram;
  itxn_submit

  itxn CreatedApplicationID; app_params_get AppAddress; assert
  addr ` + appAddr(5000).String() + `
  ==
`
		TestApp(t, createAndUse, ep)
		// Again, can't test if this (properly) fails in previous version, because
		// we can't even create apps this way in previous version.
	})
}

// TestCreateAndPay checks that an app can be created in an inner app, and then
// a pay can be done to the app's account.  This was not allowed until v6,
// because of the strict adherence to the foreign-accounts rules.
func TestCreateAndPay(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	TestLogicRange(t, CreatedResourcesVersion, 0, func(t *testing.T, ep *EvalParams, tx *transactions.Transaction, ledger *Ledger) {
		v := ep.Proto.LogicSigVersion
		pay5back := main(`
itxn_begin
int pay;    itxn_field TypeEnum
txn Sender; itxn_field Receiver
int 5;      itxn_field Amount
itxn_submit
int 1
`)

		createAndPay := `
  itxn_begin
   int appl;    itxn_field TypeEnum
	` + fmt.Sprintf("byte %s", hexProgram(t, pay5back, v)) + `
  dup
  itxn_field ApprovalProgram;
  itxn_field ClearStateProgram;
  itxn_submit

  itxn_begin
   int pay;                   itxn_field TypeEnum
   itxn CreatedApplicationID; app_params_get AppAddress; assert; itxn_field Receiver
   int 10;                    itxn_field Amount
  itxn_submit

  int 1
`

		ledger.NewApp(tx.Receiver, 888, basics.AppParams{})
		ledger.NewAccount(appAddr(888), 10*MakeTestProto().MinTxnFee)
		TestApp(t, createAndPay, ep)

		// This test is impossible because CreatedResourcesVersion is also when
		// inner txns could make apps.
		// ep.Proto = MakeTestProtoV(CreatedResourcesVersion - 1)
		// TestApp(t, createAndPay, ep, "invalid Address reference")
	})
}

// TestInnerGaid ensures there's no confusion over the tracking of ids
// across multiple inner transaction groups
func TestInnerGaid(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	ep, tx, ledger := MakeSampleEnv()
	ep.Proto.MaxInnerTransactions = 100
	// App to log the aid of slot[apparg[0]]
	logGaid := TestProg(t, `txn ApplicationArgs 0; btoi; gaids; itob; log; int 1`, AssemblerMaxVersion)
	ledger.NewApp(tx.Receiver, 222, basics.AppParams{
		ApprovalProgram: logGaid.Program,
	})

	ledger.NewApp(tx.Receiver, 888, basics.AppParams{})
	ledger.NewAccount(appAddr(888), 50_000)
	tx.ForeignApps = []basics.AppIndex{basics.AppIndex(222)}
	TestApp(t, `itxn_begin
int acfg;    itxn_field TypeEnum
itxn_next
int pay;      itxn_field TypeEnum
txn Sender;   itxn_field Receiver
itxn_next
int appl;    itxn_field TypeEnum
int 222;     itxn_field ApplicationID
int 0; itob; itxn_field ApplicationArgs
itxn_submit
itxn Logs 0
btoi
int 5000
==
assert

// Swap the pay and acfg, ensure gaid 1 works instead
itxn_begin
int pay;      itxn_field TypeEnum
txn Sender;   itxn_field Receiver
itxn_next
int acfg;    itxn_field TypeEnum
itxn_next
int appl;    itxn_field TypeEnum
int 222;     itxn_field ApplicationID
int 1; itob; itxn_field ApplicationArgs
itxn_submit
itxn Logs 0
btoi
int 5001
==
assert


int 1
`, ep)

	// Nearly identical, but ensures that gaid 0 FAILS in the second group
	TestApp(t, `itxn_begin
int acfg;    itxn_field TypeEnum
itxn_next
int pay;      itxn_field TypeEnum
txn Sender;   itxn_field Receiver
itxn_next
int appl;    itxn_field TypeEnum
int 222;     itxn_field ApplicationID
int 0; itob; itxn_field ApplicationArgs
itxn_submit
itxn Logs 0
btoi
int 5000
==
assert

// Swap the pay and acfg, ensure gaid 1 works instead
itxn_begin
int pay;      itxn_field TypeEnum
txn Sender;   itxn_field Receiver
itxn_next
int acfg;    itxn_field TypeEnum
itxn_next
int appl;    itxn_field TypeEnum
int 222;     itxn_field ApplicationID
int 0; itob; itxn_field ApplicationArgs
itxn_submit
itxn Logs 0
btoi
int 5001
==
assert


int 1
`, ep, "assert failed")

}

// TestInnerCallDepth ensures that inner calls are limited in depth
func TestInnerCallDepth(t *testing.T) {
	partitiontest.PartitionTest(t)

	t.Parallel()

	ep, tx, ledger := MakeSampleEnv()
	// Allow a lot to make the test viable
	ep.Proto.MaxAppTxnForeignApps = 50
	ep.Proto.MaxAppTotalTxnReferences = 50

	var apps []basics.AppIndex
	// 200 will be a simple app that always approves
	yes := TestProg(t, `int 1`, AssemblerMaxVersion)
	ledger.NewApp(tx.Receiver, 200, basics.AppParams{
		ApprovalProgram: yes.Program,
	})
	apps = append(apps, basics.AppIndex(200))

	// 201-210 will be apps that call the next lower one.
	for i := 0; i < 10; i++ {
		source := main(`
 global CurrentApplicationID
 itob
 log
 itxn_begin
 int appl;                    itxn_field TypeEnum
 txn NumApplications
loop:
 dup
 bz done
 dup
 txnas Applications
 itxn_field Applications
 int 1
 -
 b loop

done:
 pop
 ` + fmt.Sprintf("int %d", 200+i) + `; itxn_field ApplicationID
 itxn_submit
`)
		idx := basics.AppIndex(200 + i + 1)
		ledger.NewApp(tx.Receiver, idx, basics.AppParams{
			ApprovalProgram: TestProg(t, source, AssemblerMaxVersion).Program,
		})
		ledger.NewAccount(appAddr(int(idx)), 10_000)
		apps = append(apps, idx)
	}
	tx.ForeignApps = apps
	ledger.NewAccount(appAddr(888), 100_000)

	app, _, err := ledger.AppParams(202)
	require.NoError(t, err)
	TestAppBytes(t, app.ApprovalProgram, ep)

	app, _, err = ledger.AppParams(208)
	require.NoError(t, err)
	TestAppBytes(t, app.ApprovalProgram, ep)

	app, _, err = ledger.AppParams(209)
	require.NoError(t, err)
	TestAppBytes(t, app.ApprovalProgram, ep, "appl depth")
}

// TestForeignAppAccountAccess ensures that an app can access the account
// associated withe an app mentioned in its ForeignApps.
func TestForeignAppAccountAccess(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	TestLogicRange(t, 5, 0, func(t *testing.T, ep *EvalParams, tx *transactions.Transaction, ledger *Ledger) {
		v := ep.Proto.LogicSigVersion
		ledger.NewAccount(appAddr(888), 50_000)
		tx.ForeignApps = []basics.AppIndex{basics.AppIndex(111)}

		ledger.NewApp(tx.Sender, 111, basics.AppParams{
			ApprovalProgram:   TestProg(t, "int 1", AssemblerMaxVersion).Program,
			ClearStateProgram: TestProg(t, "int 1", AssemblerMaxVersion).Program,
		})

		// app address available starting with 7
		var problem []string
		if v < 7 {
			problem = []string{"unavailable Account " + appAddr(111).String()}
		}

		TestApp(t, `
itxn_begin
int pay; itxn_field TypeEnum
int 100; itxn_field Amount
txn Applications 1
app_params_get AppAddress
assert
itxn_field Receiver
itxn_submit
int 1
`, ep, problem...)
	})
}
